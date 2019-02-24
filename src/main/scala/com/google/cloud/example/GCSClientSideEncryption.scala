/* Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.cloud.example

import java.nio.ByteBuffer
import java.nio.channels.{FileChannel, ReadableByteChannel, WritableByteChannel}
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths, StandardOpenOption}
import java.security.SecureRandom

import com.google.cloud.kms.v1.{CryptoKeyName, KeyManagementServiceClient}
import com.google.cloud.storage._
import com.google.cloud.{ReadChannel, RestorableState, WriteChannel}
import com.google.common.io.BaseEncoding
import com.google.protobuf.ByteString
import javax.crypto._
import javax.crypto.spec.{GCMParameterSpec, IvParameterSpec, PBEKeySpec, SecretKeySpec}

import scala.collection.JavaConverters.{mapAsJavaMapConverter, mapAsScalaMapConverter}

object GCSClientSideEncryption {
  private val keyAlgorithm = "AES"
  private val keyLength = 256
  private val keySize = keyLength/8

  private val encryptAlgorithm = "AES/GCM/NoPadding"
  private val ivLength = 12
  private val random = new SecureRandom()
  private val defaultChunkSize = 2 * 1024 * 1024 // from BlobReadChannel

  trait KMS {
    val kmsId: String
    val encryptAlgorithm: String
    def encrypt(keyId: String, plaintext: Array[Byte]): Array[Byte]
    def decrypt(keyId: String, ciphertext: Array[Byte]): Array[Byte]
  }

  class CloudKMS extends KMS {
    override val kmsId: String = "google"
    override val encryptAlgorithm: String = "symmetric"
    private val kms = KeyManagementServiceClient.create()

    override def encrypt(cryptoKey: String, plaintext: Array[Byte]): Array[Byte] = {
      val response = kms.encrypt(cryptoKey, ByteString.copyFrom(plaintext))
      response.getCiphertext.toByteArray
    }

    override def decrypt(cryptoKey: String, ciphertext: Array[Byte]): Array[Byte] = {
      val response = kms.decrypt(cryptoKey, ByteString.copyFrom(ciphertext))
      response.getPlaintext.toByteArray
    }
  }

  class PasswordKMS(private val password: String) extends KMS {
    override val kmsId: String = "password"
    override val encryptAlgorithm: String = "AES/ECB/PKCS5Padding"

    def genSalt(): Array[Byte] = {
      val saltBytes = new Array[Byte](20)
      random.nextBytes(saltBytes)
      saltBytes
    }

    private def key(saltB64: String): SecretKeySpec = {
      val secretKeyFactoryAlgorithm = "PBKDF2WithHmacSHA1"
      val pwdIterations = 65536
      val spec = new PBEKeySpec(password.toCharArray, BaseEncoding.base64().decode(saltB64), pwdIterations, keyLength)
      val keyBytes = SecretKeyFactory.getInstance(secretKeyFactoryAlgorithm).generateSecret(spec).getEncoded
      new SecretKeySpec(keyBytes, keyAlgorithm)
    }

    override def decrypt(keyId: String, ciphertext: Array[Byte]): Array[Byte] = {
      val cipher = Cipher.getInstance(encryptAlgorithm)
      cipher.init(Cipher.DECRYPT_MODE, key(keyId))
      cipher.doFinal(ciphertext)
    }

    override def encrypt(keyId: String, plaintext: Array[Byte]): Array[Byte] = {
      val cipher = Cipher.getInstance(encryptAlgorithm)
      cipher.init(Cipher.ENCRYPT_MODE, key(keyId))
      cipher.doFinal(plaintext)
    }
  }

  class StaticKMS(private val keys: Map[String,SecretKeySpec]) extends KMS {
    override val kmsId: String = "static"
    override val encryptAlgorithm = "AES/ECB/PKCS5Padding"

    private def getKey(keyId: String): SecretKeySpec = {
      keys(keyId)
    }

    override def encrypt(keyId: String, plaintext: Array[Byte]): Array[Byte] = {
      val cipher = Cipher.getInstance(encryptAlgorithm)
      cipher.init(Cipher.ENCRYPT_MODE, getKey(keyId))
      cipher.doFinal(plaintext)
    }

    override def decrypt(keyId: String, ciphertext: Array[Byte]): Array[Byte] = {
      val cipher = Cipher.getInstance(encryptAlgorithm)
      cipher.init(Cipher.DECRYPT_MODE, getKey(keyId))
      cipher.doFinal(ciphertext)
    }
  }

  private def genIv: IvParameterSpec = {
    val bytes = new Array[Byte](ivLength)
    random.nextBytes(bytes)
    new IvParameterSpec(bytes)
  }

  private def genKey: SecretKeySpec = {
    val bytes = new Array[Byte](keySize)
    random.nextBytes(bytes)
    new SecretKeySpec(bytes, keyAlgorithm)
  }

  private def encrypt(key: SecretKeySpec, iv: IvParameterSpec): Cipher = {
    val cipher = Cipher.getInstance(encryptAlgorithm)
    val parameterSpec = new GCMParameterSpec(128, iv.getIV)
    cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec)
    cipher
  }

  private def decrypt(key: SecretKeySpec, iv: IvParameterSpec): Cipher = {
    val cipher = Cipher.getInstance(encryptAlgorithm)
    val parameterSpec = new GCMParameterSpec(128, iv.getIV)
    cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec)
    cipher
  }

  private class CipherWriteChannel(wc: WriteChannel, cipher: Cipher) extends WriteChannel {
    private var chunkSize: Int = defaultChunkSize
    private var buf: ByteBuffer = ByteBuffer.allocate(chunkSize)

    override def write(src: ByteBuffer): Int = {
      buf.clear()
      cipher.update(src, buf)
      buf.flip()
      wc.write(buf)
    }

    override def close(): Unit = {
      wc.write(ByteBuffer.wrap(cipher.doFinal()))
      wc.close()
    }

    override def isOpen: Boolean = wc.isOpen

    override def setChunkSize(newChunkSize: Int): Unit = {
      if (newChunkSize != chunkSize) {
        chunkSize = newChunkSize
        buf = ByteBuffer.allocate(chunkSize)
        wc.setChunkSize(chunkSize)
      }
    }

    override def capture(): RestorableState[WriteChannel] =
      wc.capture()
  }

  private class CipherReadChannel(rc: ReadChannel, cipher: Cipher) extends ReadChannel {
    private var chunkSize: Int = defaultChunkSize
    private var buf: ByteBuffer = ByteBuffer.allocate(chunkSize)
    private var done: Boolean = false

    override def read(dst: ByteBuffer): Int = {
      if (done) {
        -1
      } else {
        buf.clear()
        if (dst.remaining() < buf.capacity()) {
          buf.limit(dst.remaining())
        }
        if (rc.read(buf) == -1) {
          done = true
          buf.put(cipher.doFinal())
          buf.flip()
          dst.put(buf)
          buf.position
        } else {
          buf.flip()
          val m = cipher.update(buf, dst)
          m
        }
      }
    }

    override def close(): Unit = {
      done = true
      rc.close()
    }

    override def isOpen: Boolean = !done && rc.isOpen

    override def seek(position: Long): Unit = rc.seek(position)

    override def setChunkSize(newChunkSize: Int): Unit = {
      if (newChunkSize != chunkSize) {
        chunkSize = newChunkSize
        buf = ByteBuffer.allocate(chunkSize)
        rc.setChunkSize(chunkSize)
      }
    }

    override def capture(): RestorableState[ReadChannel] = {
      rc.capture()
    }
  }

  private def transfer(rc: ReadableByteChannel, wc: WritableByteChannel): Unit = {
    val buf = ByteBuffer.allocate(defaultChunkSize)
    while (rc.read(buf) > 0) {
      buf.flip()
      wc.write(buf)
      buf.clear()
    }
  }

  private def writeToFile(rc: ReadableByteChannel, path: Path): Unit = {
    transfer(rc, FileChannel.open(path, StandardOpenOption.CREATE, StandardOpenOption.WRITE))
  }

  class CSEStorage(val kms: KMS, val storage: Storage) {

    def get(bucket: String, obj: String): ReadChannel = {
      val blob = storage.get(BlobId.of(bucket, obj))
      val meta = blob.getMetadata.asScala.toMap
      val ivBytes = BaseEncoding.base64.decode(meta("iv"))
      val keyBytes = kms.decrypt(meta.getOrElse("keyId", ""), BaseEncoding.base64.decode(meta("k")))

      require(blob.getContentEncoding.equalsIgnoreCase(encryptAlgorithm), s"Content-Encoding must be $encryptAlgorithm")
      require(meta.getOrElse("kms", "") == kms.kmsId, s"KMS must be ${kms.kmsId}")
      require(ivBytes.length == ivLength, s"IV must be $ivLength bytes")
      require(keyBytes.length == keySize, s"key must be $keySize bytes")

      val cipher = decrypt(
        key = new SecretKeySpec(keyBytes, keyAlgorithm),
        iv = new IvParameterSpec(ivBytes))
      new CipherReadChannel(blob.reader(), cipher)
    }

    def putFile(bucket: String, obj: String, path: Path, keyId: String): BlobInfo =
      put(bucket, obj, FileChannel.open(path, StandardOpenOption.READ), keyId)

    def put(bucket: String, obj: String, rc: ReadableByteChannel, keyId: String): BlobInfo = {
      val iv = genIv
      val key = genKey
      val blobId = BlobId.of(bucket, obj)

      val meta = Map[String,String](
        "iv" -> BaseEncoding.base64.encode(iv.getIV),
        "k" -> BaseEncoding.base64.encode(kms.encrypt(keyId, key.getEncoded)),
        "kms" -> kms.kmsId,
        "keyId" -> keyId
      ).filter(_._2.nonEmpty)

      val blobInfo = BlobInfo.newBuilder(blobId)
        .setContentType("application/octet-stream")
        .setContentEncoding(encryptAlgorithm)
        .setMetadata(meta.asJava)
        .build

      val wc = new CipherWriteChannel(storage.writer(blobInfo), encrypt(key, iv))
      transfer(rc, wc)
      wc.close()

      blobInfo
    }
  }

  def run(bucket: String, obj: String, path: String, keyId: String, cse: CSEStorage): Unit = {
    val file = Paths.get(path)
    require(file.toFile.exists(), s"$file does not exist")
    val blob = cse.putFile(bucket, obj, file, keyId)
    System.out.println(s"Wrote gs://${blob.getBlobId.getBucket}/${blob.getBlobId.getName}")

    // decrypt the file
    val decryptedFile = Paths.get(path+".decrypted")
    writeToFile(cse.get(bucket, obj), decryptedFile)
    System.out.println(new String(Files.readAllBytes(decryptedFile), StandardCharsets.UTF_8))
  }

  def main(args: Array[String]): Unit = {
    args match {
      case Array(bucket, obj, path, kmsType) =>
        val kms: KMS = kmsType match {
          case "google" =>
            new CloudKMS
          case "static" =>
            new StaticKMS(Map("default" -> genKey))
          case _ =>
            new PasswordKMS(sys.env.getOrElse("KMS_PASS", "changeit"))
        }

        val keyId = kmsType match {
          case "google" =>
            CryptoKeyName.format(sys.env("PROJECT_ID"), sys.env("KMS_LOCATION"), sys.env("KMS_KEYRING"), sys.env("KMS_KEY"))
          case "static" =>
            "default"
          case _ =>
            kms match {
              case x: PasswordKMS =>
                BaseEncoding.base64().encode(x.genSalt())
              case _ =>
                ""
            }
        }

        val gcs: Storage = StorageOptions.getDefaultInstance.getService
        val cse = new CSEStorage(kms, gcs)

        run(bucket, obj, path, keyId, cse)

      case _ =>
        System.out.println(s"Usage: ${getClass.getSimpleName} <bucket> <obj> </path/to/file> <kmsType:google|static>")
    }
  }
}
