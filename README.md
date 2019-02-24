# GCS Client-Side Encryption

This project provides a demonstration of 3 different types of Client-Side encryption used with Google Cloud Storage.

To encrypt an object, the client generates 256-bit AES Data Encryption Key (DEK), which is encrypted by a user-specified KMS and stored in object metadata. To decrypt an object, the client reads the DEK from object metadata, uses KMS to decrypt the DEK, then uses the DEK to decrypt the GCS blob contents.


## KMS Types

- Google KMS - CryptoKey resource name and iv are obtained from metadata
- Static - key identifier and iv are obtained from metadata
- Password - salt for PBKDF2 and iv are obtained from metadata


## Usage


#### Run with SBT

```sh
sbt 'runMain com.google.cloud.example.GCSClientSideEncryption mybucket path/to/object /path/to/plaintext <google|static|password>'
```


#### Run from Jar
```
sbt assembly
java -jar target/scala-2.11/gcs-cse-0.1.0.jar com.google.cloud.example.GCSClientSideEncryption mybucket path/to/object /path/to/file <google|static|password>
```


## Requirements

- [sbt](https://www.scala-sbt.org/download.html) - extract archive and add bin directory to PATH
- JDK 8


## Disclaimer

This is not an official Google project.
