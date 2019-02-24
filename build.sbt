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

name := "gcs-cse"

version := "0.1.0"

scalaVersion := "2.11.11"

val exGuava = ExclusionRule(organization="com.google.guava", name="guava")

libraryDependencies += "com.google.cloud" % "google-cloud-storage" % "1.63.0" excludeAll exGuava

libraryDependencies += "com.google.cloud" % "google-cloud-kms" % "0.81.0-beta" excludeAll exGuava

libraryDependencies += "com.google.guava" % "guava" % "26.0-jre"

libraryDependencies += "com.google.protobuf" % "protobuf-java" % "3.6.1"

libraryDependencies += "com.google.code.gson" % "gson" % "2.8.5"

libraryDependencies += "org.scalatest" %% "scalatest" % "3.0.4" % "test"

assemblyOption in assembly := (assemblyOption in assembly).value.copy(includeScala = true)

mainClass in assembly := Some("com.google.cloud.example.GCSClientSideEncryption")

assemblyMergeStrategy in assembly := {
  case PathList("META-INF", _) => MergeStrategy.discard
  case _ => MergeStrategy.first
}

assemblyShadeRules in assembly := Seq(
  ShadeRule.rename("com.google.common.**" -> "shadegooglecommon.@1").inAll,
  ShadeRule.rename("com.google.protobuf.*" -> "shadedproto.@1").inAll
)
