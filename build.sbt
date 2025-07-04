name := "nginx-mastery"
version := "0.1.0-SNAPSHOT"

scalaVersion := "3.3.3"

val root = (project in file("."))
.settings(
libraryDependencies ++= Seq(
"com.github.plokhotnyuk.jsoniter-scala" %% "jsoniter-scala-core" % "2.36.5",
"com.github.plokhotnyuk.jsoniter-scala" %% "jsoniter-scala-circe" % "2.36.5",
"com.github.plokhotnyuk.jsoniter-scala" %% "jsoniter-scala-macros" % "2.36.5" % "provided",
// https://mvnrepository.com/artifact/com.nimbusds/nimbus-jose-jwt
"com.nimbusds" % "nimbus-jose-jwt" % "10.3",

// https://mvnrepository.com/artifact/com.nimbusds/oauth2-oidc-sdk
 "com.nimbusds" % "oauth2-oidc-sdk" % "11.26" % "runtime",
 
 // https://mvnrepository.com/artifact/net.minidev/json-smart
  "net.minidev" % "json-smart" % "2.5.2",

"de.dentrassi.crypto" % "pem-keystore" % "3.0.0",
// https://mvnrepository.com/artifact/com.azure/azure-identity
"com.azure" % "azure-identity" % "1.16.2",

// https://mvnrepository.com/artifact/com.azure/azure-security-keyvault-keys
"com.azure" % "azure-security-keyvault-keys" % "4.10.0",
// https://mvnrepository.com/artifact/com.azure/azure-security-keyvault-secrets
"com.azure" % "azure-security-keyvault-secrets" % "4.10.0",
// https://mvnrepository.com/artifact/com.azure/azure-security-keyvault-certificates
"com.azure" % "azure-security-keyvault-certificates" % "4.8.0",
// https://mvnrepository.com/artifact/com.azure/azure-storage-common
"com.azure" % "azure-storage-common" % "12.29.1",
"com.azure" % "azure-storage-blob" % "12.30.1"
)
)


javacOptions ++= Seq(
  "-encoding",
  "UTF-8",
  "-Xlint:-options",
  "-Xlint:unchecked",
  "-Xlint:deprecation",
  //"-proc:only" // or "-proc:full" if you want full processing

)