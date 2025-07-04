# Azure Key Vault
Azure Key Vault is a cloud service that provides secure storage of certificates, cryptographic keys and secrets used by cloud applications and services.

Azure Key Vault Managed HSM is a fully-managed, highly-available, single-tenant, standards-compliant cloud service that enables you to safeguard cryptographic keys for your cloud applications using FIPS 140-2 Level 3 validated HSMs.

- `Azure Key Vault Keys` is a cloud service that enables you to safeguard and manage cryptographic keys.
- `Azure Key Vault Certificates` is a cloud service that allows you to securely manage and tightly control your certificates.
- `Azure Key Vault Secrets` is a cloud service that provides management and secure storage for secrets, such as passwords and database connection strings.
- `The Azure Key Vault Administration` library clients support administrative tasks such as full backup/restore and key-level role-based access control (RBAC) for Azure Key Vault Managed HSM.
- `Azure Key Vault JCA` is a Java Cryptography Architecture provider for certificates in Azure Key Vault.

## Azure Key Vault Certificate client library for Java

Azure Key Vault allows you to securely manage and tightly control your certificates. The Azure Key Vault Certificate client library supports certificates backed by RSA and EC keys.

Multiple certificates and multiple versions of the same certificate can be kept in the Key Vault. Cryptographic keys in Azure Key Vault backing the certificates are represented as JSON Web Key (JWK) objects. This library offers operations to create, retrieve, update, delete, purge, backup, restore, and list the certificates, as well as its versions.


