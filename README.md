
# Crypto Key Generation Starter Suite

A reusable **Spring Boot Starter** that provides `@CryptoKeyGeneration` with:
- **Redis-backed rate limiting** (auto-selected if Redis is on classpath and configured)
- **HSM/KMS adapters** (AWS KMS, Azure Key Vault) via conditional auto-config
- **Enterprise policy engine** (runtime + compile-time annotation processor)
- **OpenAPI demo** app + **integration tests** (Redis via Testcontainers)

## Build all modules
```bash
mvn -q -DskipTests package
```

## Run demo
```bash
cd crypto-keygen-demo
mvn spring-boot:run
# Swagger UI -> http://localhost:8080/swagger-ui.html
```

## Enable Redis rate limiting
Ensure Redis is available and `spring.data.redis.*` properties are set.

## Enable AWS KMS adapter
Add dependency `software.amazon.awssdk:kms` to your app (already optional in starter) and set:
```yaml
crypto:
  keygen:
    kms:
      key-id: arn:aws:kms:REGION:ACCOUNT:key/KEY_ID
```
Provide AWS credentials via default provider chain.

## Enable Azure Key Vault adapter
Add dependency `com.azure:azure-security-keyvault-keys` (already optional in starter) and set:
```yaml
crypto:
  keygen:
    keyvault:
      key-id: https://<vault>.vault.azure.net/keys/<key>/<version>
```
Provide Azure credentials via environment/managed identity.

## Compile-time policy enforcement
The `crypto-keygen-processor` validates annotation usages. Adjust the `maven-compiler-plugin` `compilerArgs` in its POM or in consuming modules to set policy thresholds.
