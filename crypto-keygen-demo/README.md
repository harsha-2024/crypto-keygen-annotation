
# Crypto KeyGen Demo

## Run
```bash
mvn -q -DskipTests package
cd crypto-keygen-demo
mvn spring-boot:run
```
Open Swagger UI: http://localhost:8080/swagger-ui.html

## Redis-backed rate limiting
Ensure Redis is running locally (default localhost:6379). For tests we use Testcontainers.

## KMS/Key Vault
Provide `crypto.keygen.kms.key-id` (AWS) or `crypto.keygen.keyvault.key-id` (Azure) and credentials via environment (SDK default providers).
