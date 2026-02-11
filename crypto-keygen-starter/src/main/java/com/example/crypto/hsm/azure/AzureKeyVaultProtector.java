
package com.example.crypto.hsm.azure;

import com.example.crypto.hsm.KeyProtector;
import com.example.crypto.hsm.ProtectedKey;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.EncryptResult;
import com.azure.security.keyvault.keys.cryptography.models.EncryptionAlgorithm;

import java.util.Base64;
import java.util.Map;

/** Azure Key Vault protector: encrypts with an existing Key Vault key */
public class AzureKeyVaultProtector implements KeyProtector {
    private final CryptographyClient crypto;
    public AzureKeyVaultProtector(String keyId) {
        this.crypto = new CryptographyClientBuilder().keyIdentifier(keyId).buildClient();
    }
    @Override
    public ProtectedKey protect(byte[] pkcs8PrivateKey, Map<String, Object> context) {
        EncryptResult res = crypto.encrypt(EncryptionAlgorithm.RSA_OAEP_256, pkcs8PrivateKey);
        return new ProtectedKey("KEY_VAULT", Base64.getEncoder().encodeToString(res.getCipherText()));
    }
}
