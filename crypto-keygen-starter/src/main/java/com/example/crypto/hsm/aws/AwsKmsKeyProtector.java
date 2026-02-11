
package com.example.crypto.hsm.aws;

import com.example.crypto.hsm.KeyProtector;
import com.example.crypto.hsm.ProtectedKey;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.EncryptRequest;

import java.util.Base64;
import java.util.Map;

/** AWS KMS-based protector: encrypts PKCS#8 bytes with a symmetric KMS CMK */
public class AwsKmsKeyProtector implements KeyProtector {
    private final KmsClient kms;
    private final String keyId;
    public AwsKmsKeyProtector(KmsClient kms, String keyId) { this.kms = kms; this.keyId = keyId; }
    @Override
    public ProtectedKey protect(byte[] pkcs8PrivateKey, Map<String, Object> context) {
        EncryptRequest req = EncryptRequest.builder()
                .keyId(keyId)
                .plaintext(SdkBytes.fromByteArray(pkcs8PrivateKey))
                .build();
        byte[] ct = kms.encrypt(req).ciphertextBlob().asByteArray();
        return new ProtectedKey("KMS_WRAPPED", Base64.getEncoder().encodeToString(ct));
    }
}
