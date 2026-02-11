
package com.example.crypto.demo;

import com.example.crypto.annotation.CryptoKeyGeneration;
import com.example.crypto.annotation.CryptoKeyGeneration.Encoding;
import com.example.crypto.annotation.CryptoKeyGeneration.OutputType;
import com.example.crypto.model.KeyMaterial;
import org.springframework.stereotype.Service;

@Service
public class KeyService {

    @CryptoKeyGeneration(purpose = "DATA_ENCRYPTION", algorithm = "AES", keySize = 256, output = OutputType.SECRET, encoding = Encoding.JWK, rolesAllowed = {"ROLE_USER", "ROLE_ADMIN"})
    public KeyMaterial generateAes256() { return null; }

    @CryptoKeyGeneration(purpose = "SIGNING", algorithm = "RSA", keySize = 3072, output = OutputType.KEYPAIR, encoding = Encoding.PEM, exportPrivate = true, rolesAllowed = {"ROLE_ADMIN"})
    public KeyMaterial generateRsa3072() { return null; }

    @CryptoKeyGeneration(purpose = "SIGNING", algorithm = "EC", curve = "secp256r1", output = OutputType.KEYPAIR, encoding = Encoding.JWK, exportPrivate = false, rolesAllowed = {"ROLE_ADMIN"})
    public KeyMaterial generateEcP256() { return null; }
}
