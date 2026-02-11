
package com.example.crypto.policy;

import com.example.crypto.annotation.CryptoKeyGeneration;
import com.example.crypto.config.CryptoKeyGenProperties;
import com.example.crypto.exception.CryptoKeyGenException;

import java.util.Arrays;

public class DefaultPolicyEngine implements PolicyEngine {
    private final CryptoKeyGenProperties props;
    public DefaultPolicyEngine(CryptoKeyGenProperties props) { this.props = props; }

    @Override
    public void validate(CryptoKeyGeneration ann) {
        // Min sizes
        if (ann.algorithm().equalsIgnoreCase("AES") && ann.keySize() < props.getMinAesKeySize()) {
            throw new CryptoKeyGenException("AES keySize below enterprise minimum");
        }
        if (ann.algorithm().equalsIgnoreCase("RSA") && ann.keySize() < props.getMinRsaKeySize()) {
            throw new CryptoKeyGenException("RSA keySize below enterprise minimum");
        }
        // Curves
        if (ann.algorithm().equalsIgnoreCase("EC") && ann.fipsRequired()) {
            if (!Arrays.asList(props.getAllowedCurves()).contains(ann.curve().isBlank()?"secp256r1":ann.curve())) {
                throw new CryptoKeyGenException("Curve not allowed by policy");
            }
        }
        // Export bans
        if (props.isBanPrivateExport() && ann.exportPrivate()) {
            throw new CryptoKeyGenException("Exporting private key is banned by enterprise policy");
        }
    }
}
