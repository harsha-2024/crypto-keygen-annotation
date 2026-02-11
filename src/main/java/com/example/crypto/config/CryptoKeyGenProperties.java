
package com.example.crypto.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "crypto.keygen")
public class CryptoKeyGenProperties {
    private boolean fipsMode = true; // Global FIPS mode
    private int minAesKeySize = 128;
    private int minRsaKeySize = 2048;
    private String correlationHeader = "X-Correlation-Id";

    public boolean isFipsMode() { return fipsMode; }
    public void setFipsMode(boolean fipsMode) { this.fipsMode = fipsMode; }

    public int getMinAesKeySize() { return minAesKeySize; }
    public void setMinAesKeySize(int minAesKeySize) { this.minAesKeySize = minAesKeySize; }

    public int getMinRsaKeySize() { return minRsaKeySize; }
    public void setMinRsaKeySize(int minRsaKeySize) { this.minRsaKeySize = minRsaKeySize; }

    public String getCorrelationHeader() { return correlationHeader; }
    public void setCorrelationHeader(String correlationHeader) { this.correlationHeader = correlationHeader; }
}
