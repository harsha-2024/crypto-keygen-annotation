
package com.example.crypto.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "crypto.keygen")
public class CryptoKeyGenProperties {
    /*** Global FIPS mode toggle */
    private boolean fipsMode = true;
    private int minAesKeySize = 128;
    private int minRsaKeySize = 2048;
    private String correlationHeader = "X-Correlation-Id";

    // Policy toggles
    private boolean banPrivateExport = true;
    private String[] allowedCurves = new String[]{"secp256r1","secp384r1","secp521r1"};
    private boolean preferRedisRateLimiter = true;

    public boolean isFipsMode() { return fipsMode; }
    public void setFipsMode(boolean fipsMode) { this.fipsMode = fipsMode; }
    public int getMinAesKeySize() { return minAesKeySize; }
    public void setMinAesKeySize(int minAesKeySize) { this.minAesKeySize = minAesKeySize; }
    public int getMinRsaKeySize() { return minRsaKeySize; }
    public void setMinRsaKeySize(int minRsaKeySize) { this.minRsaKeySize = minRsaKeySize; }
    public String getCorrelationHeader() { return correlationHeader; }
    public void setCorrelationHeader(String correlationHeader) { this.correlationHeader = correlationHeader; }
    public boolean isBanPrivateExport() { return banPrivateExport; }
    public void setBanPrivateExport(boolean banPrivateExport) { this.banPrivateExport = banPrivateExport; }
    public String[] getAllowedCurves() { return allowedCurves; }
    public void setAllowedCurves(String[] allowedCurves) { this.allowedCurves = allowedCurves; }
    public boolean isPreferRedisRateLimiter() { return preferRedisRateLimiter; }
    public void setPreferRedisRateLimiter(boolean preferRedisRateLimiter) { this.preferRedisRateLimiter = preferRedisRateLimiter; }
}
