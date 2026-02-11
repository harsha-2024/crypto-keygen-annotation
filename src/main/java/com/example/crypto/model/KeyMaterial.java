
package com.example.crypto.model;

import java.time.Instant;
import java.util.Map;

public class KeyMaterial {
    private String kid;
    private String algorithm;
    private String kty;
    private String encoding;
    private int length;
    private Instant createdAt = Instant.now();

    private String secret;    // for symmetric
    private String publicKey; // for keypairs
    private String privateKey; // only if export allowed

    private Map<String, Object> meta;

    public String getKid() { return kid; }
    public void setKid(String kid) { this.kid = kid; }
    public String getAlgorithm() { return algorithm; }
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }
    public String getKty() { return kty; }
    public void setKty(String kty) { this.kty = kty; }
    public String getEncoding() { return encoding; }
    public void setEncoding(String encoding) { this.encoding = encoding; }
    public int getLength() { return length; }
    public void setLength(int length) { this.length = length; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public String getSecret() { return secret; }
    public void setSecret(String secret) { this.secret = secret; }
    public String getPublicKey() { return publicKey; }
    public void setPublicKey(String publicKey) { this.publicKey = publicKey; }
    public String getPrivateKey() { return privateKey; }
    public void setPrivateKey(String privateKey) { this.privateKey = privateKey; }
    public Map<String, Object> getMeta() { return meta; }
    public void setMeta(Map<String, Object> meta) { this.meta = meta; }
}
