
package com.example.crypto.audit;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "crypto_audit_events")
public class AuditEvent {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String principal;
    private String purpose;
    private String algorithm;
    private String outputType;
    private String encoding;
    private String status;
    private Instant ts = Instant.now();

    public AuditEvent() {}

    public AuditEvent(String principal, String purpose, String algorithm, String outputType, String encoding, String status) {
        this.principal = principal;
        this.purpose = purpose;
        this.algorithm = algorithm;
        this.outputType = outputType;
        this.encoding = encoding;
        this.status = status;
    }

    public Long getId() { return id; }
    public String getPrincipal() { return principal; }
    public void setPrincipal(String principal) { this.principal = principal; }
    public String getPurpose() { return purpose; }
    public void setPurpose(String purpose) { this.purpose = purpose; }
    public String getAlgorithm() { return algorithm; }
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }
    public String getOutputType() { return outputType; }
    public void setOutputType(String outputType) { this.outputType = outputType; }
    public String getEncoding() { return encoding; }
    public void setEncoding(String encoding) { this.encoding = encoding; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public Instant getTs() { return ts; }
    public void setTs(Instant ts) { this.ts = ts; }
}
