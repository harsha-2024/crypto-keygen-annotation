
package com.example.crypto.util;

import org.slf4j.MDC;

import java.util.Optional;
import java.util.UUID;

public class MdcUtil {
    public static final String CORRELATION_ID = "correlationId";

    public static String ensureCorrelationId(String incomingHeader) {
        String cid = Optional.ofNullable(incomingHeader).filter(s -> !s.isBlank()).orElse(UUID.randomUUID().toString());
        MDC.put(CORRELATION_ID, cid);
        return cid;
    }

    public static void clear() { MDC.remove(CORRELATION_ID); }
}
