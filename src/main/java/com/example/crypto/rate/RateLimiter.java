
package com.example.crypto.rate;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class RateLimiter {
    private static class Window { int count; long windowStart; }
    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    public boolean tryAcquire(String key, int limitPerMinute) {
        long now = Instant.now().getEpochSecond();
        long currentWindow = now / 60;
        Window w = windows.computeIfAbsent(key, k -> new Window());
        synchronized (w) {
            if (w.windowStart != currentWindow) {
                w.windowStart = currentWindow;
                w.count = 0;
            }
            if (w.count >= limitPerMinute) return false;
            w.count++;
            return true;
        }
    }
}
