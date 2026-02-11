
package com.example.crypto.util;

import java.util.Base64;

public class Base64Url {
    public static String encode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }
}
