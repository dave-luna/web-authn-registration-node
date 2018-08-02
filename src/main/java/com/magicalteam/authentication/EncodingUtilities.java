package com.magicalteam.authentication;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Base64;

/**
 * Utility class (...I know)
 */
class EncodingUtilities {

    static byte[] base64UrlDecode(String challenge) {
        Base64 encoder = new Base64(true);
        return encoder.decode(challenge);
    }

    static byte[] getHash(String value) {
        byte[] hash = null;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return hash;
    }
}
