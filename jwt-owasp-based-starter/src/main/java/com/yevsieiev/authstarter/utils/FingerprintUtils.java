package com.yevsieiev.authstarter.utils;

import com.yevsieiev.authstarter.exceptions.HashFingerprintException;
import org.apache.commons.codec.binary.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;

public class FingerprintUtils {

    private static final int FINGERPRINT_LENGTH = 100;

    public static String generateFingerprint() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[FINGERPRINT_LENGTH];
        secureRandom.nextBytes(randomBytes);
        return Hex.encodeHexString(randomBytes);
    }

    public static String hashFingerprint(String fingerprint)  {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new HashFingerprintException(e);
        }
        byte[] hashBytes = digest.digest(fingerprint.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(hashBytes);
    }
}
