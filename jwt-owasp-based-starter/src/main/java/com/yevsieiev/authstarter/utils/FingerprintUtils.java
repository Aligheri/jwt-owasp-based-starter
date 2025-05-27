package com.yevsieiev.authstarter.utils;

import com.yevsieiev.authstarter.exceptions.HashFingerprintException;
import com.yevsieiev.authstarter.exceptions.InvalidFingerprintException;
import com.yevsieiev.authstarter.exceptions.MissingFingerprintException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;

@RequiredArgsConstructor
@Slf4j
public class FingerprintUtils {

    private static final int FINGERPRINT_LENGTH = 100;
    private static final String FINGERPRINT_PATTERN = "^[a-zA-Z0-9]{100}$";
    private static final String HASH_ALGORITHM = "SHA-256";
    private final CookieUtils cookieUtils;
    private final SecureRandom secureRandom;

    public String generateFingerprint() {
        byte[] randomBytes = new byte[FINGERPRINT_LENGTH];
        secureRandom.nextBytes(randomBytes);
        return Hex.encodeHexString(randomBytes);
    }

    public static String hashFingerprint(String fingerprint) {
        if (fingerprint == null || fingerprint.length() != FINGERPRINT_LENGTH * 2) {
            throw new InvalidFingerprintException("Invalid fingerprint");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
            byte[] hashBytes = digest.digest(fingerprint.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException("Critical security component missing", e);
        }
    }

    public String validateFingerprint(HttpServletRequest request) {
        String fingerprint = cookieUtils.extractFingerprintCookie(request);

        if (fingerprint == null) {
            log.warn("Missing fingerprint cookie");
            throw new MissingFingerprintException("missing cookie in request");
        }

        if (!fingerprint.matches(FINGERPRINT_PATTERN)) {
            log.warn("Invalid fingerprint format");
            throw new InvalidFingerprintException("invalid fingerprint format");
        }

        return fingerprint;
    }
}