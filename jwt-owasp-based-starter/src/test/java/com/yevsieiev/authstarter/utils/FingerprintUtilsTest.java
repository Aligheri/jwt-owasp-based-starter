package com.yevsieiev.authstarter.utils;

import com.yevsieiev.authstarter.exceptions.InvalidFingerprintException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class FingerprintUtilsTest {
    @Mock
    private SecureRandom secureRandom;

    private static final int FINGERPRINT_LENGTH = 100;

    private FingerprintUtils fingerprintUtils;



    @BeforeEach
    void setUp() {
        fingerprintUtils = new FingerprintUtils(secureRandom);

    }

    @Test
    void generateFingerprint_shouldGenerateFingerprintWithExactLength() {
        String fingerprint = fingerprintUtils.generateFingerprint();
        assertEquals(FINGERPRINT_LENGTH * 2, fingerprint.length());
    }

    @Test
    void hashFingerprint_shouldHashFingerprintWithSHA256() {
        String fingerprint = "a008efee0a071deccba873c61f21eae7d93a2a0" +
                "ddb4e5640c37f5548446b6447ed603ba2adec9cba080fcc3c251f" +
                "7a0d6a087f5829fedd046e2b6ea8e6fa7fb6b04b5f1a49a" +
                "7128b8acc043b47b77d863afe4f121271292e3d7aa750f404d3cbbeb3cfa2";
        String hashedFingerprint = FingerprintUtils.hashFingerprint(fingerprint);
        assertNotEquals(fingerprint, hashedFingerprint);
    }

    @Test
    void hashFingerprint_shouldNotThrowException_whenFingerprintIsNull() {
        assertThrows(InvalidFingerprintException.class, () -> FingerprintUtils.hashFingerprint(null));
    }

    @Test
    void hashFingerprint_shouldThrowException_whenFingerprintIsInvalid() {
        assertThrows(InvalidFingerprintException.class, () -> FingerprintUtils.hashFingerprint("invalid-fingerprint"));
    }
}