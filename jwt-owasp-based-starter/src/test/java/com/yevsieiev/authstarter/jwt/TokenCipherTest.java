package com.yevsieiev.authstarter.jwt;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;

import static org.junit.jupiter.api.Assertions.*;

class TokenCipherTest {
    private static final String TEST_FILE = "test-keyset.json";
    private TokenCipher cipher;

    @BeforeEach
    public void setUp() throws Exception {
        File keyFile = new File(TEST_FILE);
        if (keyFile.exists()) {
            keyFile.delete();
        }

        cipher = new TokenCipher() {
            @Override
            protected String getKeysetFilePath() {
                return TEST_FILE;
            }
        };
    }

    @AfterEach
    public void tearDown() {
        cipher.shutdown();
        File file = new File(TEST_FILE);
        if (file.exists()) file.delete();
    }

    @Test
    public void testEncryptAndDecryptToken() throws GeneralSecurityException {
        String token = "test-token";
        String encrypted = cipher.cipherToken(token);
        String decrypted = cipher.decipherToken(encrypted);

        assertEquals(token, decrypted);
    }

    @Test
    public void testPersistenceOfKeyset() throws Exception {
        String token = "persistent-token";
        String encrypted = cipher.cipherToken(token);

        TokenCipher cipher2 = new TokenCipher() {
            @Override
            protected String getKeysetFilePath() {
                return TEST_FILE;
            }
        };

        String decrypted = cipher2.decipherToken(encrypted);
        assertEquals(token, decrypted);
        cipher2.shutdown();
    }

    @Test
    public void testDecryptInvalidTokenShouldFail() {
        String brokenToken = "!!!invalid-base64###";

        assertThrows(IllegalArgumentException.class, () -> {
            cipher.decipherToken(brokenToken);
        });
    }

}