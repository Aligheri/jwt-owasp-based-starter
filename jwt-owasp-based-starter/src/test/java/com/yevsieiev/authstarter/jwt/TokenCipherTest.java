package com.yevsieiev.authstarter.jwt;

import com.yevsieiev.authstarter.exceptions.TokenDecryptionException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import static org.junit.jupiter.api.Assertions.*;

class TokenCipherTest {
    private static final String TEST_FILE = "test-keyset.json";
    private TokenCipher cipher;

    @BeforeEach
    public void setUp() throws Exception {
        deleteKeysetFile();
        cipher = new TestTokenCipher();
    }

    @AfterEach
    public void tearDown() {
        cipher.shutdown();
        deleteKeysetFile();
    }

    private void deleteKeysetFile() {
        File file = new File(TEST_FILE);
        if (file.exists() && !file.delete()) {
            file.deleteOnExit();
        }
    }

    @Test
    void testEncryptAndDecryptToken() {
        String token = "test-token";
        String encrypted = cipher.cipherToken(token);
        String decrypted = cipher.decipherToken(encrypted);
        assertEquals(token, decrypted);
    }

    @Test
    void testPersistenceOfKeyset() throws GeneralSecurityException, IOException {
        String token = "persistent-token";
        String encrypted = cipher.cipherToken(token);

        TokenCipher cipher2 = new TestTokenCipher();
        String decrypted = cipher2.decipherToken(encrypted);
        assertEquals(token, decrypted);
        cipher2.shutdown();
    }

    @Test
    void testDecryptInvalidTokenShouldFail() {
        String brokenToken = "!!!invalid-base64###";
        assertThrows(
                TokenDecryptionException.class,
                () -> cipher.decipherToken(brokenToken)
        );
    }

    private static class TestTokenCipher extends TokenCipher {
        public TestTokenCipher() throws GeneralSecurityException, IOException {
        }

        @Override
        protected String getKeysetFilePath() {
            return TEST_FILE;
        }

        @Override
        protected boolean isValidTokenStructure(String token) {
            return true;
        }
    }
}