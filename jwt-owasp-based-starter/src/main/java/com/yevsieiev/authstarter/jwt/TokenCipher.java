package com.yevsieiev.authstarter.jwt;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.config.TinkConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.GeneralSecurityException;

/**
 * Service for encrypting and decrypting JWT tokens.
 */

public class TokenCipher {
    private final transient KeysetHandle keysetHandle;
    private static final Logger logger = LoggerFactory.getLogger(TokenCipher.class);

    public TokenCipher() throws GeneralSecurityException {
        TinkConfig.register();
        this.keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.AES256_GCM);
    }

    /**
     * Encrypts a JWT token.
     *
     * @param jwt the JWT token to encrypt
     * @return the encrypted token
     * @throws GeneralSecurityException if encryption fails
     */
    public String cipherToken(String jwt) throws GeneralSecurityException {
        Aead aead = this.keysetHandle.getPrimitive(Aead.class);
        byte[] ciphertext = aead.encrypt(jwt.getBytes(), null);
        return java.util.Base64.getEncoder().encodeToString(ciphertext);
    }

    /**
     * Decrypts a JWT token.
     *
     * @param jwt the encrypted JWT token
     * @return the decrypted token
     * @throws GeneralSecurityException if decryption fails
     */
    public String decipherToken(String jwt) throws GeneralSecurityException {
        logger.info("Deciphering token: " + jwt);
        Aead aead = this.keysetHandle.getPrimitive(Aead.class);
        byte[] decrypted = aead.decrypt(java.util.Base64.getDecoder().decode(jwt.trim()), null);
        return new String(decrypted);
    }
}