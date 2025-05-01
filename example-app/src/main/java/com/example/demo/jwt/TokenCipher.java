package com.example.demo.jwt;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.config.TinkConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.GeneralSecurityException;
@Service
public class TokenCipher {
    private final transient KeysetHandle keysetHandle;
    private static final Logger logger = LoggerFactory.getLogger(TokenCipher.class);

    public TokenCipher() throws GeneralSecurityException {
        TinkConfig.register();
        this.keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.AES256_GCM);
    }

    public String cipherToken(String jwt) throws GeneralSecurityException {
        Aead aead = this.keysetHandle.getPrimitive(Aead.class);
        byte[] ciphertext = aead.encrypt(jwt.getBytes(), null);
        return java.util.Base64.getEncoder().encodeToString(ciphertext);
    }

    public String decipherToken(String jwt) throws GeneralSecurityException {
        logger.info("Deciphering token: " + jwt);
        Aead aead = this.keysetHandle.getPrimitive(Aead.class);
        byte[] decrypted = aead.decrypt(java.util.Base64.getDecoder().decode(jwt.trim()), null);
        return new String(decrypted);
    }
}
