package com.yevsieiev.authstarter.jwt;

import com.google.crypto.tink.*;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Service for encrypting and decrypting JWT tokens.
 */

public class TokenCipher {
    private transient KeysetHandle keysetHandle;
    private static final Logger logger = LoggerFactory.getLogger(TokenCipher.class);
    private static final String KEYSET_FILE = "key-ciphering.json";
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    public TokenCipher() throws GeneralSecurityException, IOException {
        AeadConfig.register();
        this.keysetHandle = loadOrGenerateKeyset();
        scheduleKeyRotation();
    }

    private KeysetHandle loadOrGenerateKeyset() throws GeneralSecurityException, IOException {
        File keysetFile = new File(getKeysetFilePath());

        if (keysetFile.exists()) {
            return CleartextKeysetHandle.read(JsonKeysetReader.withFile(keysetFile));
        }

        KeysetHandle handle = KeysetHandle.generateNew(AeadKeyTemplates.AES256_GCM);
        CleartextKeysetHandle.write(handle, JsonKeysetWriter.withFile(keysetFile));
        return handle;
    }

    private void saveKeyset(KeysetHandle handle) throws IOException {
        CleartextKeysetHandle.write(handle, JsonKeysetWriter.withFile(new File(KEYSET_FILE)));
    }

    private void rotateKey() {
        logger.info("Starting key rotation...");
        try {
            int currentPrimary = keysetHandle.getKeysetInfo().getPrimaryKeyId();
            logger.info("Current primary key ID: {}", currentPrimary);


            KeysetManager manager = KeysetManager.withKeysetHandle(keysetHandle);
            int newKeyId = manager.addNewKey(AeadKeyTemplates.AES256_GCM, false);
            logger.info("New key added. ID: {}", newKeyId);

            manager = manager.promote(newKeyId);
            logger.info("Promoted key: {}", newKeyId);

            this.keysetHandle = manager.getKeysetHandle();

            logger.info("New keyset info: {}", keysetHandle.getKeysetInfo());

            saveKeyset(keysetHandle);
            logger.info("Keyset saved successfully");

        } catch (Exception e) {
            logger.error("Key rotation FAILED", e);
        }
    }

    private void scheduleKeyRotation() {
        long initialDelay = LocalDateTime.now().until(
                LocalDateTime.now().plusDays(30).withHour(3).withMinute(0),
                ChronoUnit.MINUTES
        );

        long periodMinutes = 30 * 24 * 60;

        scheduler.scheduleAtFixedRate(
                this::rotateKey,
                initialDelay,
                periodMinutes,
                TimeUnit.MINUTES
        );
    }

    public String cipherToken(String jwt) throws GeneralSecurityException {
        Aead aead = keysetHandle.getPrimitive(Aead.class);
        byte[] ciphertext = aead.encrypt(jwt.getBytes(), null);
        return java.util.Base64.getEncoder().encodeToString(ciphertext);
    }

    public String decipherToken(String jwt) throws GeneralSecurityException {
        Aead aead = keysetHandle.getPrimitive(Aead.class);
        byte[] decrypted = aead.decrypt(
                java.util.Base64.getDecoder().decode(jwt.trim()),
                null
        );
        return new String(decrypted);
    }

    protected String getKeysetFilePath() {
        return KEYSET_FILE;
    }

    public void shutdown() {
        scheduler.shutdown();
    }
}