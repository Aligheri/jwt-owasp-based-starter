package com.yevsieiev.authstarter.jwt;

import com.google.crypto.tink.*;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.yevsieiev.authstarter.exceptions.KeyRotationException;
import com.yevsieiev.authstarter.exceptions.TokenDecryptionException;
import com.yevsieiev.authstarter.exceptions.TokenEncyptionException;
import lombok.extern.slf4j.Slf4j;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Service for encrypting and decrypting JWT tokens.
 */
@Slf4j
public class TokenCipher {
    private transient KeysetHandle keysetHandle;
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
        log.info("Starting key rotation...");
        try {
            int currentPrimary = keysetHandle.getKeysetInfo().getPrimaryKeyId();
            log.info("Current primary key ID: {}", currentPrimary);

            KeysetManager manager = KeysetManager.withKeysetHandle(keysetHandle);
            int newKeyId = manager.addNewKey(AeadKeyTemplates.AES256_GCM, false);
            log.info("New key added. ID: {}", newKeyId);

            manager = manager.promote(newKeyId);
            log.info("Promoted key: {}", newKeyId);
            this.keysetHandle = manager.getKeysetHandle();

            log.info("New keyset info: {}", keysetHandle.getKeysetInfo());
            saveKeyset(keysetHandle);
            log.info("Keyset saved successfully");

        } catch (GeneralSecurityException e) {
            log.error("Cryptographic failure during rotation", e);
        } catch (IOException e) {
            log.error("Keyset storage failure", e);
            throw new KeyRotationException("Key persistence error", e);
        } catch (Exception e) {
            log.error("Catastrophic rotation failure", e);
            throw new KeyRotationException("Unrecoverable key error", e);
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

    public String cipherToken(String jwt) {
        Aead aead;
        try {
            aead = keysetHandle.getPrimitive(Aead.class);
        } catch (GeneralSecurityException e) {
            throw new TokenEncyptionException("failed to get primitive from keysetHandle", e);
        }
        byte[] ciphertext;
        try {
            ciphertext = aead.encrypt(jwt.getBytes(), null);
        } catch (GeneralSecurityException e) {
            throw new TokenEncyptionException("failed to encrypt token", e);
        }
        return java.util.Base64.getEncoder().encodeToString(ciphertext);
    }

    public String decipherToken(String jwt) {
        try {
            Aead aead = keysetHandle.getPrimitive(Aead.class);
            byte[] decrypted = aead.decrypt(Base64.getDecoder().decode(jwt.trim()), null);
            String token = new String(decrypted, StandardCharsets.UTF_8);

            if (!isValidTokenStructure(token)) {
                throw new TokenDecryptionException("Invalid token structure");
            }
            return token;
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            log.error("Decryption failed for token: {}", jwt.substring(0, Math.min(8, jwt.length())) + "...");
            throw new TokenDecryptionException("Decryption failed", e);
        }
    }

    protected boolean isValidTokenStructure(String token) {
        return token.split("\\.").length == 3;
    }

    protected String getKeysetFilePath() {
        return KEYSET_FILE;
    }

    public void shutdown() {
        scheduler.shutdown();
    }
}