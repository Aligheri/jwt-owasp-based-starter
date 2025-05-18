package com.yevsieiev.authstarter.jwt;

import com.yevsieiev.authstarter.entity.RevokedToken;
import com.yevsieiev.authstarter.repository.RevokedTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TokenRevokerTest {

    private TokenRevoker tokenRevoker;
    private RevokedTokenRepository revokedTokenRepository;
    private TokenCipher tokenCipher;

    @BeforeEach
    public void setUp() throws GeneralSecurityException, IOException {
        revokedTokenRepository = mock(RevokedTokenRepository.class);
        tokenCipher = mock(TokenCipher.class);
        tokenRevoker = new TokenRevoker(revokedTokenRepository, tokenCipher);
    }

    @Test
    void revoke_ShouldNotSaveIfAlreadyRevoked() throws Exception {
        String encryptedToken = "encrypted-token";
        String decryptedToken = "decrypted-token";

        byte[] digestBytes = MessageDigest.getInstance("SHA-256").digest(decryptedToken.getBytes());
        String digestBase64 = Base64.getEncoder().encodeToString(digestBytes);

        when(tokenCipher.decipherToken(encryptedToken)).thenReturn(decryptedToken);
        when(revokedTokenRepository.findByJwtTokenDigest(digestBase64)).thenReturn(Optional.of(new RevokedToken()));

        tokenRevoker.revokeToken(encryptedToken);

        verify(revokedTokenRepository, never()).save(any());
    }

    @Test
    void testIsTokenRevoked_ShouldReturnTrue() throws Exception {
        String encryptedToken = "encrypted-token";
        String decryptedToken = "decrypted-token";
        byte[] digestBytes = MessageDigest.getInstance("SHA-256").digest(decryptedToken.getBytes());
        String digestBase64 = Base64.getEncoder().encodeToString(digestBytes);

        when(tokenCipher.decipherToken(encryptedToken)).thenReturn(decryptedToken);
        when(revokedTokenRepository.findByJwtTokenDigest(digestBase64)).thenReturn(Optional.of(new RevokedToken()));


        boolean result = tokenRevoker.isTokenRevoked(encryptedToken);

        assertTrue(result);
        verify(revokedTokenRepository).findByJwtTokenDigest(digestBase64);
    }

    @Test
    void testIsTokenRevoked_ShouldReturnFalse() throws Exception {
        String encryptedToken = "encrypted-token";
        String decryptedToken = "decrypted-token";
        byte[] digestBytes = MessageDigest.getInstance("SHA-256").digest(decryptedToken.getBytes());
        String digestBase64 = Base64.getEncoder().encodeToString(digestBytes);

        when(tokenCipher.decipherToken(encryptedToken)).thenReturn(decryptedToken);
        when(revokedTokenRepository.findByJwtTokenDigest(digestBase64)).thenReturn(Optional.empty());

        boolean result = tokenRevoker.isTokenRevoked(encryptedToken);

        assertFalse(result);
        verify(revokedTokenRepository).findByJwtTokenDigest(digestBase64);
    }


    @Test
    void testScheduledDeletionActuallyRuns() throws InterruptedException {
        RevokedTokenRepository repo = mock(RevokedTokenRepository.class);
        TokenCipher cipher = mock(TokenCipher.class);

        ScheduledExecutorService testScheduler = Executors.newScheduledThreadPool(1);

        TokenRevoker revoker = new TokenRevoker(repo, cipher) {
            @Override
            protected void scheduleRevokedTokensDeletion() {
                testScheduler.schedule(this::deleteAllRevokedTokensFromDb, 100, TimeUnit.MILLISECONDS);
            }

            private void deleteAllRevokedTokensFromDb() {
                repo.deleteAll();
            }
        };

        Thread.sleep(300);

        verify(repo, timeout(500).atLeastOnce()).deleteAll();
        testScheduler.shutdown();
    }

}