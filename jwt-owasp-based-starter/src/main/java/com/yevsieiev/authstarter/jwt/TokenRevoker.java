package com.yevsieiev.authstarter.jwt;

import com.yevsieiev.authstarter.entity.RevokedToken;
import com.yevsieiev.authstarter.exceptions.SecurityConfigurationException;
import com.yevsieiev.authstarter.exceptions.TokenDecryptionException;
import com.yevsieiev.authstarter.exceptions.TokenProcessingException;
import com.yevsieiev.authstarter.repository.RevokedTokenRepository;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Service for revoking and checking revoked JWT tokens.
 */
@Slf4j
public class TokenRevoker {
    private final RevokedTokenRepository revokedTokenRepository;
    private final TokenCipher tokenCipher;
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    public TokenRevoker(RevokedTokenRepository revokedTokenRepository, TokenCipher tokenCipher) {
        this.revokedTokenRepository = revokedTokenRepository;
        this.tokenCipher = tokenCipher;
        scheduleRevokedTokensDeletion();
    }

    private String calculateTokenDigest(String jwtInHex) {
        try {
            String decrypted = tokenCipher.decipherToken(jwtInHex);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(decrypted.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new TokenProcessingException("Token processing failed", e);
        }
    }

    /**
     * Checks if a token is revoked.
     *
     * @param jwtInHex the encrypted JWT token
     * @return true if the token is revoked, false otherwise
     * @throws TokenProcessingException if an error occurs
     */
    public boolean isTokenRevoked(String jwtInHex) {
        try {
            String digest = calculateTokenDigest(jwtInHex);
            return revokedTokenRepository.findByJwtTokenDigest(digest)
                    .map(token -> true)
                    .orElse(false);
        } catch (TokenProcessingException e) {
            log.warn("Invalid token received: {}", jwtInHex.substring(0, 8) + "...");
            return true;
        }
    }

    /**
     * Revokes a token.
     *
     * @param jwtInHex the encrypted JWT token
     * @throws TokenProcessingException if an error occurs
     */
    public void revokeToken(String jwtInHex) {
        try {
            log.debug("Deciphering token for revocation");
            String decipheredToken = tokenCipher.decipherToken(jwtInHex);

            byte[] cipheredToken = decipheredToken.getBytes();

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] cipheredTokenDigest = digest.digest(cipheredToken);
            String jwtTokenDigestInHex = Base64.getEncoder().encodeToString(cipheredTokenDigest);

            if (!isTokenRevoked(jwtInHex)) {
                RevokedToken revokedToken = new RevokedToken();
                revokedToken.setJwtTokenDigest(jwtTokenDigestInHex);
                revokedToken.setRevocationDate(Instant.now());
                revokedTokenRepository.save(revokedToken);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new TokenProcessingException("Security algorithm unavailable", e);
        } catch (Exception e) {
            throw new TokenProcessingException("Unexpected revocation error", e);
        }
    }

    protected void scheduleRevokedTokensDeletion() {
        long initialDelay = LocalDateTime.now().until(
                LocalDateTime.now().plusDays(30).withHour(3).withMinute(0),
                ChronoUnit.MINUTES
        );

        long periodMinutes = 30 * 24 * 60;

        scheduler.scheduleAtFixedRate(
                this::deleteAllRevokedTokensFromDb,
                initialDelay,
                periodMinutes,
                TimeUnit.MINUTES
        );
    }

    private void deleteAllRevokedTokensFromDb() {
        revokedTokenRepository.deleteAll();
    }
}