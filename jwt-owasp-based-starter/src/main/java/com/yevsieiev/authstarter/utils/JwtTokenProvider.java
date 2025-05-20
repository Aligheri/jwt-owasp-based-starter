package com.yevsieiev.authstarter.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.yevsieiev.authstarter.config.JwtProperties;
import com.yevsieiev.authstarter.exceptions.*;
import com.yevsieiev.authstarter.jwt.TokenCipher;
import com.yevsieiev.authstarter.jwt.TokenRevoker;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Date;

@RequiredArgsConstructor
@Slf4j
public class JwtTokenProvider {
    private final JwtProperties jwtProperties;
    private final TokenCipher tokenCipher;
    private final TokenRevoker tokenRevoker;
    private final FingerprintUtils fingerprintUtils;
    private final Algorithm jwtAlgorithm;

    public String generateToken(String username, String fingerprintHash) {
        Instant now = Instant.now();
        return JWT.create()
                .withSubject(username)
                .withExpiresAt(Date.from(now.plus(jwtProperties.getTokenValidity())))
                .withNotBefore(Date.from(now))
                .withIssuer(jwtProperties.getIssuerId())
                .withClaim("fingerprint", fingerprintHash)
                .sign(jwtAlgorithm);
    }


    public boolean validateToken(String encryptedToken, HttpServletRequest request) {
        try {
            if (tokenRevoker.isTokenRevoked(encryptedToken)) {
                log.warn("Token revoked: {}", encryptedToken);
                return false;
            }
            String token = decryptToken(encryptedToken);

            String fingerprint = fingerprintUtils.validateFingerprint(request);
            String fingerprintHash = fingerprintUtils.hashFingerprint(fingerprint);

            verifyTokenClaims(token, fingerprintHash);

            return true;

        } catch (TokenValidationException e) {
            log.warn("Token validation failed: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("Unexpected error during token validation", e);
            return false;
        }
    }

    private String decryptToken(String encryptedToken) throws TokenDecryptionException {
        try {
            return tokenCipher.decipherToken(encryptedToken);
        } catch (GeneralSecurityException e) {
            throw new TokenDecryptionException("Token decryption failed", e);
        }
    }

    private void verifyTokenClaims(String token, String fingerprintHash) {
        JWTVerifier verifier = JWT.require(jwtAlgorithm)
                .withIssuer(jwtProperties.getIssuerId())
                .withClaim("fingerprint", fingerprintHash)
                .build();

        DecodedJWT decodedToken = verifier.verify(token);
        logSecurityDetails(decodedToken);
    }

    private void logSecurityDetails(DecodedJWT decodedToken) {
        if (log.isInfoEnabled()) {
            log.info("Authenticated user: {}", decodedToken.getSubject());
            log.info("Token issuer: {}", decodedToken.getIssuer());
            log.info("Token expires at: {}", decodedToken.getExpiresAt());
        }
    }

    public String getUsernameFromToken(String encryptedToken) {
        try {
            String token = decryptToken(encryptedToken);
            return JWT.require(jwtAlgorithm)
                    .withIssuer(jwtProperties.getIssuerId())
                    .build()
                    .verify(token)
                    .getSubject();
        } catch (TokenValidationException e) {
            throw new InvalidTokenException("Failed to extract username");
        }
    }
}
