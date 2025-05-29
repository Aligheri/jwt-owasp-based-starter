package com.yevsieiev.authstarter.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.yevsieiev.authstarter.config.JwtProperties;
import com.yevsieiev.authstarter.exceptions.TokenValidationException;
import com.yevsieiev.authstarter.jwt.TokenCipher;
import com.yevsieiev.authstarter.jwt.TokenRevoker;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;

@RequiredArgsConstructor
@Slf4j
public class TokenValidationUtils {
    private final JwtProperties jwtProperties;
    private final TokenCipher tokenCipher;
    private final TokenRevoker tokenRevoker;
    private final com.auth0.jwt.algorithms.Algorithm jwtAlgorithm;
    private final CookieProvider cookieProvider;

    public boolean validateToken(String encryptedToken, HttpServletRequest request) {
        try {
            if (tokenRevoker.isTokenRevoked(encryptedToken)) {
                log.warn("Token revoked: {}", encryptedToken);
                return false;
            }
            String token = decryptToken(encryptedToken);

            String fingerprint = cookieProvider.extractFingerprintCookie(request);
            String fingerprintHash = FingerprintUtils.hashFingerprint(fingerprint);

            verifyTokenClaims(token, fingerprintHash);

            return true;

        } catch (TokenValidationException e) {
            log.warn("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    private String decryptToken(String encryptedToken) {
        return tokenCipher.decipherToken(encryptedToken);
    }

    private DecodedJWT verifyTokenClaims(String token, String fingerprintHash) {
        JWTVerifier verifier = JWT.require(jwtAlgorithm)
                .withIssuer(jwtProperties.getIssuerId())
                .withClaim("fingerprint", fingerprintHash)
                .acceptNotBefore(Instant.now().getEpochSecond())
                .acceptExpiresAt(5)
                .build();
        logSecurityDetails(verifier.verify(token));
        return verifier.verify(token);
    }

    private void logSecurityDetails(DecodedJWT decodedToken) {
        if (log.isInfoEnabled()) {
            log.info("Authenticated user: {}", decodedToken.getSubject());
            log.info("Token issuer: {}", decodedToken.getIssuer());
            log.info("Token expires at: {}", decodedToken.getExpiresAt());
        }
    }
}
