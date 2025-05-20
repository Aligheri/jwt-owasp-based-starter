package com.yevsieiev.authstarter.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.yevsieiev.authstarter.config.JwtProperties;
import com.yevsieiev.authstarter.exceptions.InvalidTokenException;
import com.yevsieiev.authstarter.jwt.TokenCipher;
import com.yevsieiev.authstarter.jwt.TokenRevoker;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.Date;

@RequiredArgsConstructor
@Slf4j
public class JwtTokenProvider {
    private final JwtProperties jwtProperties;
    private final TokenCipher tokenCipher;
    private final TokenRevoker tokenRevoker;
    private final Algorithm jwtAlgorithm;

    public String generateToken(String username, String fingerprintHash) {
        return JWT.create()
                .withSubject(username)
                .withExpiresAt(Date.from(Instant.now().plus(jwtProperties.getTokenValidity())))
                .withIssuer(jwtProperties.getIssuerId())
                .withClaim("fingerprint", fingerprintHash)
                .sign(jwtAlgorithm);
    }

    public boolean validateToken(String encryptedToken, HttpServletRequest request) {
        try {
            final String token = tokenCipher.decipherToken(encryptedToken);
            final String fingerprint = CookieUtils.extractFingerprintCookie(request,
                    jwtProperties.getFingerprintCookieName());

            if (tokenRevoker.isTokenRevoked(encryptedToken)) {
                return false;
            }

            return validateFingerprint(token, fingerprint);
        } catch (Exception e) {
            log.error("Token validation failed", e);
            return false;
        }
    }

    private boolean validateFingerprint(String token, String fingerprint) throws JWTVerificationException {
        final DecodedJWT decodedToken = getJwtVerifier().verify(token);
        final String storedHash = decodedToken.getClaim("fingerprint").asString();
        final String calculatedHash = FingerprintUtils.hashFingerprint(fingerprint);

        return calculatedHash.equals(storedHash);
    }

    public String getUsernameFromToken(String encryptedToken) {
        try {
            final String token = tokenCipher.decipherToken(encryptedToken);
            return getJwtVerifier().verify(token).getSubject();
        } catch (Exception e) {
            log.error("Failed to extract username from token", e);
            throw new InvalidTokenException("Invalid or expired token");
        }
    }

    private JWTVerifier getJwtVerifier() {
        return JWT.require(jwtAlgorithm)
                .withIssuer(jwtProperties.getIssuerId())
                .build();
    }
}
