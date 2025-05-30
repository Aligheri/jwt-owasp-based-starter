package com.yevsieiev.authstarter.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.yevsieiev.authstarter.config.JwtProperties;
import com.yevsieiev.authstarter.exceptions.*;
import com.yevsieiev.authstarter.jwt.TokenCipher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.Date;

@RequiredArgsConstructor
@Slf4j
public class JwtTokenProvider {
    private final JwtProperties jwtProperties;
    private final TokenCipher tokenCipher;
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

    public String getUsernameFromToken(String encryptedToken) {
        try {
            String token = tokenCipher.decipherToken(encryptedToken);
            log.info("Decrypted Token: {}", token);
            return JWT.decode(token).getSubject();
        } catch (JWTDecodeException e) {
            throw new InvalidTokenException("Invalid token format");
        }
    }

    public String getHashedFingerprintFromToken(String encryptedToken) {
        try {
            String token = tokenCipher.decipherToken(encryptedToken);
            return JWT.decode(token).getClaim("fingerprint").asString();
        } catch (JWTDecodeException e) {
            throw new RuntimeException(e);
        }
    }
}
