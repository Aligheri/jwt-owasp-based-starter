package com.yevsieiev.authstarter.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
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
        if (username == null || username.isEmpty()) {
            throw new IllegalArgumentException("Username cannot be null or empty");
        }

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
        if (encryptedToken == null) {
            throw new IllegalArgumentException("Token cannot be null");
        }

        try {
            String token = tokenCipher.decipherToken(encryptedToken);
            log.info("Decrypted Token: {}", token);

            // Add proper verification
            JWTVerifier verifier = JWT.require(jwtAlgorithm)
                    .withIssuer(jwtProperties.getIssuerId())
                    .build();

            DecodedJWT jwt = verifier.verify(token);
            return jwt.getSubject();
        } catch (JWTDecodeException e) {
            throw new InvalidTokenException("Invalid token format");
        } catch (TokenExpiredException e) {
            throw new InvalidTokenException("Token has expired");
        } catch (JWTVerificationException e) {
            throw new InvalidTokenException("Invalid token: " + e.getMessage());
        }
    }

    public String getHashedFingerprintFromToken(String encryptedToken) {
        try {
            String token = tokenCipher.decipherToken(encryptedToken);
            DecodedJWT jwt = JWT.decode(token);

            String fingerprint = jwt.getClaim("fingerprint").asString();
            if (fingerprint == null) {
                throw new HashFingerprintException("Fingerprint claim missing from token");
            }
            return fingerprint;
        } catch (JWTDecodeException e) {
            throw new InvalidTokenException("Invalid token format");
        }
    }
}
