package com.yevsieiev.authstarter.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.yevsieiev.authstarter.config.JwtProperties;
import com.yevsieiev.authstarter.jwt.TokenCipher;
import com.yevsieiev.authstarter.jwt.TokenRevoker;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TokenValidationUtilsTest {

    @Mock private JwtProperties jwtProperties;
    @Mock private TokenCipher tokenCipher;
    @Mock private TokenRevoker tokenRevoker;
    @Mock private com.auth0.jwt.algorithms.Algorithm jwtAlgorithm;
    @Mock private CookieProvider cookieProvider;
    @Mock private HttpServletRequest request;
    @Mock private DecodedJWT decodedJWT;
    @Mock private JWTVerifier jwtVerifier;

    private TokenValidationUtils tokenValidationUtils;

    @BeforeEach
    void setUp() {
        when(jwtProperties.getTokenValidity()).thenReturn(Duration.ofHours(1));
        when(jwtProperties.getSecretKey()).thenReturn("test-secret");
        when(jwtProperties.getIssuerId()).thenReturn("test-issuer");
        when(jwtProperties.getFingerprintCookieName()).thenReturn("fingerprint");
        when(jwtProperties.getFingerprintCookieMaxAge()).thenReturn(3600);

        tokenValidationUtils = new TokenValidationUtils(
                jwtProperties, tokenCipher, tokenRevoker, jwtAlgorithm, cookieProvider
        );
    }

    @Test
    void validateToken_shouldReturnTrue_whenTokenIsValid() {
        String encryptedToken = "encrypted.token.value";
        String decryptedToken = "decrypted.token.value";
        String fingerprint = "fingerprint-value";
        String fingerprintHash = "hashed-fingerprint";

        when(tokenRevoker.isTokenRevoked(encryptedToken)).thenReturn(false);
        when(tokenCipher.decipherToken(encryptedToken)).thenReturn(decryptedToken);
        when(cookieProvider.extractFingerprintCookie(request)).thenReturn(fingerprint);

        try (MockedStatic<FingerprintUtils> fingerprintUtilsMock = mockStatic(FingerprintUtils.class);
             MockedStatic<JWT> jwtMock = mockStatic(JWT.class)) {

            fingerprintUtilsMock
                    .when(() -> FingerprintUtils.hashFingerprint(fingerprint))
                    .thenReturn(fingerprintHash);

            JWTVerifier.BaseVerification verificationMock = mock(JWTVerifier.BaseVerification.class, RETURNS_DEEP_STUBS);
            when(JWT.require(jwtAlgorithm)).thenReturn(verificationMock);
            when(verificationMock.withIssuer("test-issuer")
                    .withClaim(eq("fingerprint"), eq(fingerprintHash))
                    .acceptNotBefore(anyLong())
                    .acceptExpiresAt(5)
                    .build()).thenReturn(jwtVerifier);

            when(jwtVerifier.verify(decryptedToken)).thenReturn(decodedJWT);

            boolean result = tokenValidationUtils.validateToken(encryptedToken, request);

            assertTrue(result);
        }
    }
}