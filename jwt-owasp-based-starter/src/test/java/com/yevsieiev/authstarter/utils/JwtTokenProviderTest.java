package com.yevsieiev.authstarter.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.yevsieiev.authstarter.config.JwtProperties;
import com.yevsieiev.authstarter.exceptions.TokenDecryptionException;
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

import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class JwtTokenProviderTest {

    @Mock
    private JwtProperties jwtProperties;

    @Mock
    private TokenCipher tokenCipher;

    @Mock
    private TokenRevoker tokenRevoker;

    @Mock
    private FingerprintUtils fingerprintUtils;

    private Algorithm jwtAlgorithm;
    private JwtTokenProvider jwtTokenProvider;

    @BeforeEach
    void setUp() {
        jwtAlgorithm = Algorithm.HMAC256("test-secret");
        jwtTokenProvider = new JwtTokenProvider(jwtProperties, tokenCipher, tokenRevoker, fingerprintUtils, jwtAlgorithm);
    }

    @Test
    void generateToken_validInput_containsCorrectClaims() {
        // Setup mocks specifically for this test
        when(jwtProperties.getIssuerId()).thenReturn("test-issuer");
        when(jwtProperties.getTokenValidity()).thenReturn(Duration.ofHours(1));

        String username = "test-user";
        String fingerprintHash = "fingerprint-hash";
        Instant fixedNow = Instant.now(); // Fixed timestamp

        String token = jwtTokenProvider.generateToken(username, fingerprintHash);

        DecodedJWT decodedJWT = JWT.decode(token);
        assertThat(decodedJWT.getSubject()).isEqualTo(username);
        assertThat(decodedJWT.getIssuer()).isEqualTo("test-issuer");
        assertThat(decodedJWT.getClaim("fingerprint").asString()).isEqualTo(fingerprintHash);
        assertThat(decodedJWT.getExpiresAt()).isBetween(
                Date.from(fixedNow.plus(Duration.ofHours(1).minusSeconds(1))),
                Date.from(fixedNow.plus(Duration.ofHours(1).plusSeconds(1)))
        );
    }

    @Test
    void validateToken_tokenRevoked_returnsFalse() throws Exception {
        String encryptedToken = "encrypted-token";
        HttpServletRequest request = mock(HttpServletRequest.class);

        when(tokenRevoker.isTokenRevoked(encryptedToken)).thenReturn(true);

        boolean isValid = jwtTokenProvider.validateToken(encryptedToken, request);

        assertThat(isValid).isFalse();
        verify(tokenRevoker).isTokenRevoked(encryptedToken);
        verifyNoInteractions(tokenCipher);
    }

    @Test
    void validateToken_decryptionFails_returnsFalse() throws Exception {
        String encryptedToken = "encrypted-token";
        HttpServletRequest request = mock(HttpServletRequest.class);

        when(tokenRevoker.isTokenRevoked(encryptedToken)).thenReturn(false);
        when(tokenCipher.decipherToken(encryptedToken)).thenThrow(new GeneralSecurityException("Decryption failed"));

        boolean isValid = jwtTokenProvider.validateToken(encryptedToken, request);

        assertThat(isValid).isFalse();
        verify(tokenCipher).decipherToken(encryptedToken);
    }

    @Test
    void validateToken_invalidFingerprint_returnsFalse() throws Exception {
        String encryptedToken = "encrypted-token";
        String decryptedToken = generateValidToken("wrong-hash");
        HttpServletRequest request = mock(HttpServletRequest.class);

        when(tokenRevoker.isTokenRevoked(encryptedToken)).thenReturn(false);
        when(tokenCipher.decipherToken(encryptedToken)).thenReturn(decryptedToken);
        when(fingerprintUtils.validateFingerprint(request)).thenReturn("actual-fingerprint");
        try (MockedStatic<FingerprintUtils> mocked = mockStatic(FingerprintUtils.class)) {
            mocked.when(() -> FingerprintUtils.hashFingerprint("actual-fingerprint"))
                    .thenReturn("correct-hash");

            boolean isValid = jwtTokenProvider.validateToken(encryptedToken, request);

            assertThat(isValid).isFalse();
        }
    }

    @Test
    void validateToken_validToken_returnsTrue() throws Exception {
        String encryptedToken = "encrypted-token";
        String fingerprintHash = "correct-hash";
        String decryptedToken = generateValidToken(fingerprintHash);
        HttpServletRequest request = mock(HttpServletRequest.class);

        when(jwtProperties.getIssuerId()).thenReturn("test-issuer");
        when(tokenRevoker.isTokenRevoked(encryptedToken)).thenReturn(false);
        when(tokenCipher.decipherToken(encryptedToken)).thenReturn(decryptedToken);
        when(fingerprintUtils.validateFingerprint(request)).thenReturn("fingerprint");
        try (MockedStatic<FingerprintUtils> mocked = mockStatic(FingerprintUtils.class)) {
            mocked.when(() -> FingerprintUtils.hashFingerprint("fingerprint"))
                    .thenReturn(fingerprintHash);

            boolean isValid = jwtTokenProvider.validateToken(encryptedToken, request);

            assertThat(isValid).isTrue();
        }
    }

    @Test
    void getUsernameFromToken_validToken_returnsUsername() throws GeneralSecurityException {
        String encryptedToken = "encrypted-token";
        String decryptedToken = generateValidToken("test-hash");

        when(tokenCipher.decipherToken(encryptedToken)).thenReturn(decryptedToken);

        String username = jwtTokenProvider.getUsernameFromToken(encryptedToken);

        assertThat(username).isEqualTo("test-user");
    }

    @Test
    void getUsernameFromToken_decryptionFails_throwsTokenDecryptionException() throws GeneralSecurityException {
        String encryptedToken = "encrypted-token";

        when(tokenCipher.decipherToken(encryptedToken)).thenThrow(new GeneralSecurityException("Decryption failed"));

        assertThatThrownBy(() -> jwtTokenProvider.getUsernameFromToken(encryptedToken))
                .isInstanceOf(TokenDecryptionException.class)
                .hasMessageContaining("Token decryption failed");
    }

    @Test
    void getUsernameFromToken_invalidToken_throwsInvalidTokenException() throws GeneralSecurityException {
        String encryptedToken = "encrypted-token";
        String invalidToken = JWT.create()
                .withSubject("test-user")
                .withIssuer("wrong-issuer")
                .sign(jwtAlgorithm);

        when(tokenCipher.decipherToken(encryptedToken)).thenReturn(invalidToken);
        when(jwtProperties.getIssuerId()).thenReturn("test-issuer"); // Mock issuer check

        assertThatThrownBy(() -> jwtTokenProvider.getUsernameFromToken(encryptedToken))
                .isInstanceOf(JWTVerificationException.class);
    }

    private String generateValidToken(String fingerprintHash) {
        return JWT.create()
                .withSubject("test-user")
                .withIssuer("test-issuer")
                .withExpiresAt(Date.from(Instant.now().plus(Duration.ofHours(1))))
                .withClaim("fingerprint", fingerprintHash)
                .sign(jwtAlgorithm);
    }
}