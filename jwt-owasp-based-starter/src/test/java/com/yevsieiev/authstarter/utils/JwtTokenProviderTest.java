package com.yevsieiev.authstarter.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.yevsieiev.authstarter.config.JwtProperties;
import com.yevsieiev.authstarter.exceptions.HashFingerprintException;
import com.yevsieiev.authstarter.exceptions.InvalidTokenException;
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
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class JwtTokenProviderTest {
    @Mock
    private JwtProperties jwtProperties;

    @Mock
    private TokenCipher tokenCipher;

    private JwtTokenProvider jwtTokenProvider;
    private Algorithm testAlgorithm;

    @BeforeEach
    void setUp() {
        testAlgorithm = Algorithm.HMAC256("test-secret");

        when(jwtProperties.getTokenValidity()).thenReturn(Duration.ofHours(1));
        when(jwtProperties.getIssuerId()).thenReturn("test-issuer");

        jwtTokenProvider = new JwtTokenProvider(jwtProperties, tokenCipher, testAlgorithm);
    }

    @Test
    void generateToken_shouldCreateValidJwtWithCorrectClaims() {
        String username = "testUser";
        String fingerprint = "fingerprint123";

        String token = jwtTokenProvider.generateToken(username, fingerprint);

        assertNotNull(token);

        DecodedJWT decodedJWT = JWT.decode(token);

        assertEquals(username, decodedJWT.getSubject());
        assertEquals("test-issuer", decodedJWT.getIssuer());
        assertEquals(fingerprint, decodedJWT.getClaim("fingerprint").asString());
        assertTrue(decodedJWT.getExpiresAt().toInstant().isAfter(Instant.now()));
    }
    @Test
    void getUsernameFromToken_shouldReturnUsernameForValidToken() {
        String testToken = "valid.token.here";
        String decryptedToken = "header.payload.signature";
        when(tokenCipher.decipherToken(testToken)).thenReturn(decryptedToken);


        DecodedJWT mockJwt = mock(DecodedJWT.class);
        when(mockJwt.getSubject()).thenReturn("testUser");

        String realToken = jwtTokenProvider.generateToken("testUser", "fp123");
        when(tokenCipher.decipherToken(testToken)).thenReturn(realToken);
        String username = jwtTokenProvider.getUsernameFromToken(testToken);
        assertEquals("testUser", username);
    }

    @Test
    void getHashedFingerprintFromToken_shouldReturnFingerprint() {
        String testFingerprint = "testFingerprintHash";
        String realToken = jwtTokenProvider.generateToken("user", testFingerprint);
        when(tokenCipher.decipherToken(anyString())).thenReturn(realToken);

        String fingerprint = jwtTokenProvider.getHashedFingerprintFromToken("encryptedToken");

        assertEquals(testFingerprint, fingerprint);
    }

    @Test
    void generatedToken_shouldExpireAfterConfiguredDuration() {
        String username = "testUser";
        String fingerprint = "fingerprint123";
        Duration validity = Duration.ofMinutes(30);
        when(jwtProperties.getTokenValidity()).thenReturn(validity);

        String token = jwtTokenProvider.generateToken(username, fingerprint);
        DecodedJWT decodedJWT = JWT.decode(token);
        Instant expiration = decodedJWT.getExpiresAt().toInstant();

        assertTrue(expiration.isAfter(Instant.now()));
        assertTrue(expiration.isBefore(Instant.now().plus(validity).plusSeconds(1)));
    }

    @Test
    void getUsernameFromToken_shouldThrowWhenTokenCannotBeDeciphered() {

        String invalidToken = "invalid.token";
        when(tokenCipher.decipherToken(invalidToken))
                .thenThrow(new InvalidTokenException("Decryption failed"));

        assertThrows(InvalidTokenException.class, () -> {
            jwtTokenProvider.getUsernameFromToken(invalidToken);
        });
    }

    @Test
    void getHashedFingerprintFromToken_shouldThrowWhenFingerprintMissing() {
        String tokenWithoutFp = JWT.create()
                .withSubject("testUser")
                .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))
                .sign(testAlgorithm);

        when(tokenCipher.decipherToken(anyString())).thenReturn(tokenWithoutFp);

        assertThrows(HashFingerprintException.class, () -> {
            jwtTokenProvider.getHashedFingerprintFromToken(tokenWithoutFp);
        });
    }

    @Test
    void getUsernameFromToken_shouldThrowForTokenWithDifferentAlgorithm() {
        Algorithm differentAlgorithm = Algorithm.HMAC256("different-secret");
        String tokenWithDifferentAlg = JWT.create()
                .withSubject("testUser")
                .sign(differentAlgorithm);

        when(tokenCipher.decipherToken(anyString())).thenReturn(tokenWithDifferentAlg);

        assertThrows(InvalidTokenException.class, () -> {
            jwtTokenProvider.getUsernameFromToken("anyToken");
        });
    }

    @Test
    void generatedToken_shouldHaveCorrectNotBeforeClaim() {
        String username = "testUser";
        String fingerprint = "fingerprint123";

        String token = jwtTokenProvider.generateToken(username, fingerprint);
        DecodedJWT decodedJWT = JWT.decode(token);

        assertNotNull(decodedJWT.getNotBefore());
        assertTrue(decodedJWT.getNotBefore().toInstant().isBefore(Instant.now()) ||
                decodedJWT.getNotBefore().toInstant().equals(Instant.now()));
    }

    @Test
    void generateToken_shouldThrowForNullUsername() {
        assertThrows(IllegalArgumentException.class, () -> {
            jwtTokenProvider.generateToken(null, "fingerprint");
        });
    }

    @Test
    void generateToken_shouldThrowForEmptyUsername() {
        assertThrows(IllegalArgumentException.class, () -> {
            jwtTokenProvider.generateToken("", "fingerprint");
        });
    }

    @Test
    void getUsernameFromToken_shouldThrowForNullToken() {
        assertThrows(IllegalArgumentException.class, () -> {
            jwtTokenProvider.getUsernameFromToken(null);
        });
    }

    @Test
    void getUsernameFromToken_shouldThrowForMalformedToken() {
        when(tokenCipher.decipherToken("malformed")).thenReturn("not.a.valid.jwt");

        assertThrows(InvalidTokenException.class, () -> {
            jwtTokenProvider.getUsernameFromToken("malformed");
        });
    }
    @Test
    void getUsernameFromToken_shouldThrowForExpiredToken() {

        String expiredToken = JWT.create()
                .withSubject("testUser")
                .withExpiresAt(Date.from(Instant.now().minusSeconds(1)))
                .sign(testAlgorithm);

        when(tokenCipher.decipherToken("expired")).thenReturn(expiredToken);

        assertThrows(InvalidTokenException.class, () -> {
            jwtTokenProvider.getUsernameFromToken("expired");
        });
    }

    @Test
    void getUsernameFromToken_shouldThrowForTokenNotYetValid() {
        String futureToken = JWT.create()
                .withSubject("testUser")
                .withNotBefore(Date.from(Instant.now().plusSeconds(3600)))
                .sign(testAlgorithm);

        when(tokenCipher.decipherToken("future")).thenReturn(futureToken);

        assertThrows(InvalidTokenException.class, () -> {
            jwtTokenProvider.getUsernameFromToken("future");
        });
    }
    @Test
    void getUsernameFromToken_shouldThrowForWrongIssuer() {
        String wrongIssuerToken = JWT.create()
                .withSubject("testUser")
                .withIssuer("wrong-issuer")
                .sign(testAlgorithm);

        when(tokenCipher.decipherToken("wrongIssuer")).thenReturn(wrongIssuerToken);

        assertThrows(InvalidTokenException.class, () -> {
            jwtTokenProvider.getUsernameFromToken("wrongIssuer");
        });
    }
}