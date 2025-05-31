package com.yevsieiev.authstarter.utils;

import com.yevsieiev.authstarter.config.JwtProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;


@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class CookieValidationUtilsTest {
    @Mock
    private JwtProperties jwtProperties;
    @Mock
    private JwtTokenProvider jwtTokenProvider;

    private CookieValidationUtils cookieValidationUtils;


    @Mock
    private HttpServletRequest request;

    @BeforeEach
    void setUp() {
        cookieValidationUtils = new CookieValidationUtils(jwtProperties, jwtTokenProvider);
        when(jwtProperties.getFingerprintCookieName()).thenReturn("fingerprint");
        when(jwtProperties.getFingerprintCookieMaxAge()).thenReturn(3600);
    }

    @Test
    void isValidCookie_shouldReturnTrue_whenCookieIsValidAndFingerprintMatches() {
        String token = "valid.jwt.token";
        String rawFingerprint = "a008efee0a071deccba873c61f21eae7d93a2a0ddb4e5640c37f5548446b6447ed603ba2adec9cba080fcc3c251f7a0d6a087f5829fedd046e2b6ea8e6fa7fb6b04b5f1a49a7128b8acc043b47b77d863afe4f121271292e3d7aa750f404d3cbbeb3cfa2";

        Cookie cookie = new Cookie("fingerprint", rawFingerprint);
        cookie.setMaxAge(3600);
        cookie.setSecure(true);

        when(request.getCookies()).thenReturn(new Cookie[]{cookie});
        when(request.isSecure()).thenReturn(true);

        when(jwtTokenProvider.getHashedFingerprintFromToken(token)).thenReturn("e69f4602c33c566c147a730e98cbebf2102a705f06bfe455a90990e0753052ef");

        boolean result = cookieValidationUtils.isValidCookie(request, token);

        assertTrue(result);
    }

    @Test
    void isValidCookie_shouldReturnFalse_whenNoCookiesInRequest() {
        when(request.getCookies()).thenReturn(null);

        boolean result = cookieValidationUtils.isValidCookie(request, "token");

        assertFalse(result);
    }

    @Test
    void isValidCookie_shouldReturnFalse_whenFingerprintCookieNotFound() {
        Cookie[] cookies = {new Cookie("something-else", "value")};
        when(request.getCookies()).thenReturn(cookies);
        boolean result = cookieValidationUtils.isValidCookie(request, "token");
        assertFalse(result);
    }

    @Test
    void isValidCookie_shouldReturnFalse_whenFingerprintFormatIsInvalid() {
        Cookie[] cookies = {new Cookie("fingerprint", "!!!@@@###")};
        cookies[0].setMaxAge(3600);
        cookies[0].setSecure(true);
        when(request.getCookies()).thenReturn(cookies);
        boolean result = cookieValidationUtils.isValidCookie(request, "token");
        assertFalse(result);
    }

    @Test
    void isValidCookie_shouldReturnFalse_whenFingerprintDoesNotMatchToken() {
        String rawFingerprint = "a008efee0a071deccba873c61f21eae7d93a2a0ddb4e5640c37f55" +
                "48446b6447ed603ba2adec9cba080fcc3c251f7a0d6a087f58" +
                "29fedd046e2b6ea8e6fa7fb6b04b5f1a49a7128b8acc043b47b77d863afe4f121271292e3d7aa750f404d3cbbeb3cfa2";

        String invalidFingerprint = hash(rawFingerprint);
        Cookie cookie = new Cookie("fingerprint", rawFingerprint);
        cookie.setMaxAge(3600);
        cookie.setSecure(true);

        when(request.getCookies()).thenReturn(new Cookie[]{cookie});
        when(request.isSecure()).thenReturn(true);
        when(jwtTokenProvider.getHashedFingerprintFromToken("token")).thenReturn(invalidFingerprint);

        boolean result = cookieValidationUtils.isValidCookie(request, "token");

        assertFalse(result);
    }



    private String hash(String raw) {
        return "hashed_" + raw;
    }
}