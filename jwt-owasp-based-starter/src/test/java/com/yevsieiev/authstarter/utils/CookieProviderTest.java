package com.yevsieiev.authstarter.utils;

import com.yevsieiev.authstarter.config.JwtProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class CookieProviderTest {

    @Mock
    private JwtProperties jwtProperties;

    private CookieProvider cookieProvider;


    @BeforeEach
    void setUp() {
        when(jwtProperties.getFingerprintCookieName()).thenReturn("test-value");
        when(jwtProperties.getFingerprintCookieMaxAge()).thenReturn(3600);
        cookieProvider = new CookieProvider(jwtProperties);
    }

    @Test
    void setFingerprintCookie_shouldCreateValidCookieHeader() {
        HttpServletResponse response = mock(HttpServletResponse.class);
        String fingerprint = "test-value";

        cookieProvider.setFingerprintCookie(response, fingerprint);

        ArgumentCaptor<String> headerCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> valueCaptor = ArgumentCaptor.forClass(String.class);

        verify(response).addHeader(headerCaptor.capture(), valueCaptor.capture());

        assertTrue(headerCaptor.getValue().equalsIgnoreCase("Set-Cookie"));
        assertTrue(valueCaptor.getValue().contains("test-value"));
        assertTrue(valueCaptor.getValue().contains("HttpOnly"));
        assertTrue(valueCaptor.getValue().contains("Path=/"));
    }

    @Test
    void extractFingerprintCookie_shouldReturnCookieValue_whenCookiePresent() {
        JwtProperties jwtProperties = mock(JwtProperties.class);
        when(jwtProperties.getFingerprintCookieName()).thenReturn("fingerprint");

        CookieProvider provider = new CookieProvider(jwtProperties);

        Cookie[] cookies = {
                new Cookie("other", "abc"),
                new Cookie("fingerprint", "test-value")
        };

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getCookies()).thenReturn(cookies);

        String result = provider.extractFingerprintCookie(request);

        assertEquals("test-value", result);
    }

    @Test
    void extractFingerprintCookie_shouldReturnNull_whenCookieNotPresent() {
        JwtProperties jwtProperties = mock(JwtProperties.class);
        when(jwtProperties.getFingerprintCookieName()).thenReturn("fingerprint");

        CookieProvider provider = new CookieProvider(jwtProperties);

        Cookie[] cookies = {
                new Cookie("something-else", "value")
        };

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getCookies()).thenReturn(cookies);

        String result = provider.extractFingerprintCookie(request);

        assertNull(result);
    }

    @Test
    void extractFingerprintCookie_shouldReturnNull_whenNoCookies() {
        JwtProperties jwtProperties = mock(JwtProperties.class);
        when(jwtProperties.getFingerprintCookieName()).thenReturn("fingerprint");

        CookieProvider provider = new CookieProvider(jwtProperties);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getCookies()).thenReturn(null);

        String result = provider.extractFingerprintCookie(request);

        assertNull(result);
    }
    @Test
    void deleteCookie_shouldDeleteCookie() {
        HttpServletResponse response = mock(HttpServletResponse.class);
        String cookie = "fingerprint";

        cookieProvider.deleteCookie(response, cookie);

        ArgumentCaptor<String> headerCaptor = ArgumentCaptor.forClass(String.class);

        verify(response).addHeader(headerCaptor.capture(), anyString());

        assertFalse(headerCaptor.getValue().contains(cookie));
    }

}