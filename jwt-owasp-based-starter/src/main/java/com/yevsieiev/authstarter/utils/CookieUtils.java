package com.yevsieiev.authstarter.utils;

import com.yevsieiev.authstarter.config.JwtProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;

import java.util.Arrays;
import java.util.Optional;

@RequiredArgsConstructor
public class CookieUtils {

    private final JwtProperties jwtProperties;

    public void setFingerprintCookie(HttpServletResponse response, String fingerprint) {
        ResponseCookie cookie = createSecureCookie(
                jwtProperties.getFingerprintCookieName(),
                fingerprint,
                jwtProperties.getFingerprintCookieMaxAge()
        );
        response.addHeader("Set-Cookie", cookie.toString());
    }

    public String extractFingerprintCookie(HttpServletRequest request) {
        return getCookieValue(request, jwtProperties.getFingerprintCookieName())
                .orElse(null);
    }

    private ResponseCookie createSecureCookie(String name, String value, int maxAge) {
        return ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(maxAge)
                .sameSite("Strict")
                .build();
    }

    private Optional<String> getCookieValue(HttpServletRequest request, String name) {
        return Optional.ofNullable(request.getCookies())
                .map(Arrays::stream)
                .flatMap(stream -> stream.filter(c -> name.equals(c.getName())).findFirst())
                .map(Cookie::getValue);
    }

    public void deleteCookie(HttpServletResponse response, String name) {
        ResponseCookie cookie = ResponseCookie.from(name, "")
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(0)
                .sameSite("Lax")
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }
}
