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
        ResponseCookie cookie = ResponseCookie.from(jwtProperties.getFingerprintCookieName(), fingerprint)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(jwtProperties.getFingerprintCookieMaxAge())
                .sameSite("Lax")
                .build();

        response.addHeader("Set-Cookie", cookie.toString());
    }

    public static String extractFingerprintCookie(HttpServletRequest request, String cookieName) {
        return Optional.ofNullable(request.getCookies())
                .stream()
                .flatMap(Arrays::stream)
                .filter(c -> c.getName().equals(cookieName))
                .findFirst()
                .map(Cookie::getValue)
                .orElse(null);
    }
}

