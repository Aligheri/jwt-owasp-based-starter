package com.yevsieiev.authstarter.utils;

import com.yevsieiev.authstarter.config.JwtProperties;
import com.yevsieiev.authstarter.exceptions.FingerprintValidationException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.Arrays;
import java.util.Optional;

import static com.yevsieiev.authstarter.utils.FingerprintUtils.*;

@Slf4j
@RequiredArgsConstructor
public class CookieValidationUtils {
    private final JwtProperties jwtProperties;
    private final JwtTokenProvider jwtTokenProvider;
    private static final int FINGERPRINT_LENGTH = 100;
    private static final String FINGERPRINT_PATTERN = "^[a-zA-Z0-9]{100}$";

    public boolean isValidCookie(HttpServletRequest request) {
        try {
            validateCookie(request);
            return true;
        } catch (FingerprintValidationException e) {
            log.warn("Cookie validation failed: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("Unexpected error during cookie validation", e);
            return false;
        }
    }

    public String validateFingerprintCookie(HttpServletRequest request) throws FingerprintValidationException {
        if (request.getCookies() == null || request.getCookies().length == 0) {
            throw new FingerprintValidationException("No cookies found in request");
        }

        String cookieName = jwtProperties.getFingerprintCookieName();

        Optional<Cookie> fingerprintCookie = Arrays.stream(request.getCookies())
                .filter(cookie -> cookieName.equals(cookie.getName()))
                .findFirst();

        if (fingerprintCookie.isEmpty()) {
            throw new FingerprintValidationException("Fingerprint cookie not found");
        }

        Cookie cookie = fingerprintCookie.get();
        String fingerprintValue = cookie.getValue();

        validateFingerprintFormat(fingerprintValue);

        validateCookieFlags(cookie, request);

        validateCookieExpiration(cookie);

        log.debug("Fingerprint cookie validation successful for value: {}",
                fingerprintValue.substring(0, 10) + "...");

        return fingerprintValue;
    }

    public void validateFingerprintFormat(String fingerprint) throws FingerprintValidationException {
        if (fingerprint == null || fingerprint.isEmpty()) {
            throw new FingerprintValidationException("Fingerprint value is null or empty");
        }

        if (fingerprint.length() != FINGERPRINT_LENGTH) {
            throw new FingerprintValidationException(
                    String.format("Invalid fingerprint length. Expected: %d, Actual: %d",
                            FINGERPRINT_LENGTH, fingerprint.length()));
        }

        if (!fingerprint.matches(FINGERPRINT_PATTERN)) {
            throw new FingerprintValidationException(
                    "Fingerprint contains invalid characters. Only alphanumeric characters are allowed");
        }
    }

    /**
     * Validates cookie security flags (HttpOnly, Secure, SameSite)
     */
    private void validateCookieFlags(Cookie cookie, HttpServletRequest request) throws FingerprintValidationException {
        if (!cookie.isHttpOnly()) {
            throw new FingerprintValidationException("Fingerprint cookie must have HttpOnly flag set");
        }

        if (request.isSecure() && !cookie.getSecure()) {
            throw new FingerprintValidationException("Fingerprint cookie must have Secure flag set for HTTPS requests");
        }

        String expectedPath = "/";
        if (!expectedPath.equals(cookie.getPath())) {
            log.warn("Cookie path mismatch. Expected: {}, Actual: {}", expectedPath, cookie.getPath());
        }
    }

    private void validateCookieExpiration(Cookie cookie) throws FingerprintValidationException {
        int maxAge = cookie.getMaxAge();

        if (maxAge == 0) {
            throw new FingerprintValidationException("Fingerprint cookie has expired");
        }

        int expectedMaxAge = jwtProperties.getFingerprintCookieMaxAge();
        if (maxAge > 0 && maxAge > expectedMaxAge) {
            log.warn("Cookie max age ({}) exceeds expected max age ({})", maxAge, expectedMaxAge);
        }
    }

    /**
     * Validates fingerprint against JWT token claim
     *
     * @param rawFingerprint Raw fingerprint from cookie
     * @return true if fingerprints match
     */
    public boolean validateFingerprintMatch(String rawFingerprint) {
        try {
            String tokenFingerprintHash = jwtTokenProvider.getHashedFingerprintFromToken(rawFingerprint);
            String hashedFingerprint = hashFingerprint(rawFingerprint);
            boolean matches = hashedFingerprint.equals(tokenFingerprintHash);

            if (!matches) {
                log.warn("Fingerprint mismatch detected. Cookie fingerprint hash does not match token claim");
            }

            return matches;
        } catch (Exception e) {
            log.error("Error validating fingerprint match", e);
            return false;
        }
    }

    /**
     * Complete fingerprint validation for use in JWT validation
     *
     * @param request HTTP request
     * @return validated raw fingerprint
     * @throws FingerprintValidationException if any validation fails
     */
    public String validateCookie(HttpServletRequest request)
            throws FingerprintValidationException {

        String rawFingerprint = validateFingerprintCookie(request);

        if (!validateFingerprintMatch(rawFingerprint)) {
            throw new FingerprintValidationException("Fingerprint does not match token claim");
        }

        return rawFingerprint;
    }
}
