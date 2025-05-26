package com.yevsieiev.authstarter.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.time.Instant;

/**
 * JWT Authentication Entry Point to handle unauthorized requests.
 */

public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException
    ) throws IOException {
        logger.error("Unauthorized error [URI: {}][Method: {}]: {}",
                request.getRequestURI(),
                request.getMethod(),
                authException.getMessage()
        );

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader(HttpHeaders.PRAGMA, "no-cache");

        ErrorResponse errorResponse = new ErrorResponse(
                HttpServletResponse.SC_UNAUTHORIZED,
                "Unauthorized",
                "Authentication failed",
                request.getServletPath(),
                Instant.now(),
                "ERR-401-AUTH"
        );

        try {
            MAPPER.writeValue(response.getOutputStream(), errorResponse);
        } catch (IOException e) {
            logger.error("Failed to serialize error response: {}", e.getMessage());
            throw e;
        }
    }

    private record ErrorResponse(
            int status,
            String error,
            String message,
            String path,
            Instant timestamp,
            String errorCode
    ) {
    }
}
