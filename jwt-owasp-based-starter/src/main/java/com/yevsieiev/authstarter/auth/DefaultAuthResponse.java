package com.yevsieiev.authstarter.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Базовая реализация AuthResponse
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class DefaultAuthResponse implements AuthResponse {
    private String accessToken;
    private String tokenType = "Bearer";
    private long expiresIn;
}
