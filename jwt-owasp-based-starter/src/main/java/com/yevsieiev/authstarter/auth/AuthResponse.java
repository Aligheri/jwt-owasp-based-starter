package com.yevsieiev.authstarter.auth;

/**
 * Интерфейс для ответа аутентификации
 */
public interface AuthResponse {
    String getAccessToken();
    String getTokenType();
    long getExpiresIn();
}
