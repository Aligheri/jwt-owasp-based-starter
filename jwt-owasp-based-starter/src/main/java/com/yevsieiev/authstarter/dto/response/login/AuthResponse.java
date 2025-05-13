package com.yevsieiev.authstarter.dto.response.login;

import java.time.Instant;

/**
 * Интерфейс для ответа аутентификации
 */
public interface AuthResponse {
    String getAccessToken();
    Long getExpiresIn();
}
