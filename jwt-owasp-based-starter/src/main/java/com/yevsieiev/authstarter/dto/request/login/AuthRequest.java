package com.yevsieiev.authstarter.dto.request.login;

/**
 * Базовый интерфейс для запроса аутентификации
 */
public interface AuthRequest {
    String getUsername();
    String getPassword();
}