package com.yevsieiev.authstarter.auth;

/**
 * Базовый интерфейс для запроса аутентификации
 */
public interface AuthRequest {
    String getUsername();
    String getPassword();
}