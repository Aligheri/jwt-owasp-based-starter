package com.yevsieiev.authstarter.dto.response.login;

import java.time.Instant;

public interface AuthResponse {
    String getToken();
    void setToken(String token);
}
