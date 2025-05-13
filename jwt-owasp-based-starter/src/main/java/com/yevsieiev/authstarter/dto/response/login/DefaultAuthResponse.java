package com.yevsieiev.authstarter.dto.response.login;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class DefaultAuthResponse implements AuthResponse {
    private String token;
}
