package com.yevsieiev.authstarter.dto.response.register;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DefaultRegisterResponse implements RegisterResponse {
    private String message;
}
