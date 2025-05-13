package com.yevsieiev.authstarter.dto.request.register;

import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@Data
@NoArgsConstructor
public class DefaultRegistrationRequest implements RegisterRequest {
    private String username;
    private String password;
    private String email;

}
