package com.yevsieiev.authstarter.auth;

import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@Data
@NoArgsConstructor
public class RegistrationRequest {
    private String username;
    private String password;
    private String email;

}
