package com.yevsieiev.authstarter.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Базовая реализация RegisterRequest
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class DefaultRegistrationRequest  {
    @NotBlank
    @Size(min = 3, max = 50)
    private String username;

    @NotBlank
    @Size(min = 6)
    private String password;

    @Email
    @NotBlank
    private String email;
    
    private Set<String> roles = new HashSet<>();

}