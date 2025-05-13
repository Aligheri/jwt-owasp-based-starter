package com.yevsieiev.authstarter.service;

import com.yevsieiev.authstarter.dto.request.login.AuthRequest;
import com.yevsieiev.authstarter.dto.request.register.RegisterRequest;
import com.yevsieiev.authstarter.dto.response.login.AuthResponse;
import com.yevsieiev.authstarter.dto.response.login.DefaultAuthResponse;
import com.yevsieiev.authstarter.dto.request.login.DefaultAuthRequest;
import com.yevsieiev.authstarter.dto.response.register.DefaultRegisterResponse;
import com.yevsieiev.authstarter.dto.request.register.DefaultRegistrationRequest;
import com.yevsieiev.authstarter.dto.response.register.RegisterResponse;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Interface for authentication services
 */
public interface AuthenticationService<
        T extends AuthRequest,
        R extends AuthResponse,
        U extends RegisterRequest,
        V extends RegisterResponse> {

    R authenticateUser(T loginRequest, HttpServletResponse response, String issuerId);

    V registerUser(U registrationRequest);

    V logout(String jwtToken, HttpServletResponse response, String cookieName);
}