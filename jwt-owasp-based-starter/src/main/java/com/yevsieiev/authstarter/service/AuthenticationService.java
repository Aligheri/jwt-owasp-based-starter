package com.yevsieiev.authstarter.service;

import com.yevsieiev.authstarter.dto.response.login.DefaultAuthResponse;
import com.yevsieiev.authstarter.dto.request.login.DefaultAuthRequest;
import com.yevsieiev.authstarter.dto.response.register.DefaultRegisterResponse;
import com.yevsieiev.authstarter.dto.request.register.DefaultRegistrationRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Interface for authentication services
 */
public interface AuthenticationService {
    
    /**
     * Register a new user
     *
     * @param defaultRegistrationRequest the registration request
     * @return a message response indicating success or failure
     */
    DefaultRegisterResponse registerUser(DefaultRegistrationRequest defaultRegistrationRequest);
    
    /**
     * Authenticate a user
     *
     * @param loginRequest the login request
     * @param response the HTTP servlet response
     * @param issuerId the issuer ID for the JWT
     * @return an authentication response containing the JWT token and user details
     */
    DefaultAuthResponse authenticateUser(DefaultAuthRequest loginRequest, HttpServletResponse response, String issuerId);
    
    /**
     * Logout a user
     *
     * @param jwtToken the JWT token
     * @param response the HTTP servlet response
     * @param cookieName the name of the cookie to delete
     * @return a message response indicating success or failure
     */
    DefaultRegisterResponse logout(String jwtToken, HttpServletResponse response, String cookieName);
    

}