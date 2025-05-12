package com.yevsieiev.authstarter.service;

import com.yevsieiev.authstarter.auth.AuthRequest;
import com.yevsieiev.authstarter.auth.AuthResponse;
import com.yevsieiev.authstarter.auth.RegistrationRequest;
import com.yevsieiev.authstarter.dto.MessageResponse;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Interface for authentication services
 */
public interface AuthenticationService {
    
    /**
     * Register a new user
     *
     * @param registrationRequest the registration request
     * @return a message response indicating success or failure
     */
    MessageResponse registerUser(RegistrationRequest registrationRequest);
    
    /**
     * Authenticate a user
     *
     * @param loginRequest the login request
     * @param response the HTTP servlet response
     * @param issuerId the issuer ID for the JWT
     * @return an authentication response containing the JWT token and user details
     */
    AuthResponse authenticateUser(AuthRequest loginRequest, HttpServletResponse response, String issuerId);
    
    /**
     * Logout a user
     *
     * @param jwtToken the JWT token
     * @param response the HTTP servlet response
     * @param cookieName the name of the cookie to delete
     * @return a message response indicating success or failure
     */
    MessageResponse logout(String jwtToken, HttpServletResponse response, String cookieName);
    

}