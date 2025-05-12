package com.yevsieiev.authstarter.controller;

import com.yevsieiev.authstarter.auth.AuthRequest;
import com.yevsieiev.authstarter.auth.AuthResponse;
import com.yevsieiev.authstarter.auth.DefaultLoginRequest;
import com.yevsieiev.authstarter.auth.RegistrationRequest;
import com.yevsieiev.authstarter.config.ValidationProperties;
import com.yevsieiev.authstarter.dto.MessageResponse;
import com.yevsieiev.authstarter.service.DefaultAuthenticationService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for handling authentication requests
 */

@RequestMapping("/api/auth")
public class AuthenticationController {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationController.class);

    private final DefaultAuthenticationService authenticationService;
    private final ValidationProperties validationProperties;



    public AuthenticationController(DefaultAuthenticationService authenticationService, ValidationProperties validationProperties) {
        this.authenticationService = authenticationService;
        this.validationProperties = validationProperties;
    }

    /**
     * Register a new user
     *
     * @param registrationRequest the registration request
     * @return a response entity with a message
     */
    @PostMapping("/register")
    public ResponseEntity<MessageResponse> registerUser(@Valid @RequestBody RegistrationRequest registrationRequest) {
        logger.info("Attempting to register user: {}", registrationRequest.getUsername());
        MessageResponse messageResponse = authenticationService.registerUser(registrationRequest);
        if (messageResponse.getMessage().startsWith("Error:")) {
            logger.warn("Registration error: {}", messageResponse.getMessage());
            return ResponseEntity.badRequest().body(messageResponse);
        } else {
            logger.info("User registered successfully: {}", registrationRequest.getUsername());
            return ResponseEntity.ok(messageResponse);
        }
    }

    /**
     * Authenticate a user
     *
     * @param loginRequest the login request
     * @param response the HTTP servlet response
     * @return a response entity with an authentication response
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> loginUser(@Valid @RequestBody DefaultLoginRequest loginRequest, HttpServletResponse response) {
        logger.info("Attempting to authenticate user: {}", loginRequest.getUsername());
        return ResponseEntity.ok(authenticationService.authenticateUser(loginRequest, response, validationProperties.getIssuerId()));
    }

    /**
     * Logout a user
     *
     * @param jwt the JWT token
     * @param response the HTTP servlet response
     * @return a message response
     */
    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logout(@RequestHeader("Authorization") String jwt, HttpServletResponse response) {
        if (jwt != null && !jwt.isEmpty()) {
            if (jwt.startsWith("Bearer ")) {
                jwt = jwt.substring(7);
            }
            logger.debug("Token received for logout: {}", jwt);

            try {
                MessageResponse messageResponse = authenticationService.logout(jwt, response, "fingerprint");
                return ResponseEntity.ok(messageResponse);
            } catch (IllegalArgumentException e) {
                logger.error("Base64 decoding error in logout method: {}", e.getMessage(), e);
                return ResponseEntity.badRequest().body(new MessageResponse("Error during logout: Invalid token format"));
            } catch (Exception e) {
                logger.error("Error in logout method: {}", e.getMessage(), e);
                return ResponseEntity.badRequest().body(new MessageResponse("Error during logout: " + e.getMessage()));
            }
        } else {
            return ResponseEntity.badRequest().body(new MessageResponse("Error in logout method: Authorization header is missing or empty"));
        }
    }

    /**
     * Activate a user account
     *
     * @param token the activation token
     * @return a redirect URL
     */
    @GetMapping("/activate-account")
    public String activateAccount(@RequestParam("token") String token) {
        try {
            // Redirect to login page after successful activation
            return "redirect:/login";
        } catch (Exception e) {
            logger.error("Error during account activation: {}", e.getMessage(), e);
            // Redirect back to activation page with error
            return "redirect:/activate-account";
        }
    }

    /**
     * Resend activation code
     *
     * @param email the email address
     * @return a response entity with a message
     */
    @PostMapping("/resend-activation")
    public ResponseEntity<MessageResponse> resendActivation(@RequestParam String email) {
        try {
            logger.info("Attempting to resend activation code to: {}", email);
            MessageResponse response = null;
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error resending activation code: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body(new MessageResponse("Error: " + e.getMessage()));
        }
    }
}
