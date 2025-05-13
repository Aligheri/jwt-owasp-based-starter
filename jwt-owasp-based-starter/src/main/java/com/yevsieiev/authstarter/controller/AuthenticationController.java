package com.yevsieiev.authstarter.controller;

import com.yevsieiev.authstarter.dto.response.login.AuthResponse;
import com.yevsieiev.authstarter.dto.request.login.DefaultAuthRequest;
import com.yevsieiev.authstarter.dto.request.register.DefaultRegistrationRequest;
import com.yevsieiev.authstarter.config.ValidationProperties;
import com.yevsieiev.authstarter.dto.response.register.DefaultRegisterResponse;
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
    public ResponseEntity<DefaultRegisterResponse> registerUser(@Valid @RequestBody DefaultRegistrationRequest registrationRequest) {
        logger.info("Attempting to register user: {}", registrationRequest.getUsername());
        DefaultRegisterResponse defaultRegisterResponse = authenticationService.registerUser(registrationRequest);
        if (defaultRegisterResponse.getMessage().startsWith("Error:")) {
            logger.warn("Registration error: {}", defaultRegisterResponse.getMessage());
            return ResponseEntity.badRequest().body(defaultRegisterResponse);
        } else {
            logger.info("User registered successfully: {}", registrationRequest.getUsername());
            return ResponseEntity.ok(defaultRegisterResponse);
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
    public ResponseEntity<AuthResponse> loginUser(@Valid @RequestBody DefaultAuthRequest loginRequest, HttpServletResponse response) {
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
    public ResponseEntity<DefaultRegisterResponse> logout(@RequestHeader("Authorization") String jwt, HttpServletResponse response) {
        if (jwt != null && !jwt.isEmpty()) {
            if (jwt.startsWith("Bearer ")) {
                jwt = jwt.substring(7);
            }
            logger.debug("Token received for logout: {}", jwt);

            try {
                DefaultRegisterResponse defaultRegisterResponse = authenticationService.logout(jwt, response, "fingerprint");
                return ResponseEntity.ok(defaultRegisterResponse);
            } catch (IllegalArgumentException e) {
                logger.error("Base64 decoding error in logout method: {}", e.getMessage(), e);
                return ResponseEntity.badRequest().body(new DefaultRegisterResponse("Error during logout: Invalid token format"));
            } catch (Exception e) {
                logger.error("Error in logout method: {}", e.getMessage(), e);
                return ResponseEntity.badRequest().body(new DefaultRegisterResponse("Error during logout: " + e.getMessage()));
            }
        } else {
            return ResponseEntity.badRequest().body(new DefaultRegisterResponse("Error in logout method: Authorization header is missing or empty"));
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
    public ResponseEntity<DefaultRegisterResponse> resendActivation(@RequestParam String email) {
        try {
            logger.info("Attempting to resend activation code to: {}", email);
            DefaultRegisterResponse response = null;
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error resending activation code: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body(new DefaultRegisterResponse("Error: " + e.getMessage()));
        }
    }
}
