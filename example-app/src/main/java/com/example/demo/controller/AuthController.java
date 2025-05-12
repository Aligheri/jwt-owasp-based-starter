package com.example.demo.controller;

import com.example.demo.services.AuthenticationService;
import com.yevsieiev.authstarter.auth.AuthRequest;
import com.yevsieiev.authstarter.auth.AuthResponse;
import com.yevsieiev.authstarter.auth.RegistrationRequest;
import com.yevsieiev.authstarter.dto.MessageResponse;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;

@RestController
@RequestMapping("/api/auth")
@PropertySource("classpath:application.properties")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthenticationService authenticationService;

    @Value(value = "${auth.validation.issuer-id}")
    private transient String issuerId;

    public AuthController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
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
    public ResponseEntity<AuthResponse> loginUser(@Valid @RequestBody AuthRequest loginRequest, HttpServletResponse response) throws NoSuchAlgorithmException {
        logger.info("Attempting to authenticate user: {}", loginRequest.getUsername());
        return ResponseEntity.ok(authenticationService.authenticateUser(loginRequest, response, issuerId));
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
            authenticationService.activateAccount(token);
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
            // This is a simplified implementation
            // In a real application, you would find the user by email, generate a new activation code,
            // send the activation email, etc.
            return ResponseEntity.ok(new MessageResponse("Activation code resent successfully!"));
        } catch (Exception e) {
            logger.error("Error resending activation code: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body(new MessageResponse("Error: " + e.getMessage()));
        }
    }
}
