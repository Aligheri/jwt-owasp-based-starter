package com.example.demo.controller;

import com.example.demo.services.AuthenticationService;
import com.yevsieiev.authstarter.dto.response.login.AuthResponse;
import com.yevsieiev.authstarter.dto.request.login.DefaultAuthRequest;
import com.yevsieiev.authstarter.dto.response.register.DefaultRegisterResponse;

import com.yevsieiev.authstarter.dto.request.register.DefaultRegistrationRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/auth")
@PropertySource("classpath:application.yml")
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
     * @param defaultRegistrationRequest the registration request
     * @return a response entity with a message
     */
    @PostMapping("/register")
    public ResponseEntity<DefaultRegisterResponse> registerUser(@Valid @RequestBody DefaultRegistrationRequest defaultRegistrationRequest) {
        logger.info("Attempting to register user: {}", defaultRegistrationRequest.getUsername());
        DefaultRegisterResponse defaultRegisterResponse = authenticationService.registerUser(defaultRegistrationRequest);
        if (defaultRegisterResponse.getMessage().startsWith("Error:")) {
            logger.warn("Registration error: {}", defaultRegisterResponse.getMessage());
            return ResponseEntity.badRequest().body(defaultRegisterResponse);
        } else {
            logger.info("User registered successfully: {}", defaultRegistrationRequest.getUsername());
            return ResponseEntity.ok(defaultRegisterResponse);
        }
    }

    /**
     * Authenticate a user
     *
     * @param loginRequest the login request
     * @param response     the HTTP servlet response
     * @return a response entity with an authentication response
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> loginUser(@Valid @RequestBody DefaultAuthRequest loginRequest, HttpServletResponse response) {
        logger.info("Attempting to authenticate user: {}", loginRequest.getUsername());
        return ResponseEntity.ok(authenticationService.authenticateUser(loginRequest, response, issuerId));
    }

    /**
     * Logout a user
     *
     * @param jwt      the JWT token
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
    public ResponseEntity<DefaultRegisterResponse> resendActivation(@RequestParam String email) {
        try {
            logger.info("Attempting to resend activation code to: {}", email);
            // This is a simplified implementation
            // In a real application, you would find the user by email, generate a new activation code,
            // send the activation email, etc.
            return ResponseEntity.ok(new DefaultRegisterResponse("Activation code resent successfully!"));
        } catch (Exception e) {
            logger.error("Error resending activation code: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body(new DefaultRegisterResponse("Error: " + e.getMessage()));
        }
    }
}
