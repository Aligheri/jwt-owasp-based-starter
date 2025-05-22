package com.example.demo.controller;

import com.example.demo.services.AuthenticationService;
import com.yevsieiev.authstarter.dto.response.login.AuthResponse;
import com.yevsieiev.authstarter.dto.request.login.DefaultAuthRequest;
import com.yevsieiev.authstarter.dto.response.register.DefaultRegisterResponse;

import com.yevsieiev.authstarter.dto.request.register.DefaultRegistrationRequest;
import com.yevsieiev.authstarter.exceptions.EmailException;
import com.yevsieiev.authstarter.exceptions.RegisterException;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;


@RestController
@RequestMapping("/api/auth")
@PropertySource("classpath:application.properties")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthenticationService authenticationService;

    @Value(value = "${auth.jwt.issuer-id}")
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
        try{
            DefaultRegisterResponse defaultRegisterResponse = authenticationService.registerUser(defaultRegistrationRequest);
            logger.info("User registered successfully: {}", defaultRegistrationRequest.getUsername());
            return ResponseEntity.ok(defaultRegisterResponse);
        }catch (RegisterException e){
            return ResponseEntity.badRequest().body(new DefaultRegisterResponse(e.getMessage()));
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


    @GetMapping("/activate-account")
    public String activateAccount(
            @RequestParam String email,
            @RequestParam String code,
            RedirectAttributes redirectAttributes
    ) {
        try {
            authenticationService.activateAccount(email, code);
            redirectAttributes.addFlashAttribute("message", "Account activated successfully!");
            return "redirect:/login";
        } catch (EmailException e) {
            redirectAttributes.addFlashAttribute("error", e.getMessage());
            return "redirect:/activation-error.html";
        } catch (UsernameNotFoundException e) {
            redirectAttributes.addFlashAttribute("error", "User not found");
            return "redirect:/registration";
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
            return ResponseEntity.ok(new DefaultRegisterResponse("Activation code resent successfully!"));
        } catch (Exception e) {
            logger.error("Error resending activation code: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body(new DefaultRegisterResponse("Error: " + e.getMessage()));
        }
    }
}
