package com.example.demo.controller;


import com.yevsieiev.authstarter.jwt.JwtUtils;
import com.yevsieiev.authstarter.jwt.TokenCipher;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.GeneralSecurityException;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Controller for web pages using Thymeleaf templates.
 * This controller handles the web interface for the authentication process,
 * showing the JWT token and fingerprint cookie after login and their removal during logout.
 */
@Controller
public class WebController {

    private final JwtUtils jwtUtils;
    private final TokenCipher tokenCipher;

    @Value("${auth.validation.issuer-id}")
    private String issuerId;

    @Autowired
    public WebController(JwtUtils jwtUtils, TokenCipher tokenCipher) {
        this.jwtUtils = jwtUtils;
        this.tokenCipher = tokenCipher;
    }

    /**
     * Home page
     */
    @GetMapping("/")
    public String home() {
        return "index";
    }

    /**
     * Registration page
     */
    @GetMapping("/register")
    public String register() {
        return "register";
    }

    /**
     * Account activation page
     */
    @GetMapping("/activate-account")
    public String activateAccount() {
        return "activate-account";
    }

    /**
     * Login page
     */
    @GetMapping("/login")
    public String login() {
        return "login";
    }
    /**
     * OAuth 2
     */
    @GetMapping("/user")
    public Map<String, Object> user(@AuthenticationPrincipal OAuth2User principal, HttpServletResponse response) {
        if (principal == null) {
            return Collections.singletonMap("authenticated", false);
        }

        try {
            // Generate user fingerprint and store it in a cookie
            String userFingerprint = jwtUtils.createUserFingerprint();
            jwtUtils.createCookie(response, "fingerprint", userFingerprint, 24 * 60 * 60, true);

            // Hash the fingerprint
            String userFingerprintHash = jwtUtils.hashFingerprint(userFingerprint);

            // Generate JWT token
            String username = principal.getAttribute("login");
            if (username == null) {
                username = principal.getAttribute("name");
            }

            String jwt = jwtUtils.generateAccessTokenFromUsername(username, issuerId, userFingerprintHash);

            // Cipher the JWT token
            String cipheredJwt = tokenCipher.cipherToken(jwt);

            // Return the token and user details
            Map<String, Object> result = new HashMap<>();
            result.put("name", principal.getAttribute("name"));
            result.put("token", cipheredJwt);

            return result;
        } catch (GeneralSecurityException e) {
            return Collections.singletonMap("error", "Authentication failed: " + e.getMessage());
        }
    }
    /**
     * Dashboard page - displays the JWT token and fingerprint cookie
     */
    @GetMapping("/dashboard")
    public String dashboard() {
        return "dashboard";
    }

    /**
     * Logout confirmation page
     */
    @GetMapping("/logout")
    public String logout() {
        return "logout";
    }
}
