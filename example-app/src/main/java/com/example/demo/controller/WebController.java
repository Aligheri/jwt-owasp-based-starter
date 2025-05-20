package com.example.demo.controller;


import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
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
    public Map<String, Object> user(@AuthenticationPrincipal OAuth2User principal) {
        if (principal == null) {
            return Collections.singletonMap("authenticated", false);
        }
            Map<String, Object> result = new HashMap<>();
            result.put("name", principal.getAttribute("name"));
            return result;
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
