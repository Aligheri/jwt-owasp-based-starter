package com.yevsieiev.authstarter.service;

import com.yevsieiev.authstarter.auth.*;
import com.yevsieiev.authstarter.dto.MessageResponse;
import com.yevsieiev.authstarter.jwt.JwtUtils;
import com.yevsieiev.authstarter.jwt.TokenCipher;
import com.yevsieiev.authstarter.jwt.TokenRevoker;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Default implementation of the AuthenticationService interfaceF
 */

@RequiredArgsConstructor
public abstract class DefaultAuthenticationService implements AuthenticationService {

    private static final Logger logger = LoggerFactory.getLogger(DefaultAuthenticationService.class);

    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final TokenCipher tokenCipher;
    private final TokenRevoker tokenRevoker;

    @Override
    public abstract MessageResponse registerUser(RegistrationRequest registrationRequest);

    public DefaultAuthResponse authenticateUser(DefaultLoginRequest loginRequest, HttpServletResponse response, String issuerId) {
        try {
            // Authenticate the user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

            // Set the authentication in the security context
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Generate a fingerprint for the user
            String userFingerprint = jwtUtils.createUserFingerprint();
            logger.debug("Generated userFingerprint: {}", userFingerprint);

            // Create a cookie with the fingerprint
            jwtUtils.createCookie(response, "fingerprint", userFingerprint, 24 * 60 * 60, true);

            // Hash the fingerprint for use in the JWT
            String userFingerprintHash = jwtUtils.hashFingerprint(userFingerprint);
            logger.debug("Generated userFingerprintHash: {}", userFingerprintHash);

            // Generate a JWT for the user
            String jwt = jwtUtils.generateAccessTokenFromUsername(loginRequest.getUsername(), issuerId, userFingerprintHash);

            // Cipher the JWT for security
            String cipheredJwt = tokenCipher.cipherToken(jwt);

            System.out.println(cipheredJwt);

            // Create and return the authentication response
            return DefaultAuthResponse.builder()
                    .accessToken(cipheredJwt)
                    .tokenType("Bearer")
                    .expiresIn(3600) // 1 hour
                    .build();
        } catch (Exception e) {
            logger.error("Error during authentication", e);
            throw new RuntimeException("Error during authentication: " + e.getMessage());
        }
    }

    @Override
    public MessageResponse logout(String jwtToken, HttpServletResponse response, String cookieName) {
        try {
            // Delete the cookie
            jwtUtils.deleteCookie(response, cookieName);
            // Revoke the token
            tokenRevoker.revokeToken(jwtToken);
            return new MessageResponse("Logged out successfully!");
        } catch (Exception e) {
            logger.error("Error during logout", e);
            return new MessageResponse("Error during logout: " + e.getMessage());
        }
    }


    public void activateAccount(String token) {
        // This is a simplified implementation
        // In a real application, you would validate the token, find the user,
        // update their status, etc.
        logger.info("Activating account with token: {}", token);
    }
}