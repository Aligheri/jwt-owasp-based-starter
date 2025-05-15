package com.yevsieiev.authstarter.service;

import com.yevsieiev.authstarter.dto.request.login.AuthRequest;
import com.yevsieiev.authstarter.dto.request.register.RegisterRequest;
import com.yevsieiev.authstarter.dto.response.login.AuthResponse;
import com.yevsieiev.authstarter.dto.response.register.RegisterResponse;
import com.yevsieiev.authstarter.utils.JwtUtils;
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

import java.util.function.Supplier;

/**
 * Default implementation of the AuthenticationService interface
 */

@RequiredArgsConstructor
public abstract class DefaultAuthenticationService <
        T extends AuthRequest,
        R extends AuthResponse,
        U extends RegisterRequest,
        V extends RegisterResponse>
        implements AuthenticationService<T, R, U, V> {

    private static final Logger logger = LoggerFactory.getLogger(DefaultAuthenticationService.class);

    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final TokenCipher tokenCipher;
    private final TokenRevoker tokenRevoker;
    private final Supplier<R> authResponseSupplier;
    private final Supplier<V> registerResponseSupplier;

    @Override
    public R authenticateUser(T loginRequest, HttpServletResponse response, String issuerId) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getIdentifier(),
                            loginRequest.getPassword()
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            String userFingerprint = jwtUtils.createUserFingerprint();
            logger.debug("Generated userFingerprint: {}", userFingerprint);

            jwtUtils.createCookie(response, "fingerprint", userFingerprint, 24 * 60 * 60, true);

            String userFingerprintHash = jwtUtils.hashFingerprint(userFingerprint);
            logger.debug("Generated userFingerprintHash: {}", userFingerprintHash);

            String jwt = jwtUtils.generateAccessTokenFromUsername(
                    loginRequest.getIdentifier(), issuerId, userFingerprintHash
            );

            String cipheredJwt = tokenCipher.cipherToken(jwt);
            logger.debug("Generated ciphered token: {}", cipheredJwt);

            R authResponse = authResponseSupplier.get();
            authResponse.setToken(cipheredJwt);
            return authResponse;

        } catch (Exception e) {
            logger.error("Error during authentication", e);
            throw new RuntimeException("Error during authentication: " + e.getMessage());
        }
    }


    @Override
    public V registerUser(U registrationRequest) {
        throw new UnsupportedOperationException("registerUser must be overridden in subclass");
    }


    @Override
    public V logout(String jwtToken, HttpServletResponse response, String cookieName) {
        try {
            jwtUtils.deleteCookie(response, cookieName);
            tokenRevoker.revokeToken(jwtToken);

            V registerResponse = registerResponseSupplier.get();
            registerResponse.setMessage("Logged out successfully!");
            return registerResponse;

        } catch (Exception e) {
            logger.error("Error during logout", e);
            V registerResponse = registerResponseSupplier.get();
            registerResponse.setMessage("Error during logout: " + e.getMessage());
            return registerResponse;
        }
    }


    public void activateAccount(String token) {
        logger.info("Activating account with token: {}", token);
    }
}