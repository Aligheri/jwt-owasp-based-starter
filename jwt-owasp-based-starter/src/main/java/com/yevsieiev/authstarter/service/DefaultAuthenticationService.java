package com.yevsieiev.authstarter.service;

import com.yevsieiev.authstarter.dto.request.login.AuthRequest;
import com.yevsieiev.authstarter.dto.request.register.RegisterRequest;
import com.yevsieiev.authstarter.dto.response.login.AuthResponse;
import com.yevsieiev.authstarter.dto.response.register.RegisterResponse;
import com.yevsieiev.authstarter.event.AuthSuccessEvent;
import com.yevsieiev.authstarter.exceptions.*;
import com.yevsieiev.authstarter.utils.CookieProvider;
import com.yevsieiev.authstarter.utils.FingerprintUtils;
import com.yevsieiev.authstarter.utils.JwtTokenProvider;
import com.yevsieiev.authstarter.jwt.TokenCipher;
import com.yevsieiev.authstarter.jwt.TokenRevoker;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.function.Supplier;

/**
 * Default implementation of the AuthenticationService interface
 */

@RequiredArgsConstructor
public abstract class DefaultAuthenticationService<
        T extends AuthRequest,
        R extends AuthResponse,
        U extends RegisterRequest,
        V extends RegisterResponse>
        implements AuthenticationService<T, R, U, V> {

    private static final Logger logger = LoggerFactory.getLogger(DefaultAuthenticationService.class);

    private final AuthenticationManager authenticationManager;
    private final TokenCipher tokenCipher;
    private final TokenRevoker tokenRevoker;
    private final Supplier<R> authResponseSupplier;
    private final Supplier<V> registerResponseSupplier;
    private final CookieProvider cookieProvider;
    private final JwtTokenProvider jwtTokenProvider;
    private final ApplicationEventPublisher eventPublisher;
    private final FingerprintUtils fingerprintUtils;

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

            String fingerprint = fingerprintUtils.generateFingerprint();
            logger.debug("Generated fingerprint: {}", fingerprint);
            cookieProvider.setFingerprintCookie(response, fingerprint);

            String fingerprintHash = FingerprintUtils.hashFingerprint(fingerprint);
            logger.debug("Generated fingerprint hash: {}", fingerprintHash);

            String jwt = jwtTokenProvider.generateToken(loginRequest.getIdentifier(), fingerprintHash);

            String cipheredJwt = tokenCipher.cipherToken(jwt);
            logger.debug("Generated ciphered token: {}", cipheredJwt);

            R authResponse = authResponseSupplier.get();
            authResponse.setToken(cipheredJwt);

            eventPublisher.publishEvent(
                    new AuthSuccessEvent(this, loginRequest.getIdentifier())
            );

            return authResponse;

        } catch (AuthenticationException e) {
            logger.warn("Auth failure for {}", loginRequest.getIdentifier());
            throw new AuthenticationFailureException("Invalid credentials", e);
        } catch (TokenEncyptionException e) {
            logger.error("Token security breach", e);
            throw new ServiceSecurityException("Token processing failure", e);
        } catch (Exception e) {
            logger.error("System authentication failure", e);
            throw new AuthServiceException("Global auth failure", e);
        }
    }


    @Override
    public V registerUser(U registrationRequest) {
        throw new UnsupportedOperationException("registerUser must be overridden in subclass");
    }


    @Override
    public V logout(String jwtToken, HttpServletResponse response, String cookieName) {
        try {
            cookieProvider.deleteCookie(response, cookieName);
            tokenRevoker.revokeToken(jwtToken);

            V registerResponse = registerResponseSupplier.get();
            registerResponse.setMessage("Logged out successfully!");
            return registerResponse;

        } catch (TokenRevocationException e) {
            logger.error("Error during logout", e);
            V registerResponse = registerResponseSupplier.get();
            registerResponse.setMessage("Error during logout: " + e.getMessage());
            return registerResponse;
        }
        catch (Exception e) {
            logger.error("System logout failure", e);
            V registerResponse = registerResponseSupplier.get();
            registerResponse.setMessage("System logout failure: " + e.getMessage());
            return registerResponse;
        }
    }
}