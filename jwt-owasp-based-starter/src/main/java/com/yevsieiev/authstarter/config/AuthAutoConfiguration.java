package com.yevsieiev.authstarter.config;

import com.auth0.jwt.algorithms.Algorithm;
import com.yevsieiev.authstarter.event.AuthEventHandler;
import com.yevsieiev.authstarter.event.service.LoginMetricsCounter;
import com.yevsieiev.authstarter.exceptions.RegisterException;
import com.yevsieiev.authstarter.utils.*;
import com.yevsieiev.authstarter.jwt.JwtAuthenticationFilter;
import com.yevsieiev.authstarter.jwt.TokenCipher;
import com.yevsieiev.authstarter.jwt.TokenRevoker;
import com.yevsieiev.authstarter.repository.RevokedTokenRepository;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * Auto-configuration for JWT authentication.
 */
@AutoConfiguration
@ConditionalOnClass({EnableWebSecurity.class})
@ConditionalOnProperty(name = "jwt.auth.enabled", havingValue = "true", matchIfMissing = true)
@EnableJpaRepositories(basePackages = "com.yevsieiev.authstarter.repository")
@EntityScan(basePackages = "com.yevsieiev.authstarter.entity")
@EnableConfigurationProperties({JwtProperties.class})
public class AuthAutoConfiguration {


    @Bean
    @ConditionalOnMissingBean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(UserDetailsService.class)
    public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(AuthenticationConfiguration.class)
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthEntryPointJwt authEntryPointJwt() {
        return new AuthEntryPointJwt();
    }

    @Bean
    @ConditionalOnMissingBean
    public TokenCipher tokenCipher() throws GeneralSecurityException, IOException {
        return new TokenCipher();
    }

    @Bean
    @ConditionalOnMissingBean
    public TokenRevoker tokenRevoker(RevokedTokenRepository revokedTokenRepository, TokenCipher tokenCipher) {
        return new TokenRevoker(revokedTokenRepository, tokenCipher);
    }

    @Bean
    public SecureRandom secureRandom() {
        return new SecureRandom();
    }

    @Bean
    @ConditionalOnMissingBean
    public FingerprintUtils fingerprintUtils(SecureRandom secureRandom) {
        return new FingerprintUtils(secureRandom);
    }

    @Bean
    @ConditionalOnMissingBean
    public CookieProvider cookieUtils(JwtProperties jwtProperties) {
        return new CookieProvider(jwtProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public Algorithm jwtAlgorithm(JwtProperties jwtProperties) {
        return Algorithm.HMAC256(jwtProperties.getSecretKey());
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtTokenProvider jwtTokenProvider(
            JwtProperties jwtProperties,
            TokenCipher tokenCipher,
            Algorithm jwtAlgorithm
    ) {
        return new JwtTokenProvider(jwtProperties, tokenCipher, jwtAlgorithm);
    }

    @Bean
    @ConditionalOnMissingBean
    public CookieValidationUtils cookieValidationUtils(JwtProperties jwtProperties, JwtTokenProvider jwtTokenProvider) {
        return new CookieValidationUtils(jwtProperties, jwtTokenProvider);
    }

    @Bean
    @ConditionalOnMissingBean
    public TokenValidationUtils tokenValidationUtils(JwtProperties jwtProperties, TokenCipher tokenCipher, TokenRevoker tokenRevoker,
                                                     com.auth0.jwt.algorithms.Algorithm jwtAlgorithm, CookieProvider cookieProvider) {
        return new TokenValidationUtils(jwtProperties, tokenCipher, tokenRevoker, jwtAlgorithm, cookieProvider);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({UserDetailsService.class, JwtTokenProvider.class})
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider, UserDetailsService userDetailsService, CookieValidationUtils cookieValidationUtils, TokenValidationUtils tokenValidationUtils) {
        return new JwtAuthenticationFilter(jwtTokenProvider, userDetailsService, cookieValidationUtils, tokenValidationUtils);
    }

    @Bean
    @ConditionalOnMissingBean
    public RegisterException registerException() {
        return new RegisterException(String.format("Register Exception: %s", "%s"));
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthEventHandler authEventHandler(LoginMetricsCounter loginMetricsCounter) {
        return new AuthEventHandler(loginMetricsCounter);

    }
}