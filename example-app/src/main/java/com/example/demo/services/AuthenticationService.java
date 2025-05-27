package com.example.demo.services;

import com.example.demo.entities.User;
import com.example.demo.entities.UserStatus;
import com.example.demo.repositories.UserRepository;
import com.yevsieiev.authstarter.dto.request.login.DefaultAuthRequest;
import com.yevsieiev.authstarter.dto.request.register.DefaultRegistrationRequest;
import com.yevsieiev.authstarter.dto.response.login.DefaultAuthResponse;
import com.yevsieiev.authstarter.dto.response.register.DefaultRegisterResponse;
import com.yevsieiev.authstarter.email.ActivationService;

import com.yevsieiev.authstarter.utils.CookieUtils;
import com.yevsieiev.authstarter.utils.FingerprintUtils;
import com.yevsieiev.authstarter.utils.JwtTokenProvider;
import com.yevsieiev.authstarter.jwt.TokenCipher;
import com.yevsieiev.authstarter.jwt.TokenRevoker;
import com.yevsieiev.authstarter.service.DefaultAuthenticationService;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


@Service
@Slf4j
public class AuthenticationService extends DefaultAuthenticationService<
        DefaultAuthRequest,
        DefaultAuthResponse,
        DefaultRegistrationRequest,
        DefaultRegisterResponse> {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final ActivationService activationService;

    public AuthenticationService(
            AuthenticationManager authenticationManager,
            JwtTokenProvider jwtTokenProvider,
            TokenCipher tokenCipher,
            TokenRevoker tokenRevoker,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            ActivationService activationService,
            ApplicationEventPublisher eventPublisher,
            CookieUtils cookieUtils,
            FingerprintUtils fingerprintUtils
    ) {
        super(
                authenticationManager,
                tokenCipher,
                tokenRevoker,
                DefaultAuthResponse::new,
                DefaultRegisterResponse::new,
                cookieUtils,
                jwtTokenProvider,
                eventPublisher,
                fingerprintUtils
        );
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.activationService = activationService;
    }

    @Override
    public DefaultRegisterResponse registerUser(DefaultRegistrationRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            return new DefaultRegisterResponse("Error: Username is already taken!");
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            return new DefaultRegisterResponse("Error: Email is already in use!");
        }

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        UserStatus userStatus = UserStatus.builder()
                .user(user)
                .enabled(true)
                .accountLocked(false)
                .build();

        user.setUserStatus(userStatus);
        userRepository.save(user);

        String code = activationService.generateActivationCode(user.getEmail());
        activationService.sendActivationEmail(user.getEmail(), code);

        return new DefaultRegisterResponse("User registered successfully!");
    }

    public void activateAccount(String email, String code) {
        if (!activationService.validateActivationCode(email, code)) {
            throw new RuntimeException("Invalid activation code");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        UserStatus userStatus = user.getUserStatus();
        if (userStatus == null) {
            userStatus = UserStatus.builder().user(user).build();
        }

        userStatus.setAccountLocked(false);
        userStatus.setEnabled(true);
        user.setUserStatus(userStatus);
        userRepository.save(user);
        log.info("Account activated for {}: accountLocked={}, enabled={}",
                email, userStatus.isAccountLocked(), userStatus.isEnabled());
        activationService.invalidateCode(email);
    }
}
