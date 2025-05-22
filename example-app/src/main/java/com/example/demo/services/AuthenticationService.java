package com.example.demo.services;

import com.example.demo.email.EmailService;

import com.example.demo.entities.User;
import com.example.demo.entities.UserStatus;
import com.example.demo.repositories.TokenRepository;
import com.example.demo.repositories.UserRepository;
import com.yevsieiev.authstarter.dto.request.login.DefaultAuthRequest;
import com.yevsieiev.authstarter.dto.request.register.DefaultRegistrationRequest;
import com.yevsieiev.authstarter.dto.response.login.DefaultAuthResponse;
import com.yevsieiev.authstarter.dto.response.register.DefaultRegisterResponse;
import com.yevsieiev.authstarter.email.ActivationService;

import com.yevsieiev.authstarter.utils.CookieUtils;
import com.yevsieiev.authstarter.utils.JwtTokenProvider;
import com.yevsieiev.authstarter.jwt.TokenCipher;
import com.yevsieiev.authstarter.jwt.TokenRevoker;
import com.yevsieiev.authstarter.service.DefaultAuthenticationService;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


@Service
public class AuthenticationService extends DefaultAuthenticationService<
        DefaultAuthRequest,
        DefaultAuthResponse,
        DefaultRegistrationRequest,
        DefaultRegisterResponse> {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenRepository tokenRepository;
    private final EmailService emailService;
    private final ActivationService activationService;


    private static final String activationUrl = "http://localhost:8080/activate?token=";

    public AuthenticationService(
            AuthenticationManager authenticationManager,
            JwtTokenProvider jwtTokenProvider,
            TokenCipher tokenCipher,
            TokenRevoker tokenRevoker,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            TokenRepository tokenRepository,
            EmailService emailService,
            ActivationService activationService,
            ApplicationEventPublisher eventPublisher,
            CookieUtils cookieUtils
    ) {
        super(
                authenticationManager,
                tokenCipher,
                tokenRevoker,
                DefaultAuthResponse::new,
                DefaultRegisterResponse::new,
                cookieUtils,
                jwtTokenProvider,
                eventPublisher
        );
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenRepository = tokenRepository;
        this.emailService = emailService;
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

        userRepository.save(user);

        String code = activationService.generateActivationCode(user.getEmail());
        activationService.sendActivationEmail(user.getEmail(), code);

        return new DefaultRegisterResponse("User registered successfully!");
    }

//    @Override
//    public void activateAccount(String token) {
//        Token savedToken = tokenRepository.findByToken(token)
//                .orElseThrow(() -> new RuntimeException("Invalid Token"));
//        if (LocalDateTime.now().isAfter(savedToken.getExpiresAt())) {
//            try {
//                sendValidationEmail(savedToken.getUser());
//            } catch (MessagingException e) {
//                throw new RuntimeException(e);
//            }
//            throw new RuntimeException("Activation token has expired. A new token has been sent to the same email address");
//        }
//        var user = userRepository.findById(savedToken.getUser().getId())
//                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
//
//        UserStatus userStatus = user.getUserStatus();
//        if (userStatus == null) {
//            userStatus = UserStatus.builder()
//                    .accountLocked(false)
//                    .enabled(true)
//                    .user(user)
//                    .build();
//            user.setUserStatus(userStatus);
//        } else {
//            userStatus.setAccountLocked(false);
//            userStatus.setEnabled(true);
//        }
//
//        userRepository.save(user);
//        savedToken.setValidatedAt(LocalDateTime.now());
//        tokenRepository.save(savedToken);
//    }

    public void activateAccount(String email, String code) {
        // Validate using starter service
        if (!activationService.validateActivationCode(email, code)) {
            throw new RuntimeException("Invalid activation code");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        UserStatus userStatus = user.getUserStatus() != null ? user.getUserStatus() :
                UserStatus.builder().user(user).build();

        userStatus.setAccountLocked(false);
        userStatus.setEnabled(true);
        user.setUserStatus(userStatus);
        userRepository.save(user);

        activationService.invalidateCode(email);
    }

//    private void sendValidationEmail(User user) throws MessagingException {
//        var newToken = generateAndSaveActivationToken(user);
//        emailService.sendEmail(
//                user.getEmail(),
//                user.getUsername(),
//                EmailTemplateName.ACTIVATE_ACCOUNT,
//                activationUrl,
//                newToken,
//                "Account activation"
//        );
//    }

//    private String generateAndSaveActivationToken(User user) {
//        String generatedToken = generateActivationCode(6);
//        var token = Token.builder()
//                .token(generatedToken)
//                .createdAt(LocalDateTime.now())
//                .expiresAt(LocalDateTime.now().plusMinutes(15))
//                .user(user)
//                .build();
//        tokenRepository.save(token);
//
//        return generatedToken;
//    }
//
//    private String generateActivationCode(int length) {s
//        String characters = "0123456789";
//        StringBuilder codeBuilder = new StringBuilder();
//        SecureRandom secureRandom = new SecureRandom();
//        for (int i = 0; i < length; i++) {
//            int randomIndex = secureRandom.nextInt(characters.length());
//            codeBuilder.append(characters.charAt(randomIndex));
//
//        }
//        return codeBuilder.toString();
//    }
}
