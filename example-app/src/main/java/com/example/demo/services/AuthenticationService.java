package com.example.demo.services;

import com.example.demo.email.EmailService;
import com.example.demo.email.EmailTemplateName;
import com.example.demo.entities.Token;
import com.example.demo.entities.User;
import com.example.demo.entities.UserStatus;
import com.example.demo.repositories.TokenRepository;
import com.example.demo.repositories.UserRepository;
import com.yevsieiev.authstarter.auth.RegistrationRequest;
import com.yevsieiev.authstarter.dto.MessageResponse;
import com.yevsieiev.authstarter.jwt.JwtUtils;
import com.yevsieiev.authstarter.jwt.TokenCipher;
import com.yevsieiev.authstarter.jwt.TokenRevoker;
import com.yevsieiev.authstarter.service.DefaultAuthenticationService;
import jakarta.mail.MessagingException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;

@Service
public class AuthenticationService extends DefaultAuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenRepository tokenRepository;
    private final EmailService emailService;

    private static final String activationUrl = "http://localhost:8080/activate?token=";

    public AuthenticationService(AuthenticationManager authenticationManager, JwtUtils jwtUtils, TokenCipher tokenCipher, TokenRevoker tokenRevoker, UserRepository userRepository, PasswordEncoder passwordEncoder, TokenRepository tokenRepository, EmailService emailService) {
        super(authenticationManager, jwtUtils, tokenCipher, tokenRevoker);
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenRepository = tokenRepository;
        this.emailService = emailService;
    }

    @Override
    public MessageResponse registerUser(RegistrationRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            return new MessageResponse("Error: Username is already taken!");
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            return new MessageResponse("Error: Email is already in use!");
        }

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        // если не нужна email-активация
        userRepository.save(user);
        try {
            sendValidationEmail(user);
        } catch (MessagingException e) {
            throw new RuntimeException(e);
        }
        return new MessageResponse("User registered successfully!");
    }

    @Override
    public void activateAccount(String token) {
        Token savedToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid Token"));
        if (LocalDateTime.now().isAfter(savedToken.getExpiresAt())) {
            try {
                sendValidationEmail(savedToken.getUser());
            } catch (MessagingException e) {
                throw new RuntimeException(e);
            }
            throw new RuntimeException("Activation token has expired. A new token has been sent to the same email address");
        }
        var user = userRepository.findById(savedToken.getUser().getId())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        UserStatus userStatus = user.getUserStatus();
        if (userStatus == null) {
            userStatus = UserStatus.builder()
                    .accountLocked(false)
                    .enabled(true)
                    .user(user)
                    .build();
            user.setUserStatus(userStatus);
        } else {
            userStatus.setAccountLocked(false);
            userStatus.setEnabled(true);
        }

        userRepository.save(user);
        savedToken.setValidatedAt(LocalDateTime.now());
        tokenRepository.save(savedToken);
    }

    private void sendValidationEmail(User user) throws MessagingException {
        var newToken = generateAndSaveActivationToken(user);
        emailService.sendEmail(
                user.getEmail(),
                user.getUsername(),
                EmailTemplateName.ACTIVATE_ACCOUNT,
                activationUrl,
                newToken,
                "Account activation"
        );
    }

    private String generateAndSaveActivationToken(User user) {
        String generatedToken = generateActivationCode(6);
        var token = Token.builder()
                .token(generatedToken)
                .createdAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusMinutes(15))
                .user(user)
                .build();
        tokenRepository.save(token);

        return generatedToken;
    }

    private String generateActivationCode(int length) {
        String characters = "0123456789";
        StringBuilder codeBuilder = new StringBuilder();
        SecureRandom secureRandom = new SecureRandom();
        for (int i = 0; i < length; i++) {
            int randomIndex = secureRandom.nextInt(characters.length());
            codeBuilder.append(characters.charAt(randomIndex));

        }
        return codeBuilder.toString();
    }
}
