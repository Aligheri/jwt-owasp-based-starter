package com.yevsieiev.authstarter.email;

import com.yevsieiev.authstarter.exceptions.EmailException;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;


public class DefaultActivationService implements ActivationService {
    private final JavaMailSender mailSender;
    private final EmailConfig emailConfig;
    private final Map<String, String> activationCodes = new ConcurrentHashMap<>();

    public DefaultActivationService(
            @Autowired(required = false) JavaMailSender mailSender,
            EmailConfig emailConfig
    ) {
        this.mailSender = mailSender;
        this.emailConfig = emailConfig;
    }

    @Override
    public String generateActivationCode(String identifier) {
        String code = UUID.randomUUID().toString().substring(0, 6);
        activationCodes.put(identifier, code);
        return code;
    }

    @Override
    public boolean validateActivationCode(String identifier, String code) {
        return code.equals(activationCodes.get(identifier));
    }

    @Override
    public void sendActivationEmail(String email, String code) {
        if (emailConfig.isEnabled() && mailSender != null) {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message);

            try {
                helper.setTo(email);
                helper.setFrom(emailConfig.getFrom());
                helper.setSubject("Account Activation");
                helper.setText("Your activation code: " + code);
                mailSender.send(message);
            } catch (MessagingException e) {
                throw new EmailException("Failed to send activation email");
            }
        }
    }
}
