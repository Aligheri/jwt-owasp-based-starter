package com.yevsieiev.authstarter.email;

import com.yevsieiev.authstarter.exceptions.EmailException;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class DefaultActivationService implements ActivationService {
    private final EmailConfig emailConfig;
    private final SpringTemplateEngine templateEngine;
    private final Map<String, ActivationData> activationStore = new ConcurrentHashMap<>();

    private final JavaMailSender mailSender;

    public DefaultActivationService(
            EmailConfig emailConfig,
            SpringTemplateEngine templateEngine,
            JavaMailSender mailSender
    ) {
        this.emailConfig = emailConfig;
        this.templateEngine = templateEngine;
        this.mailSender = mailSender;
    }


    private static class ActivationData {
        final String code;
        final Instant expiry;

        ActivationData(String code, Instant expiry) {
            this.code = code;
            this.expiry = expiry;
        }
    }

    @Override
    public String generateActivationCode(String identifier) {
        String code = UUID.randomUUID().toString().substring(0, 6);
        activationStore.put(identifier, new ActivationData(
                code,
                Instant.now().plus(24, ChronoUnit.HOURS)
        ));
        return code;
    }

    @Override
    public boolean validateActivationCode(String identifier, String code) {
        ActivationData data = activationStore.get(identifier);
        return data != null
                && data.code.equals(code)
                && data.expiry.isAfter(Instant.now());
    }


    @Override
    public void sendActivationEmail(String email, String code) {
        if (!emailConfig.isEnabled()) {
            log.warn("Email sending is disabled");
            return;
        }

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setTo(email);
            helper.setFrom(emailConfig.getFrom());
            helper.setSubject("Account Activation");

            Context context = new Context();
            context.setVariable("code", code);
            context.setVariable("activationUrl",
                    emailConfig.getActivationBaseUrl() + URLEncoder.encode(code, StandardCharsets.UTF_8));

            String htmlContent = templateEngine.process(
                    emailConfig.getTemplateName(),
                    context
            );

            helper.setText(htmlContent, true);
            mailSender.send(message);
            log.info("Activation email sent to {}", email);

        } catch (MessagingException e) {
            throw new EmailException("Failed to send activation email" + e.getMessage());
        }
    }

    @Override
    public void invalidateCode(String identifier) {
        activationStore.remove(identifier);
    }
}
