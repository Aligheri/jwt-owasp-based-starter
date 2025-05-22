package com.example.demo.email;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring5.SpringTemplateEngine;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@Service
public class EmailService {
    private static final Logger logger = LoggerFactory.getLogger(EmailService.class);

    private final JavaMailSender mailSender;
    private final SpringTemplateEngine templateEngine;

    @Value("${mailing.from-email:noreply@example.com}")
    private String fromEmail;


    @Async
    public void sendEmail(String to, String username, EmailTemplateName emailTemplate, String confirmationUrl, String activationCode, String subject) throws MessagingException {
        logger.info("Preparing to send email to: {} with subject: {}", to, subject);

        String templateName;
        if (emailTemplate == null) {
            templateName = "confirm-email";
        } else {
            templateName = emailTemplate.name().toLowerCase() + ".html";
        }
        logger.debug("Using email template: {}", templateName);

        try {
            MimeMessage mimeMessage = this.mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, StandardCharsets.UTF_8.name());

            Map<String, Object> properties = new HashMap<>();
            properties.put("username", username);
            properties.put("confirmationUrl", confirmationUrl);
            properties.put("activation_code", activationCode);

            Context context = new Context();
            context.setVariables(properties);

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject(subject);

            String template = this.templateEngine.process(templateName, context);
            helper.setText(template, true);

            logger.debug("Email content prepared successfully");

            // Send the email
            this.mailSender.send(mimeMessage);

            logger.info("Email sent successfully to: {}", to);
        } catch (Exception e) {
            logger.error("Failed to send email to: {} - Error: {}", to, e.getMessage(), e);
            throw e;
        }
    }

    public EmailService(final JavaMailSender mailSender, @Qualifier("emailTemplateEngine") final SpringTemplateEngine templateEngine) {
        this.mailSender = mailSender;
        this.templateEngine = templateEngine;
    }
}
