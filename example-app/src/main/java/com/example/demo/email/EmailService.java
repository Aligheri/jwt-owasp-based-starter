package com.example.demo.email;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@Service
public class EmailService {
    private final JavaMailSender mailSender;
    private final SpringTemplateEngine templateEngine;

    @Async
    public void sendEmail(String to, String username, EmailTemplateName emailTemplate, String confirmationUrl, String activationCode, String subject) throws MessagingException {
        String templateName;
        if (emailTemplate == null) {
            templateName = "confirm-email";
        } else {
            templateName = emailTemplate.name();
        }

        MimeMessage mimeMessage = this.mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, 1, StandardCharsets.UTF_8.name());
        Map<String, Object> properties = new HashMap();
        properties.put("username", username);
        properties.put("confirmationUrl", confirmationUrl);
        properties.put("activation_code", activationCode);
        Context context = new Context();
        context.setVariables(properties);
        helper.setFrom("ivanyevsieiev@gmail.com");
        helper.setTo(to);
        helper.setSubject(subject);
        String template = this.templateEngine.process(templateName, context);
        helper.setText(template, true);
        this.mailSender.send(mimeMessage);
    }

    public EmailService(final JavaMailSender mailSender, final SpringTemplateEngine templateEngine) {
        this.mailSender = mailSender;
        this.templateEngine = templateEngine;
    }
}
