package com.example.demo.email;

import com.icegreen.greenmail.spring.GreenMailBean;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
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

    @Autowired(required = false)
    private GreenMailBean greenMail;

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

    /**
     * Gets the received messages from the embedded GreenMail server.
     * This is useful for testing and debugging email functionality.
     * 
     * @return An array of received messages, or null if GreenMail is not available
     */
    public MimeMessage[] getReceivedMessages() {
        if (greenMail != null) {
            try {
                MimeMessage[] receivedMessages = greenMail.getReceivedMessages();
                logger.info("Retrieved {} received messages from GreenMail", receivedMessages.length);
                return receivedMessages;
            } catch (Exception e) {
                logger.error("Error retrieving messages from GreenMail", e);
            }
        } else {
            logger.warn("GreenMail is not available, cannot retrieve received messages");
        }
        return null;
    }

    /**
     * Gets the latest activation code sent to a specific email address.
     * This is for testing purposes only and should not be used in production.
     * 
     * @param email The email address to look up
     * @return The activation code if found, or null if not found
     */
    public String getLatestActivationCode(String email) {
        MimeMessage[] messages = getReceivedMessages();
        if (messages == null || messages.length == 0) {
            return null;
        }

        // Look through messages in reverse order (newest first)
        for (int i = messages.length - 1; i >= 0; i--) {
            try {
                // Check if this message was sent to the specified email
                String[] recipients = messages[i].getRecipients(jakarta.mail.Message.RecipientType.TO)
                        .toString().split(",");

                boolean isForEmail = false;
                for (String recipient : recipients) {
                    if (recipient.contains(email)) {
                        isForEmail = true;
                        break;
                    }
                }

                if (isForEmail && messages[i].getSubject().contains("Activation")) {
                    // Extract the content as text
                    String content = "";
                    Object messageContent = messages[i].getContent();
                    if (messageContent instanceof String) {
                        content = (String) messageContent;
                    } else if (messageContent instanceof jakarta.mail.internet.MimeMultipart) {
                        jakarta.mail.internet.MimeMultipart multipart = (jakarta.mail.internet.MimeMultipart) messageContent;
                        for (int j = 0; j < multipart.getCount(); j++) {
                            jakarta.mail.BodyPart bodyPart = multipart.getBodyPart(j);
                            if (bodyPart.getContentType().startsWith("text/html")) {
                                content = (String) bodyPart.getContent();
                                break;
                            }
                        }
                    }

                    // Look for the activation code in the content
                    // The code is displayed in a div with class "activation-code"
                    if (content.contains("activation-code")) {
                        int startIndex = content.indexOf("activation-code") + "activation-code".length();
                        startIndex = content.indexOf(">", startIndex) + 1;
                        int endIndex = content.indexOf("<", startIndex);
                        if (startIndex > 0 && endIndex > startIndex) {
                            String code = content.substring(startIndex, endIndex).trim();
                            logger.info("Found activation code: {} for email: {}", code, email);
                            return code;
                        }
                    }
                }
            } catch (Exception e) {
                logger.error("Error processing message for activation code extraction", e);
            }
        }

        return null;
    }
}
