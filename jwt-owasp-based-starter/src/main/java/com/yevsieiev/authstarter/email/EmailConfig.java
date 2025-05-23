package com.yevsieiev.authstarter.email;

import jakarta.mail.MessagingException;
import lombok.Data;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import java.util.Properties;

@Data
@ConfigurationProperties(prefix = "app.email")
@Slf4j
public class EmailConfig {
    private String activationBaseUrl ;
    private String templateName = "activation-email";
    private boolean enabled;
    private String host;
    private int port;
    private String password;
    private String username;
    private String from;

    public JavaMailSender mailSender() {
        JavaMailSenderImpl sender = new JavaMailSenderImpl();

        sender.setHost(host);
        sender.setPort(port);
        sender.setUsername(username);
        sender.setPassword(password);

        Properties props = sender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.debug", "true");
        props.put("mail.smtp.ssl.protocols", "TLSv1.2");
        props.put("mail.smtp.ssl.trust", "smtp.gmail.com");


        return sender;
    }
}
