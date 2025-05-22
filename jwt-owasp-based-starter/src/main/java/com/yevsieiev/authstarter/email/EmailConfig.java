package com.yevsieiev.authstarter.email;

import lombok.Data;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import java.util.Properties;

@Data
@ConfigurationProperties(prefix = "app.email")
@ConditionalOnProperty(name = "app.email.enabled", havingValue = "true")
public class EmailConfig {
    private String activationBaseUrl ="http://localhost:8080/activate";
    private String templateName = "activation-email";
    private boolean enabled;
    private String host;
    private int port;
    private String username;
    private String password;
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

        return sender;
    }
}
