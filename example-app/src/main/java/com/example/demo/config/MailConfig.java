package com.example.demo.config;

import com.icegreen.greenmail.spring.GreenMailBean;
import com.icegreen.greenmail.util.ServerSetup;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import java.util.Properties;

@Configuration
public class MailConfig {

    @Value("${spring.mail.host:smtp.gmail.com}")
    private String mailHost;

    @Value("${spring.mail.port:587}")
    private int mailPort;

    @Value("${spring.mail.username:}")
    private String mailUsername;

    @Value("${spring.mail.password:}")
    private String mailPassword;

    @Value("${spring.mail.properties.mail.smtp.auth:true}")
    private String mailSmtpAuth;

    @Value("${spring.mail.properties.mail.smtp.starttls.enable:true}")
    private String mailSmtpStartTlsEnable;

    @Value("${spring.mail.properties.mail.debug:false}")
    private String mailDebug;

    @Value("${mail.use.greenmail:false}")
    private boolean useGreenMail;

    /**
     * Configures an embedded GreenMail server for testing email functionality
     * without requiring an external mail server or Docker.
     * Only active when mail.use.greenmail=true in application.properties
     */
    @Bean
    @Profile("dev")
    public GreenMailBean greenMail() {
        GreenMailBean greenMail = new GreenMailBean();
        greenMail.setPortOffset(3000); // Use ports starting from 3000 (SMTP: 3025)
        greenMail.setAutostart(true);  // Start automatically
        return greenMail;
    }

    /**
     * Configures JavaMailSender to use either a real SMTP server or the embedded GreenMail server.
     * This bean will be used by the EmailService for sending emails.
     */
    @Bean
    @Primary
    public JavaMailSender javaMailSender() {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();

        if (useGreenMail) {
            // Use GreenMail for development/testing
            mailSender.setHost("localhost");
            mailSender.setPort(3025); // GreenMail SMTP port (3000 + 25)
            mailSender.setUsername("test@example.com");
            mailSender.setPassword("password");
        } else {
            // Use real SMTP server
            mailSender.setHost(mailHost);
            mailSender.setPort(mailPort);
            mailSender.setUsername(mailUsername);
            mailSender.setPassword(mailPassword);
        }

        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", mailSmtpAuth);
        props.put("mail.smtp.starttls.enable", mailSmtpStartTlsEnable);
        props.put("mail.debug", mailDebug);

        return mailSender;
    }
}
