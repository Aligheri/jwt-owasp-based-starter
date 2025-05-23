package com.yevsieiev.authstarter.config;

import com.yevsieiev.authstarter.email.ActivationService;
import com.yevsieiev.authstarter.email.DefaultActivationService;
import com.yevsieiev.authstarter.email.EmailConfig;
import com.yevsieiev.authstarter.exceptions.EmailException;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;
import org.thymeleaf.templateresolver.ITemplateResolver;


@AutoConfiguration
@EnableConfigurationProperties({EmailConfig.class})
@ConditionalOnClass({EnableWebSecurity.class})
public class ActivationAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public JavaMailSender javaMailSender(EmailConfig emailConfig) {
        return emailConfig.mailSender();
    }

    @Bean
    @ConditionalOnMissingBean
    public SpringTemplateEngine templateEngine() {
        SpringTemplateEngine templateEngine = new SpringTemplateEngine();
        templateEngine.addTemplateResolver(emailTemplateResolver());
        return templateEngine;
    }

    private ITemplateResolver emailTemplateResolver() {
        ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
        resolver.setPrefix("templates/");
        resolver.setSuffix(".html");
        resolver.setTemplateMode(TemplateMode.HTML);
        resolver.setCharacterEncoding("UTF-8");
        return resolver;
    }

    @Bean
    @ConditionalOnBean(JavaMailSender.class)
    @ConditionalOnMissingBean
    public ActivationService activationService(
            EmailConfig emailConfig,
            SpringTemplateEngine templateEngine,
            JavaMailSender mailSender
    ) {
        return new DefaultActivationService(emailConfig, templateEngine, mailSender);
    }

    @Bean
    @ConditionalOnMissingBean
    public EmailException emailException() {
        return new EmailException(String.format("Email Exception: %s", "%s"));
    }
}
