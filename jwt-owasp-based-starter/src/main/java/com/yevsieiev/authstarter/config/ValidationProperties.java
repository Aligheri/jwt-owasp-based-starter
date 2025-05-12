package com.yevsieiev.authstarter.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration properties for validation constraints.
 * These properties can be overridden in application.properties or application.yml.
 */
@Data
@ConfigurationProperties(prefix = "auth.validation")
public class ValidationProperties {

    private String secretKey;
    private String issuerId;
}