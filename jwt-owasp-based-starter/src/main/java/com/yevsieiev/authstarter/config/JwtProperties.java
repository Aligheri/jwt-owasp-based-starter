package com.yevsieiev.authstarter.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "auth.jwt")
@Data
public class JwtProperties {
    private String issuerId;
    private String secretKey;
    private Duration tokenValidity = Duration.ofHours(24);
    private String fingerprintCookieName = "fingerprint";
    private int fingerprintCookieMaxAge = 86400;

}
