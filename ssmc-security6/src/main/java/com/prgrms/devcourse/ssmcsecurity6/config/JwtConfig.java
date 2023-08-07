package com.prgrms.devcourse.ssmcsecurity6.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(prefix = "jwt")
@Component
@Data
public class JwtConfig {

    private String header;

    private String issuer;

    private String clientSecret;

    private int expirySeconds;

    private String accessToken;

    private String refreshToken;
}
