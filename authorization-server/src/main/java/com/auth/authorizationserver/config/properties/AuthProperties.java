package com.auth.authorizationserver.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "auth")
public record AuthProperties(Token token, Registration registration, PasswordReset passwordReset, Mail mail) {

    public record Token(String audience) {
    }

    public record Registration(Duration tokenTtl) {
    }

    public record PasswordReset(Duration tokenTtl) {
    }

    public record Mail(String from) {
    }
}
