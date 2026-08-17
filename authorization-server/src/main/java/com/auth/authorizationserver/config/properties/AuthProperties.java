package com.auth.authorizationserver.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "auth")
public record AuthProperties(Token token, Session session, Registration registration, PasswordReset passwordReset,
                             Mail mail) {

    public record Token(String audience) {
    }

    /**
     * @param maxLifetime how long a login session may live from creation, however active it stays.
     *                    {@code spring.session.timeout} only bounds idle time.
     */
    public record Session(Duration maxLifetime) {
    }

    public record Registration(Duration tokenTtl) {
    }

    public record PasswordReset(Duration tokenTtl) {
    }

    public record Mail(String from) {
    }
}
