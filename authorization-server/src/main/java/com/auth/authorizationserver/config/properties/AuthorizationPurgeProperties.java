package com.auth.authorizationserver.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "auth.authorization.purge")
public record AuthorizationPurgeProperties(Duration retention, int batchSize) {
}
