package com.auth.authorizationserver.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "auth.jwk.rotation")
public record JwkRotationProperties(Duration rotationPeriod, Duration publishAhead, Duration retirementGrace) {
}
