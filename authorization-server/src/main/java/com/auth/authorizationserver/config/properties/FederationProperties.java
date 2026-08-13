package com.auth.authorizationserver.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Map;

@ConfigurationProperties(prefix = "auth.federation")
public record FederationProperties(Map<String, Provider> providers) {

    public record Provider(boolean linkByEmail) {
    }

    public boolean linkByEmailAllowed(String registrationId) {
        Provider provider = providers == null ? null : providers.get(registrationId);
        return provider != null && provider.linkByEmail();
    }
}
