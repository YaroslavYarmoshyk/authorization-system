package com.auth.authorizationserver.model;

public record FederatedIdentity(
        String provider,
        String subject,
        String email,
        boolean emailVerified,
        String displayName) {
}
