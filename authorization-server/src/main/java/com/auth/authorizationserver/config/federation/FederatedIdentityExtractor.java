package com.auth.authorizationserver.config.federation;

import com.auth.authorizationserver.model.FederatedIdentity;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

@Component
public class FederatedIdentityExtractor {

    public FederatedIdentity extract(String registrationId, OAuth2User principal) {
        if (principal instanceof OidcUser oidcUser) {
            return new FederatedIdentity(
                    registrationId,
                    oidcUser.getSubject(),
                    normalize(oidcUser.getEmail()),
                    Boolean.TRUE.equals(oidcUser.getEmailVerified()),
                    oidcUser.getFullName());
        }
        throw new IllegalStateException("Non-OIDC provider '" + registrationId + "' requires a custom attribute mapping");
    }

    private static String normalize(String email) {
        return email == null ? null : email.trim().toLowerCase();
    }
}
