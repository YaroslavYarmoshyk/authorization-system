package com.auth.authorizationserver.config;

import com.auth.authorizationserver.config.jwk.DatabaseJwkSource;
import com.auth.authorizationserver.config.properties.AuthProperties;
import com.auth.authorizationserver.model.entity.User;
import com.auth.authorizationserver.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Configuration
public class TokenConfig {

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(UserRepository users, DatabaseJwkSource jwkSource, AuthProperties authProperties) {
        String apiAudience = authProperties.token().audience();

        return context -> {
            boolean isAccessToken = OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType());
            boolean isIdToken = OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue());
            if (!isAccessToken && !isIdToken) {
                return;
            }
            context.getJwsHeader().keyId(jwkSource.currentSigningKid());

            if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {
                if (isAccessToken) {
                    context.getClaims()
                            .audience(Collections.singletonList(apiAudience))
                            .claim("roles", Collections.singletonList("SERVICE"));
                }
                return;
            }

            User user = resolveUser(users, context.getPrincipal())
                    .orElseThrow(() -> new IllegalStateException("Principal has no user record"));

            if (isAccessToken) {
                context.getClaims().audience(Collections.singletonList(apiAudience));
            }

            List<String> roles = user.getRoles().stream()
                    .map(Enum::name)
                    .collect(Collectors.toCollection(ArrayList::new));

            context.getClaims()
                    .claim("email", user.getEmail())
                    .claim("roles", roles);
        };
    }

    private Optional<User> resolveUser(UserRepository users, Authentication principal) {
        if (principal instanceof OAuth2AuthenticationToken federated) {
            return users.findByIdentity(
                    federated.getAuthorizedClientRegistrationId(),
                    federated.getName());
        }
        return users.findByEmail(principal.getName().toLowerCase());
    }
}
