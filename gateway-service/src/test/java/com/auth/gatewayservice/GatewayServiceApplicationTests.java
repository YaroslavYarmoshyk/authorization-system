package com.auth.gatewayservice;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

/**
 * The environment variables the application expects are supplied here, and the registration is pointed
 * at a provider declared with explicit endpoints instead of the real one. That matters: an
 * {@code issuer-uri} makes Boot fetch the discovery document while the context is being built, which
 * would make this test depend on a running authorization server.
 *
 * <p>Skipping discovery means skipping the defaults it supplies, hence the explicit redirect-uri —
 * it is the same template {@code ClientRegistrations} would have applied.
 */
@SpringBootTest
@TestPropertySource(properties = {
        "AUTHORIZATION_ISSUER=http://localhost:9000",
        "GATEWAY_CLIENT_SECRET=test-client-secret",
        "REDIS_HOST=localhost",
        "REDIS_PORT=6379",
        "ORDERS_SERVICE_URL=http://localhost:9001",
        "spring.security.oauth2.client.registration.my-auth.provider=no-discovery",
        "spring.security.oauth2.client.registration.my-auth.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
        "spring.security.oauth2.client.provider.no-discovery.authorization-uri=http://localhost:9000/oauth2/authorize",
        "spring.security.oauth2.client.provider.no-discovery.token-uri=http://localhost:9000/oauth2/token",
        "spring.security.oauth2.client.provider.no-discovery.jwk-set-uri=http://localhost:9000/oauth2/jwks",
        "spring.security.oauth2.client.provider.no-discovery.user-info-uri=http://localhost:9000/userinfo",
        "spring.security.oauth2.client.provider.no-discovery.user-name-attribute=sub"
})
class GatewayServiceApplicationTests {

    @Test
    void contextLoads() {
    }

}
