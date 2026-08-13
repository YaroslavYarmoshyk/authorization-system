package com.auth.myappsecuritystarter;

import com.auth.myappsecuritystarter.config.MyappSecurityProperties;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class MyappAudienceValidatorTests {

    private final OAuth2TokenValidator<Jwt> validator =
            new MyappResourceServerAutoConfiguration()
                    .myappAudienceValidator(new MyappSecurityProperties(null, "my-api", null));

    private static Jwt jwtWithAudience(List<String> audience) {
        Jwt.Builder builder = Jwt.withTokenValue("token").header("alg", "none").subject("alice");
        if (audience != null) {
            builder.audience(audience);
        }
        return builder.build();
    }

    @Test
    void acceptsTokenWithExpectedAudience() {
        assertThat(validator.validate(jwtWithAudience(List.of("my-api"))).hasErrors()).isFalse();
    }

    @Test
    void acceptsTokenListingExpectedAudienceAmongOthers() {
        assertThat(validator.validate(jwtWithAudience(List.of("other-api", "my-api"))).hasErrors()).isFalse();
    }

    @Test
    void rejectsTokenWithDifferentAudience() {
        assertThat(validator.validate(jwtWithAudience(List.of("other-api"))).hasErrors()).isTrue();
    }

    @Test
    void rejectsTokenWithoutAudience() {
        assertThat(validator.validate(jwtWithAudience(null)).hasErrors()).isTrue();
    }
}
