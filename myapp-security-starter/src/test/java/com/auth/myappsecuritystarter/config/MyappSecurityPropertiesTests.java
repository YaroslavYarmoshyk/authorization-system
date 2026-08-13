package com.auth.myappsecuritystarter.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.http.HttpMethod;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class MyappSecurityPropertiesTests {

    private static MyappSecurityProperties bind(Map<String, String> properties) {
        return new Binder(new MapConfigurationPropertySource(properties))
                .bindOrCreate("myapp.security", MyappSecurityProperties.class);
    }

    @Test
    void appliesDefaultsWhenNothingIsConfigured() {
        MyappSecurityProperties properties = bind(Map.of());

        assertThat(properties.rolesClaim()).isEqualTo("roles");
        assertThat(properties.audience()).isNull();
        assertThat(properties.permitAll())
                .containsExactly(Map.entry(MyappSecurityProperties.ANY_METHOD, java.util.Set.of("/actuator/health/**")));
    }

    @Test
    void bindsAudienceAndRolesClaim() {
        MyappSecurityProperties properties = bind(Map.of(
                "myapp.security.audience", "my-api",
                "myapp.security.roles-claim", "authorities"));

        assertThat(properties.audience()).isEqualTo("my-api");
        assertThat(properties.rolesClaim()).isEqualTo("authorities");
    }

    @Test
    void bindsPathsGroupedByMethod() {
        MyappSecurityProperties properties = bind(Map.of(
                "myapp.security.permit-all.ANY[0]", "/actuator/health/**",
                "myapp.security.permit-all.GET[0]", "/api/public/**",
                "myapp.security.permit-all.GET[1]", "/api/docs/**"));

        assertThat(properties.permitAll()).hasSize(2);
        assertThat(properties.permitAll().get("ANY")).containsExactly("/actuator/health/**");
        assertThat(properties.permitAll().get("GET")).containsExactlyInAnyOrder("/api/public/**", "/api/docs/**");
    }

    @Test
    void resolvesAnyMethodKeyToNoMethodRestriction() {
        assertThat(MyappSecurityProperties.toHttpMethod("ANY")).isNull();
        assertThat(MyappSecurityProperties.toHttpMethod("any")).isNull();
        assertThat(MyappSecurityProperties.toHttpMethod(null)).isNull();
        assertThat(MyappSecurityProperties.toHttpMethod(" ")).isNull();
    }

    @Test
    void resolvesMethodKeysCaseInsensitively() {
        assertThat(MyappSecurityProperties.toHttpMethod("GET")).isEqualTo(HttpMethod.GET);
        assertThat(MyappSecurityProperties.toHttpMethod("get")).isEqualTo(HttpMethod.GET);
        assertThat(MyappSecurityProperties.toHttpMethod(" post ")).isEqualTo(HttpMethod.POST);
    }

    @Test
    void rejectsUnknownMethodKey() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> MyappSecurityProperties.toHttpMethod("FETCH"));
    }
}
