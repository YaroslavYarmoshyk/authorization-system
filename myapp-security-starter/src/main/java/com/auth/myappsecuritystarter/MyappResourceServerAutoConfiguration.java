package com.auth.myappsecuritystarter;

import com.auth.myappsecuritystarter.config.BearerTokenPropagationInterceptor;
import com.auth.myappsecuritystarter.config.MyappSecurityProperties;
import com.auth.myappsecuritystarter.config.MyappTokenAuthenticationConverter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

@AutoConfiguration
@ConditionalOnClass({SecurityFilterChain.class, JwtDecoder.class})
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableConfigurationProperties(MyappSecurityProperties.class)
public class MyappResourceServerAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    MyappTokenAuthenticationConverter myappTokenAuthenticationConverter(MyappSecurityProperties properties) {
        return new MyappTokenAuthenticationConverter(properties.rolesClaim());
    }

    /**
     * Contributed as a plain validator rather than a {@link JwtDecoder} so that Spring Boot's own decoder
     * auto-configuration picks it up through its {@code additionalValidators} injection point. Declaring a
     * decoder here instead would race with that auto-configuration and could silently drop the audience check.
     */
    @Bean
    @ConditionalOnMissingBean(name = "myappAudienceValidator")
    @ConditionalOnProperty(prefix = "myapp.security", name = "audience")
    OAuth2TokenValidator<Jwt> myappAudienceValidator(MyappSecurityProperties properties) {
        String audience = properties.audience();
        return new JwtClaimValidator<List<String>>(JwtClaimNames.AUD,
                aud -> aud.contains(audience));
    }

    @Bean
    @ConditionalOnMissingBean
    BearerTokenPropagationInterceptor bearerTokenPropagationInterceptor() {
        return new BearerTokenPropagationInterceptor();
    }

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    SecurityFilterChain myappResourceServerFilterChain(HttpSecurity http,
                                                       MyappSecurityProperties properties,
                                                       MyappTokenAuthenticationConverter converter) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> {
                    properties.permitAll().forEach((method, paths) -> {
                        if (paths == null || paths.isEmpty()) {
                            return;
                        }
                        String[] patterns = paths.toArray(String[]::new);
                        HttpMethod httpMethod = MyappSecurityProperties.toHttpMethod(method);
                        if (httpMethod != null) {
                            auth.requestMatchers(httpMethod, patterns).permitAll();
                        } else {
                            auth.requestMatchers(patterns).permitAll();
                        }
                    });
                    auth.anyRequest().authenticated();
                })
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(rs -> rs.jwt(jwt ->
                        jwt.jwtAuthenticationConverter(converter)));

        return http.build();
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "myapp.security", name = "method-security",
            havingValue = "true", matchIfMissing = true)
    @EnableMethodSecurity
    static class MethodSecurityConfiguration {
    }
}
