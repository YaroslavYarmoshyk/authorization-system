package com.auth.authorizationserver.config.security;

import com.auth.authorizationserver.config.federation.FederatedLoginSuccessHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.util.LinkedHashSet;
import java.util.Set;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final FederatedLoginSuccessHandler federatedLoginSuccessHandler;

    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerChain(HttpSecurity http) {
        var authServer = new OAuth2AuthorizationServerConfigurer();

        http
                .securityMatcher(authServer.getEndpointsMatcher())
                .with(authServer, as -> as.oidc(Customizer.withDefaults()))
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .exceptionHandling(exception -> exception.defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                ));

        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain defaultChain(HttpSecurity http) {
        http
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/login", "/register", "/verify-email",
                                "/forgot-password", "/reset-password", "/error", "/assets/**").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form.loginPage("/login").permitAll())
                .oauth2Login(o -> o
                        .loginPage("/login")
                        .userInfoEndpoint(u -> u.userAuthoritiesMapper(federatedFactorAuthoritiesMapper()))
                        .successHandler(federatedLoginSuccessHandler)
                        .failureHandler(loggingFailureHandler()));

        return http.build();
    }


    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    private GrantedAuthoritiesMapper federatedFactorAuthoritiesMapper() {
        return authorities -> {
            boolean hasFactor = authorities.stream()
                    .anyMatch(FactorGrantedAuthority.class::isInstance);
            if (hasFactor) {
                return authorities;
            }
            Set<GrantedAuthority> mapped = new LinkedHashSet<>(authorities);
            mapped.add(FactorGrantedAuthority
                    .fromAuthority(FactorGrantedAuthority.AUTHORIZATION_CODE_AUTHORITY));
            return mapped;
        };
    }

    private AuthenticationFailureHandler loggingFailureHandler() {
        var delegate = new SimpleUrlAuthenticationFailureHandler("/login?error");
        return (request, response, exception) -> {
            // повний стек: у OAuth2AuthenticationException причина часто в getError()
            if (exception instanceof OAuth2AuthenticationException oae) {
                log.error("OAuth2 login failed: [{}] {}",
                        oae.getError().getErrorCode(), oae.getError().getDescription(), exception);
            } else {
                log.error("OAuth2 login failed", exception);
            }
            delegate.onAuthenticationFailure(request, response, exception);
        };
    }
}
