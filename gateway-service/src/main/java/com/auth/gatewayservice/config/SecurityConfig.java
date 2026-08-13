package com.auth.gatewayservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    SecurityWebFilterChain springSecurity(ServerHttpSecurity http, ReactiveClientRegistrationRepository clientRegistrations) {
        http
                .authorizeExchange(exchange -> exchange.anyExchange().authenticated())
                .oauth2Login(Customizer.withDefaults())
                .logout(logout -> logout.logoutSuccessHandler(getOidcClientInitiatedServerLogoutSuccessHandler(clientRegistrations)))
                .exceptionHandling(e -> e.authenticationEntryPoint(getDelegatingServerAuthenticationEntryPoint()))
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse()));

        return http.build();
    }

    @Bean
    WebFilter csrfCookieWebFilter() {
        return (exchange, chain) -> {
            Mono<CsrfToken> csrfToken = exchange.getAttribute(CsrfToken.class.getName());
            return (csrfToken != null ? csrfToken.then() : Mono.empty())
                    .then(chain.filter(exchange));
        };
    }

    private static OidcClientInitiatedServerLogoutSuccessHandler getOidcClientInitiatedServerLogoutSuccessHandler(ReactiveClientRegistrationRepository clientRegistrations) {
        var oidcLogout = new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrations);
        oidcLogout.setPostLogoutRedirectUri("{baseUrl}");
        return oidcLogout;
    }

    private static DelegatingServerAuthenticationEntryPoint getDelegatingServerAuthenticationEntryPoint() {
        var delegateEntry = new DelegatingServerAuthenticationEntryPoint.DelegateEntry(
                ServerWebExchangeMatchers.pathMatchers("/api/**", "/user"),
                new HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED));
        var entryPoint = new DelegatingServerAuthenticationEntryPoint(delegateEntry);
        entryPoint.setDefaultEntryPoint(new RedirectServerAuthenticationEntryPoint("/oauth2/authorization/my-auth"));
        return entryPoint;
    }
}
