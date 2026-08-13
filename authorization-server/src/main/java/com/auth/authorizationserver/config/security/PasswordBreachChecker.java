package com.auth.authorizationserver.config.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class PasswordBreachChecker {
    private final CompromisedPasswordChecker delegate = new HaveIBeenPwnedRestApiPasswordChecker();

    public boolean isCompromised(String rawPassword) {
        try {
            return delegate.check(rawPassword).isCompromised();
        } catch (RuntimeException e) {
            log.warn("HIBP check failed, allowing registration (fail-open)", e);
            return false;
        }
    }
}
