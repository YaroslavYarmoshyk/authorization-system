package com.auth.authorizationserver.service;

import com.auth.authorizationserver.config.properties.AuthProperties;
import com.auth.authorizationserver.config.security.PasswordBreachChecker;
import com.auth.authorizationserver.model.AuthEmailRequested;
import com.auth.authorizationserver.model.entity.EmailVerificationToken;
import com.auth.authorizationserver.model.entity.User;
import com.auth.authorizationserver.model.enumeration.Role;
import com.auth.authorizationserver.repository.EmailVerificationTokenRepository;
import com.auth.authorizationserver.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.password.CompromisedPasswordException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RegistrationService {
    private final UserRepository userRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final PasswordBreachChecker passwordBreachChecker;
    private final PasswordEncoder passwordEncoder;
    private final ApplicationEventPublisher applicationEventPublisher;
    private final AuthorizationServerSettings authorizationServerSettings;
    private final AuthProperties authProperties;
    private final PasswordResetService passwordResetService;
    private final TokenFactory tokenFactory;
    private final Clock clock;

    @Transactional
    public void register(String email, String displayName, String rawPassword) {
        if (passwordBreachChecker.isCompromised(rawPassword)) {
            throw new CompromisedPasswordException("This password is compromised");
        }

        String normalized = email.trim().toLowerCase();

        // with identities: notifyAccountExists lists the user's federated providers
        Optional<User> existing = userRepository.findByEmailWithIdentities(normalized);
        if (existing.isPresent()) {
            passwordResetService.notifyAccountExists(existing.get());
            return;
        }

        User user = new User();
        user.setEmail(normalized);
        user.setDisplayName(displayName.trim());
        user.setPasswordHash(passwordEncoder.encode(rawPassword));
        user.setEmailVerified(false);
        user.getRoles().add(Role.USER);
        userRepository.save(user);

        sendVerification(user);
    }

    @Transactional
    public boolean verify(String rawToken) {
        String hash = tokenFactory.hash(rawToken);
        return emailVerificationTokenRepository.findById(hash)
                .filter(t -> t.getExpiresAt().isAfter(clock.instant()))
                .map(t -> {
                    userRepository.findById(t.getUserId()).ifPresent(u -> u.setEmailVerified(true));
                    emailVerificationTokenRepository.delete(t);
                    return true;
                })
                .orElse(false);
    }

    private void sendVerification(User user) {
        TokenFactory.GeneratedToken token = tokenFactory.newToken();

        emailVerificationTokenRepository.deleteByUserId(user.getId());
        emailVerificationTokenRepository.save(new EmailVerificationToken(
                token.hash(), user.getId(), clock.instant().plus(authProperties.registration().tokenTtl())));

        applicationEventPublisher.publishEvent(new AuthEmailRequested(
                user.getEmail(),
                "Email confirmation",
                "To confirm your email please navigate to this link:\n"
                        + authorizationServerSettings.getIssuer() + "/verify-email?token=" + token.raw()
                        + "\n\nThe link is valid for 24h."));
    }
}
