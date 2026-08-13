package com.auth.authorizationserver.service;

import com.auth.authorizationserver.config.properties.AuthProperties;
import com.auth.authorizationserver.config.security.PasswordBreachChecker;
import com.auth.authorizationserver.model.AuthEmailRequested;
import com.auth.authorizationserver.model.entity.PasswordResetToken;
import com.auth.authorizationserver.model.entity.User;
import com.auth.authorizationserver.repository.EmailVerificationTokenRepository;
import com.auth.authorizationserver.repository.PasswordResetTokenRepository;
import com.auth.authorizationserver.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.password.CompromisedPasswordException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class PasswordResetService {
    private final UserRepository userRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final PasswordBreachChecker passwordBreachChecker;
    private final PasswordEncoder passwordEncoder;
    private final ApplicationEventPublisher applicationEventPublisher;
    private final AuthorizationServerSettings authorizationServerSettings;
    private final TokenFactory tokenFactory;
    private final AuthProperties authProperties;
    private final Clock clock;

    @Transactional
    public void requestReset(String email) {
        // silent when no account exists, same anti-enumeration contract as registration
        userRepository.findByEmail(email.trim().toLowerCase()).ifPresent(user ->
                applicationEventPublisher.publishEvent(new AuthEmailRequested(
                        user.getEmail(),
                        "Set your password",
                        "To set a new password for your account, follow this link:\n"
                                + issueResetUrl(user)
                                + "\n\nThe link is valid for " + tokenTtlText()
                                + ". If you didn't request this, you can ignore this email.")));
    }

    /**
     * Sent instead of a verification email when someone tries to register an email
     * that is already taken. The browser response stays identical either way; only
     * the inbox owner learns the account exists and how to get back into it.
     */
    @Transactional
    public void notifyAccountExists(User user) {
        String howToSignIn;
        if (user.getPasswordHash() != null) {
            howToSignIn = "You can sign in with your email and password.";
        } else {
            String providers = user.getIdentities().stream()
                    .map(User.UserIdentity::getProvider)
                    .collect(Collectors.joining(", "));
            howToSignIn = "You originally signed up with: " + providers
                    + ". You can keep signing in that way.";
        }
        applicationEventPublisher.publishEvent(new AuthEmailRequested(
                user.getEmail(),
                "You already have an account",
                "Someone (hopefully you) tried to create an account with this email address, "
                        + "but an account already exists.\n\n"
                        + howToSignIn + "\n\n"
                        + "To set a new password instead, follow this link:\n"
                        + issueResetUrl(user)
                        + "\n\nThe link is valid for " + tokenTtlText()
                        + ". If this wasn't you, you can ignore this email."));
    }

    @Transactional
    public boolean isTokenValid(String rawToken) {
        return passwordResetTokenRepository.findById(tokenFactory.hash(rawToken))
                .filter(t -> t.getExpiresAt().isAfter(clock.instant()))
                .isPresent();
    }

    @Transactional
    public boolean reset(String rawToken, String rawPassword) {
        if (passwordBreachChecker.isCompromised(rawPassword)) {
            throw new CompromisedPasswordException("This password is compromised");
        }
        return passwordResetTokenRepository.findById(tokenFactory.hash(rawToken))
                .filter(t -> t.getExpiresAt().isAfter(clock.instant()))
                .flatMap(token -> userRepository.findById(token.getUserId()).map(user -> {
                    user.setPasswordHash(passwordEncoder.encode(rawPassword));
                    // following the emailed link proves control of the inbox
                    user.setEmailVerified(true);
                    emailVerificationTokenRepository.deleteByUserId(user.getId());
                    passwordResetTokenRepository.delete(token);
                    return true;
                }))
                .orElse(false);
    }

    private String issueResetUrl(User user) {
        TokenFactory.GeneratedToken token = tokenFactory.newToken();
        passwordResetTokenRepository.deleteByUserId(user.getId());
        passwordResetTokenRepository.save(new PasswordResetToken(
                token.hash(), user.getId(), clock.instant().plus(authProperties.passwordReset().tokenTtl())));
        return authorizationServerSettings.getIssuer() + "/reset-password?token=" + token.raw();
    }

    private String tokenTtlText() {
        return authProperties.passwordReset().tokenTtl().toHours() + "h";
    }
}
