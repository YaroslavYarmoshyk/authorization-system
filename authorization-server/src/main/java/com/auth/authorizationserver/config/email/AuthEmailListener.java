package com.auth.authorizationserver.config.email;

import com.auth.authorizationserver.model.AuthEmailRequested;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthEmailListener {
    private final AuthEmailSender sender;

    @Async
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void on(AuthEmailRequested event) {
        try {
            sender.send(event.email(), event.subject(), event.text());
        } catch (RuntimeException e) {
            log.warn("Failed to send '{}' email to {}", event.subject(), event.email(), e);
        }
    }
}
