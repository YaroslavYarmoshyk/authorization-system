package com.auth.authorizationserver.config.email;

import com.auth.authorizationserver.config.properties.AuthProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthEmailSender {
    private final JavaMailSender mailSender;
    private final AuthProperties authProperties;

    public void send(String email, String subject, String text) {
        var message = new SimpleMailMessage();
        message.setFrom(authProperties.mail().from());
        message.setTo(email);
        message.setSubject(subject);
        message.setText(text);
        mailSender.send(message);
    }
}
