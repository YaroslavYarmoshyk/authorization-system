package com.auth.authorizationserver.model.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "password_reset_tokens")
public class PasswordResetToken {
    @Id
    @Column(name = "token_hash")
    private String tokenHash;
    @Column(name = "user_id", nullable = false, unique = true)
    private UUID userId;
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;
}
