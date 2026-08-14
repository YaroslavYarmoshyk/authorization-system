package com.auth.authorizationserver.model.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

/**
 * Write-once: issued, then either redeemed or deleted — never updated.
 */
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Entity
@Table(name = "password_reset_tokens")
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class PasswordResetToken {
    @Id
    @Column(name = "token_hash", length = 64)
    @EqualsAndHashCode.Include
    private String tokenHash;
    @Column(name = "user_id", nullable = false, unique = true)
    private UUID userId;
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;
}
