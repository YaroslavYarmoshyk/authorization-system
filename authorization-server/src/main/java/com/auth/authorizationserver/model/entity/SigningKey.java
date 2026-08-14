package com.auth.authorizationserver.model.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "signing_keys")
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class SigningKey {
    public enum Status {NEXT, CURRENT, RETIRED}

    @Id
    @Column(length = 64)
    @EqualsAndHashCode.Include
    private String kid;
    @Column(name = "jwk_encrypted", nullable = false)
    private String jwkEncrypted;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private Status status;
    // stamped by the caller's Clock so rotation windows stay testable
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
    @Column(name = "retired_at")
    private Instant retiredAt;

    public SigningKey(String kid, String jwkEncrypted, Status status, Instant createdAt) {
        this.kid = kid;
        this.jwkEncrypted = jwkEncrypted;
        this.status = status;
        this.createdAt = createdAt;
    }
}
