package com.auth.authorizationserver.model.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "signing_keys")
public class SigningKey {
    public enum Status {NEXT, CURRENT, RETIRED}

    @Id
    private String kid;
    @Column(name = "jwk_encrypted", nullable = false)
    private String jwkEncrypted;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Status status;
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();
    @Column(name = "retired_at")
    private Instant retiredAt;

    public SigningKey(String kid, String jwkEncrypted, Status status) {
        this.kid = kid;
        this.jwkEncrypted = jwkEncrypted;
        this.status = status;
    }
}
