package com.auth.authorizationserver.model.entity;

import com.auth.authorizationserver.model.enumeration.Role;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.Generated;
import org.hibernate.annotations.UuidGenerator;
import org.hibernate.generator.EventType;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@Entity
@Table(name = "users")
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class User {
    @Id
    @UuidGenerator(style = UuidGenerator.Style.VERSION_7)
    @EqualsAndHashCode.Include
    private UUID id;
    @Column(nullable = false, unique = true, length = 320)
    private String email;
    @Column(name = "password_hash", length = 200)
    private String passwordHash;
    @Column(name = "display_name", length = 200)
    private String displayName;
    @Column(nullable = false)
    private boolean enabled = true;
    @Column(name = "email_verified", nullable = false)
    private boolean emailVerified;
    // written by the column's now() default and read back on insert, never written by JPA
    @Generated(event = EventType.INSERT)
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
    @Version
    private long version;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Enumerated(EnumType.STRING)
    @Column(name = "role", length = 50)
    private Set<Role> roles = new HashSet<>();

    // lazy: only the federation path reads this, so fetch it with an entity graph
    @ElementCollection
    @CollectionTable(
            name = "user_identities",
            joinColumns = @JoinColumn(name = "user_id"),
            // the table's PK, which binds a provider subject to exactly one user
            uniqueConstraints = @UniqueConstraint(columnNames = {"provider", "subject"}),
            indexes = @Index(name = "idx_user_identities_user_id", columnList = "user_id"))
    private Set<UserIdentity> identities = new HashSet<>();

    /**
     * Immutable by design: these values live in a {@link HashSet}, so mutating one
     * in place would strand it in a stale bucket.
     */
    @Getter
    @EqualsAndHashCode
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    @AllArgsConstructor
    @Embeddable
    public static class UserIdentity {
        @Column(nullable = false, length = 50)
        private String provider;
        @Column(nullable = false, length = 255)
        private String subject;
    }
}
