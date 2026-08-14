package com.auth.authorizationserver.model.entity;

import com.auth.authorizationserver.model.enumeration.Role;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the equals/hashCode contract of the entities: identifier only, never mutable state.
 */
class EntityEqualityTests {

    private static User userWithId(UUID id) {
        User user = new User();
        user.setId(id);
        return user;
    }

    @Test
    void usersWithTheSameIdAreEqualAcrossInstances() {
        UUID id = UUID.randomUUID();
        assertThat(userWithId(id)).isEqualTo(userWithId(id));
        assertThat(userWithId(id)).hasSameHashCodeAs(userWithId(id));
    }

    @Test
    void usersWithDifferentIdsAreNotEqual() {
        assertThat(userWithId(UUID.randomUUID())).isNotEqualTo(userWithId(UUID.randomUUID()));
    }

    @Test
    void userEqualityIgnoresEverythingButTheId() {
        UUID id = UUID.randomUUID();

        User one = userWithId(id);
        one.setEmail("alice@example.com");
        one.getRoles().add(Role.USER);

        User other = userWithId(id);
        other.setEmail("renamed@example.com");
        other.setEmailVerified(true);

        assertThat(one).isEqualTo(other);
    }

    /**
     * Documents an accepted limitation of the Lombok-generated hashCode: it derives from the
     * id, so an entity's hash changes when persisting assigns one. Safe only because no
     * {@code Set<User>} exists — introducing one means revisiting this.
     */
    @Test
    void transientUsersShareAnIdOfNullAndSoCompareEqual() {
        assertThat(new User()).isEqualTo(new User());
    }

    @Test
    void identitiesWithTheSameProviderAndSubjectCollapseToOneSetElement() {
        Set<User.UserIdentity> identities = new HashSet<>();
        identities.add(new User.UserIdentity("google", "sub-1"));
        identities.add(new User.UserIdentity("google", "sub-1"));
        identities.add(new User.UserIdentity("google", "sub-2"));
        identities.add(new User.UserIdentity("microsoft", "sub-1"));

        assertThat(identities).hasSize(3);
    }

    @Test
    void signingKeysAreComparedByKidAloneNotByKeyMaterial() {
        Instant now = Instant.now();
        SigningKey one = new SigningKey("rsa-1", "encrypted-a", SigningKey.Status.CURRENT, now);
        SigningKey other = new SigningKey("rsa-1", "encrypted-b", SigningKey.Status.RETIRED, now);

        assertThat(one).isEqualTo(other).hasSameHashCodeAs(other);
        assertThat(one).isNotEqualTo(new SigningKey("rsa-2", "encrypted-a", SigningKey.Status.CURRENT, now));
    }

    @Test
    void tokensAreComparedByTokenHash() {
        UUID userId = UUID.randomUUID();
        Instant expiry = Instant.now();

        assertThat(new EmailVerificationToken("hash-1", userId, expiry))
                .isEqualTo(new EmailVerificationToken("hash-1", UUID.randomUUID(), expiry))
                .isNotEqualTo(new EmailVerificationToken("hash-2", userId, expiry));

        assertThat(new PasswordResetToken("hash-1", userId, expiry))
                .isEqualTo(new PasswordResetToken("hash-1", UUID.randomUUID(), expiry))
                .isNotEqualTo(new PasswordResetToken("hash-2", userId, expiry));
    }

    @Test
    void tokenTypesAreNeverEqualToEachOther() {
        UUID userId = UUID.randomUUID();
        Instant expiry = Instant.now();

        assertThat((Object) new EmailVerificationToken("hash-1", userId, expiry))
                .isNotEqualTo(new PasswordResetToken("hash-1", userId, expiry));
    }
}
