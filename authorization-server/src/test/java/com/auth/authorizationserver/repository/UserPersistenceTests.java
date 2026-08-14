package com.auth.authorizationserver.repository;

import com.auth.authorizationserver.model.entity.User;
import com.auth.authorizationserver.model.enumeration.Role;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatNoException;

/**
 * Runs against the compose Postgres so the mappings are exercised against the
 * Liquibase schema rather than a substitute database.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class UserPersistenceTests {

    @Autowired
    private UserRepository users;
    @Autowired
    private EntityManager entityManager;

    private User newUser(String email) {
        User user = new User();
        user.setEmail(email);
        user.setDisplayName("Test User");
        user.getRoles().add(Role.USER);
        return user;
    }

    private static String uniqueEmail() {
        return UUID.randomUUID() + "@example.com";
    }

    @Test
    void assignsATimeOrderedIdAndReadsBackTheDatabaseCreatedAt() {
        User first = users.saveAndFlush(newUser(uniqueEmail()));
        User second = users.saveAndFlush(newUser(uniqueEmail()));

        assertThat(first.getId()).isNotNull();
        assertThat(first.getId().version()).isEqualTo(7);
        // UUIDv7 is time-ordered, which is the point of using it for the PK
        assertThat(first.getId().toString()).isLessThan(second.getId().toString());

        // populated by the column default and read back, not written by JPA
        assertThat(first.getCreatedAt()).isNotNull();
    }

    @Test
    void entityGraphFetchesIdentitiesOutsideThePersistenceContext() {
        String email = uniqueEmail();
        User user = newUser(email);
        user.getIdentities().add(new User.UserIdentity("google", UUID.randomUUID().toString()));
        users.saveAndFlush(user);
        entityManager.clear();

        User plain = users.findByEmail(email).orElseThrow();
        entityManager.detach(plain);
        assertThatThrownBy(() -> plain.getIdentities().size())
                .isInstanceOf(org.hibernate.LazyInitializationException.class);

        entityManager.clear();
        User withGraph = users.findByEmailWithIdentities(email).orElseThrow();
        entityManager.detach(withGraph);
        assertThatNoException().isThrownBy(() -> assertThat(withGraph.getIdentities()).hasSize(1));
    }

    @Test
    void findByIdentityInitialisesTheIdentitiesItMatchedOn() {
        String subject = UUID.randomUUID().toString();
        User user = newUser(uniqueEmail());
        user.getIdentities().add(new User.UserIdentity("google", subject));
        users.saveAndFlush(user);
        entityManager.clear();

        User found = users.findByIdentity("google", subject).orElseThrow();
        entityManager.detach(found);

        assertThat(found.getIdentities())
                .extracting(User.UserIdentity::getSubject)
                .containsExactly(subject);
    }

    /**
     * Needs real commits to get two independent persistence contexts, so it opts out of
     * the surrounding rollback and cleans up after itself instead.
     */
    @Test
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    void concurrentUpdatesToTheSameUserAreRejectedByOptimisticLocking() {
        UUID id = users.saveAndFlush(newUser(uniqueEmail())).getId();
        try {
            User one = users.findById(id).orElseThrow();
            User other = users.findById(id).orElseThrow();

            one.setDisplayName("winner");
            users.saveAndFlush(one);

            other.setDisplayName("loser");
            assertThatThrownBy(() -> users.saveAndFlush(other))
                    .isInstanceOf(ObjectOptimisticLockingFailureException.class);

            assertThat(users.findById(id).orElseThrow().getDisplayName()).isEqualTo("winner");
        } finally {
            users.deleteById(id);
        }
    }
}
