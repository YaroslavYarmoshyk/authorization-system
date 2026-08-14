package com.auth.authorizationserver.repository;

import com.auth.authorizationserver.model.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByEmail(String email);

    /**
     * For callers that go on to read or mutate {@code identities}, which is lazy.
     */
    @EntityGraph(attributePaths = "identities")
    @Query("select u from User u where u.email = :email")
    Optional<User> findByEmailWithIdentities(String email);

    @EntityGraph(attributePaths = "identities")
    @Query("""
            select u from User u join u.identities i
            where i.provider = :provider and i.subject = :subject
            """)
    Optional<User> findByIdentity(String provider, String subject);
}
