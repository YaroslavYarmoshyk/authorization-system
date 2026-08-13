package com.auth.authorizationserver.repository;

import com.auth.authorizationserver.model.entity.SigningKey;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface SigningKeyRepository extends JpaRepository<SigningKey, String> {

    List<SigningKey> findByStatus(SigningKey.Status status);

    Optional<SigningKey> findFirstByStatusOrderByCreatedAtDesc(SigningKey.Status status);
}
