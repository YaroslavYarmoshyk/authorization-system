package com.auth.authorizationserver.repository;

import com.auth.authorizationserver.model.entity.EmailVerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, String> {

    // @Modifying executes the delete immediately so a replacement token's insert
    // cannot be flushed before it and trip the unique user_id constraint
    @Transactional
    @Modifying
    @Query("delete from EmailVerificationToken t where t.userId = :userId")
    void deleteByUserId(UUID userId);
}
