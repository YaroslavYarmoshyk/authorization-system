package com.auth.authorizationserver.repository;

import com.auth.authorizationserver.model.entity.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, String> {

    // @Modifying executes the delete immediately so the replacement token's
    // insert cannot be flushed before it and trip the unique user_id constraint
    @Transactional
    @Modifying
    @Query("delete from PasswordResetToken t where t.userId = :userId")
    void deleteByUserId(UUID userId);
}
