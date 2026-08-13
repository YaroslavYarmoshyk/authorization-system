package com.auth.authorizationserver.service;

import com.auth.authorizationserver.config.properties.AuthorizationPurgeProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;

/**
 * Removes rows from {@code oauth2_authorization} that Spring Authorization Server
 * never cleans up itself: fully expired grants and abandoned authorization
 * requests that only ever received a {@code state} value.
 *
 * <p>A row is purged once its latest lifetime marker — the greatest of
 * {@code created_at} and every {@code *_expires_at} column — is older than the
 * configured retention. Rows holding any still-valid token are therefore never
 * touched, because their latest expiry lies in the future.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthorizationPurgeService {
    private static final long ADVISORY_LOCK_ID = 4_333_710_002L;
    private static final int LOCK_BUSY = -1;

    // The GREATEST(...) expression must stay identical (same columns, same order)
    // to the one in idx_oauth2_authorization_purge, or Postgres won't use the index.
    private static final String DELETE_EXPIRED_BATCH_SQL = """
            DELETE FROM oauth2_authorization
            WHERE id IN (
                SELECT id
                FROM oauth2_authorization
                WHERE GREATEST(created_at,
                               authorization_code_expires_at, access_token_expires_at,
                               oidc_id_token_expires_at, refresh_token_expires_at,
                               user_code_expires_at, device_code_expires_at) < ?
                LIMIT ?
            )
            """;

    private final JdbcTemplate jdbcTemplate;
    private final TransactionTemplate transactionTemplate;
    private final AuthorizationPurgeProperties purgeProperties;
    private final Clock clock;

    @Scheduled(fixedDelayString = "PT1H", initialDelay = 0)
    public void purgeExpired() {
        Timestamp cutoff = Timestamp.from(clock.instant().minus(purgeProperties.retention()));
        long total = 0;
        int deleted;
        do {
            deleted = transactionTemplate.execute(status -> deleteBatch(cutoff));
            total += Math.max(deleted, 0);
        } while (deleted == purgeProperties.batchSize());

        if (total > 0) {
            log.info("Purged {} expired oauth2_authorization rows older than {}", total, cutoff.toInstant());
        }
    }

    private int deleteBatch(Timestamp cutoff) {
        Boolean lockAcquired = jdbcTemplate.queryForObject(
                "select pg_try_advisory_xact_lock(?)", Boolean.class, ADVISORY_LOCK_ID);
        if (!Boolean.TRUE.equals(lockAcquired)) {
            log.debug("Skipping oauth2_authorization purge: another instance holds the lock");
            return LOCK_BUSY;
        }
        return jdbcTemplate.update(DELETE_EXPIRED_BATCH_SQL, cutoff, purgeProperties.batchSize());
    }
}
