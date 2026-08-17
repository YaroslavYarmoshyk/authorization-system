package com.auth.authorizationserver.config.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;

import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The configured cap is 14 days, which no test can wait out, so this context runs with a cap of
 * 1 ms instead: any session is already over-age by the time the next request reaches the filter.
 * What is under test is the mechanism, not the duration.
 *
 * <p>Runs against the compose Postgres, like {@code UserPersistenceTests}.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "auth.session.max-lifetime=1ms")
class SessionMaxLifetimeTests {

    @LocalServerPort
    private int port;
    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void aSessionPastTheCapIsInvalidatedAndReplaced() throws Exception {
        String original = SessionCookies.issued(SessionCookies.getLogin(port, null))
                .orElseThrow(() -> new AssertionError("No session cookie on the first request"));
        String originalId = SessionCookies.idOf(original);
        assertThat(rowsFor(originalId)).isEqualTo(1);

        HttpResponse<Void> second = SessionCookies.getLogin(port, SessionCookies.asRequestCookie(original));

        // an over-age session is not merely rejected, it is replaced: the login page needs a
        // session for its CSRF token, so the server hands back a brand new one
        String replacement = SessionCookies.issued(second)
                .orElseThrow(() -> new AssertionError("Over-age session was reused instead of replaced"));
        assertThat(SessionCookies.idOf(replacement)).isNotEqualTo(originalId);

        // invalidate() has to reach Postgres, or the old session would still be usable elsewhere
        assertThat(rowsFor(originalId)).isZero();
    }

    private Integer rowsFor(String sessionId) {
        return jdbcTemplate.queryForObject(
                "select count(*) from spring_session where session_id = ?", Integer.class, sessionId);
    }
}
