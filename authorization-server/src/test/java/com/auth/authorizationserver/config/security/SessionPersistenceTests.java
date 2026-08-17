package com.auth.authorizationserver.config.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;

import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The login page renders a CSRF-protected form, which forces a session into existence.
 * One request is therefore enough to cover both halves of the session configuration:
 * the attributes of the cookie the browser is handed, and the rows Spring Session
 * writes to Postgres.
 *
 * <p><b>This needs a real web server, not MockMvc.</b> Boot configures the cookie
 * serializer in two mutually exclusive branches, and a {@code MockServletContext} is
 * non-null, so {@code @ConditionalOnWarDeployment} matches and Boot reads the cookie
 * settings off the servlet context instead of {@code server.servlet.session.cookie.*}.
 * Under MockMvc this test would assert against defaults and never see our config at all.
 *
 * <p>Runs against the compose Postgres, like {@code UserPersistenceTests}.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SessionPersistenceTests {

    @LocalServerPort
    private int port;
    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void theLoginPageIssuesAHardenedCookieBackedByRowsInPostgres() throws Exception {
        HttpResponse<Void> response = SessionCookies.getLogin(port, null);
        assertThat(response.statusCode()).isEqualTo(200);

        String cookie = SessionCookies.issued(response)
                .orElseThrow(() -> new AssertionError("No " + SessionCookies.NAME + " cookie was issued"));

        // SameSite=Strict would withhold the cookie on the top-level redirects into
        // /oauth2/authorize and back from Google. Secure is deliberately not asserted:
        // the local profile relaxes it, so the test stays profile-agnostic.
        assertThat(cookie).contains("HttpOnly", "SameSite=Lax");

        String sessionId = SessionCookies.idOf(cookie);

        Integer sessions = jdbcTemplate.queryForObject(
                "select count(*) from spring_session where session_id = ?", Integer.class, sessionId);
        assertThat(sessions).isEqualTo(1);

        // the CSRF token had to be JDK-serialized to get here, which is what would fail
        // if anything reachable from the session were not Serializable
        Integer attributes = jdbcTemplate.queryForObject("""
                select count(*)
                from spring_session_attributes a
                join spring_session s on s.primary_id = a.session_primary_id
                where s.session_id = ?
                """, Integer.class, sessionId);
        assertThat(attributes).isPositive();

        // the row is left behind on purpose: reaping it is the cleanup job's business
    }
}
