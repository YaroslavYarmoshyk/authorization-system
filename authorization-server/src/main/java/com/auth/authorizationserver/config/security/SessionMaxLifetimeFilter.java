package com.auth.authorizationserver.config.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Caps how long a login session may live, however active it stays. {@code spring.session.timeout}
 * only expires an <em>idle</em> session, so without this a browser that keeps touching the server
 * would hold an SSO session — the credential that mints tokens for every client — open forever.
 *
 * <p>Registered ahead of Spring Security so an over-age session is already invalidated by the time
 * the {@code SecurityContext} would have been read out of it, and the request carries on as
 * anonymous rather than staying authenticated for one last call.
 *
 * <p>No cleanup job is needed for the rows this leaves behind: an over-age session is deleted the
 * moment it is next used, and one that is never used again expires on the idle timeout instead.
 */
@Slf4j
@RequiredArgsConstructor
public class SessionMaxLifetimeFilter extends OncePerRequestFilter {

    private final Duration maxLifetime;
    private final Clock clock;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        HttpSession session = request.getSession(false);
        if (session != null && hasOutlivedCap(session)) {
            log.debug("Invalidating session {}: older than the {} cap", session.getId(), maxLifetime);
            session.invalidate();
        }
        filterChain.doFilter(request, response);
    }

    private boolean hasOutlivedCap(HttpSession session) {
        Instant createdAt = Instant.ofEpochMilli(session.getCreationTime());
        return createdAt.plus(maxLifetime).isBefore(clock.instant());
    }
}
