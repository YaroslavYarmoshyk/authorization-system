package com.auth.authorizationserver.config.jwk;

import com.auth.authorizationserver.model.entity.SigningKey;
import com.auth.authorizationserver.repository.SigningKeyRepository;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

@Component
@RequiredArgsConstructor
public class DatabaseJwkSource implements JWKSource<SecurityContext> {
    private static final Duration CACHE_TTL = Duration.ofSeconds(60);
    private final SigningKeyRepository signingKeyRepository;
    private final JwkEncryptor jwkEncryptor;
    private final Clock clock;
    private final AtomicReference<Snapshot> cache = new AtomicReference<>(Snapshot.EMPTY);

    private record Snapshot(JWKSet jwkSet, String currentKid, Instant loadedAt) {

        static final Snapshot EMPTY = new Snapshot(new JWKSet(), null, Instant.MIN);

        boolean isFresh(Instant now) {
            return loadedAt.plus(DatabaseJwkSource.CACHE_TTL).isAfter(now);
        }
    }

    @Override
    public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) {
        return jwkSelector.select(snapshot().jwkSet());
    }

    public String currentSigningKid() {
        String kid = snapshot().currentKid();
        if (kid == null) {
            throw new IllegalStateException(
                    "No CURRENT signing key in database — rotation not bootstrapped yet");
        }
        return kid;
    }

    private Snapshot snapshot() {
        Snapshot current = cache.get();
        Instant now = clock.instant();
        if (current.isFresh(now) && current.currentKid() != null) {
            return current;
        }
        Snapshot loaded = load(now);
        cache.set(loaded);
        return loaded;
    }

    private Snapshot load(Instant now) {
        List<SigningKey> entities = signingKeyRepository.findAll();

        List<JWK> jwks = new ArrayList<>(entities.size());
        SigningKey newestCurrent = null;

        for (SigningKey entity : entities) {
            jwks.add(parse(entity));
            if (entity.getStatus() == SigningKey.Status.CURRENT
                    && (newestCurrent == null
                    || entity.getCreatedAt().isAfter(newestCurrent.getCreatedAt()))) {
                newestCurrent = entity;
            }
        }

        return new Snapshot(new JWKSet(jwks), newestCurrent != null ? newestCurrent.getKid() : null, now);
    }

    private JWK parse(SigningKey entity) {
        try {
            return JWK.parse(jwkEncryptor.decrypt(entity.getJwkEncrypted()));
        } catch (ParseException e) {
            throw new IllegalStateException("Corrupt JWK in database: " + entity.getKid(), e);
        }
    }
}
