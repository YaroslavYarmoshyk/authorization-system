package com.auth.authorizationserver.service;

import com.auth.authorizationserver.config.jwk.JwkEncryptor;
import com.auth.authorizationserver.config.properties.JwkRotationProperties;
import com.auth.authorizationserver.model.entity.SigningKey;
import com.auth.authorizationserver.repository.SigningKeyRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import jakarta.persistence.EntityManager;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class KeyRotationService {
    private static final long ADVISORY_LOCK_ID = 4_333_710_001L;
    private static final int KEY_SIZE = 3072;
    private final SigningKeyRepository signingKeyRepository;
    private final JwkEncryptor jwkEncryptor;
    private final JwkRotationProperties jwkRotationProperties;
    private final EntityManager entityManager;
    private final Clock clock;

    @Transactional
    @Scheduled(fixedDelayString = "PT1H", initialDelay = 0)
    public void rotateIfDue() {
        entityManager.createNativeQuery("select pg_advisory_xact_lock(:id)")
                .setParameter("id", ADVISORY_LOCK_ID)
                .getSingleResult();
        Instant now = clock.instant();
        Optional<SigningKey> current = signingKeyRepository.findFirstByStatusOrderByCreatedAtDesc(SigningKey.Status.CURRENT);

        if (current.isEmpty()) {
            SigningKey bootstrap = generate(SigningKey.Status.CURRENT);
            log.info("Bootstrapped signing key {}", bootstrap.getKid());
            return;
        }

        Instant currentAge = current.get().getCreatedAt();
        boolean nextExists = !signingKeyRepository.findByStatus(SigningKey.Status.NEXT).isEmpty();
        if (!nextExists &&
                currentAge.plus(jwkRotationProperties.rotationPeriod()
                                .minus(jwkRotationProperties.publishAhead()))
                        .isBefore(now)
        ) {
            SigningKey next = generate(SigningKey.Status.NEXT);
            log.info("Published NEXT signing key {}", next.getKid());
        }

        if (currentAge.plus(jwkRotationProperties.rotationPeriod()).isBefore(now)) {
            signingKeyRepository.findFirstByStatusOrderByCreatedAtDesc(SigningKey.Status.NEXT).ifPresent(next -> {
                current.get().setStatus(SigningKey.Status.RETIRED);
                current.get().setRetiredAt(now);
                next.setStatus(SigningKey.Status.CURRENT);
                log.info("Rotated signing key: {} -> {}", current.get().getKid(), next.getKid());
            });
        }

        signingKeyRepository.findByStatus(SigningKey.Status.RETIRED).stream()
                .filter(k -> k.getRetiredAt().plus(jwkRotationProperties.retirementGrace()).isBefore(now))
                .peek(k -> log.info("Deleted retired signing key {}", k.getKid()))
                .forEach(signingKeyRepository::delete);
    }

    private SigningKey generate(SigningKey.Status status) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(KEY_SIZE);
            KeyPair keyPair = generator.generateKeyPair();

            String kid = "rsa-" + LocalDate.now(clock) + "-"
                    + UUID.randomUUID().toString().substring(0, 8);

            RSAKey jwk = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                    .privateKey((RSAPrivateKey) keyPair.getPrivate())
                    .keyID(kid)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .build();

            SigningKey key = new SigningKey(kid, jwkEncryptor.encrypt(jwk.toJSONString()), status);
            return signingKeyRepository.save(key);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA is guaranteed by the JVM spec", e);
        }
    }
}
