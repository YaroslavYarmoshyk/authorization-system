package com.auth.authorizationserver.service;

import com.auth.authorizationserver.config.properties.FederationProperties;
import com.auth.authorizationserver.error.FederatedProvisioningException;
import com.auth.authorizationserver.model.FederatedIdentity;
import com.auth.authorizationserver.model.entity.User;
import com.auth.authorizationserver.model.enumeration.Role;
import com.auth.authorizationserver.repository.EmailVerificationTokenRepository;
import com.auth.authorizationserver.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository users;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final FederationProperties federationProperties;
    private final TransactionTemplate transactionTemplate;

    public User provisionFederated(FederatedIdentity identity) {
        Optional<User> existing = users.findByIdentity(identity.provider(), identity.subject());
        if (existing.isPresent()) {
            return existing.get();
        }
        try {
            // the transaction boundary sits inside the try, not around it: the recovery
            // lookup below must not run in the transaction the constraint violation
            // already marked rollback-only
            return transactionTemplate.execute(_ -> linkOrCreate(identity));
        } catch (DataIntegrityViolationException e) {
            // a concurrent login won the insert race on the email or identity constraint
            return users.findByIdentity(identity.provider(), identity.subject())
                    .orElseThrow(() -> new FederatedProvisioningException(
                            "Email " + identity.email() + " was registered concurrently; retry sign-in"));
        }
    }

    private User linkOrCreate(FederatedIdentity identity) {
        if (identity.email() == null) {
            throw new FederatedProvisioningException("Provider '" + identity.provider() + "' did not supply an email");
        }

        Optional<User> existingByEmail = users.findByEmailWithIdentities(identity.email());

        boolean canLinkByEmail = identity.emailVerified()
                && federationProperties.linkByEmailAllowed(identity.provider());

        if (existingByEmail.isPresent()) {
            if (!canLinkByEmail) {
                throw new FederatedProvisioningException(
                        "Email " + identity.email() + " already registered; sign in with the "
                                + "original method and link '" + identity.provider()
                                + "' from account settings");
            }
            User user = existingByEmail.get();
            if (!user.isEmailVerified()) {
                // the local registration was never confirmed, so its password may have
                // been chosen by someone other than the inbox owner (pre-hijacking):
                // drop it and let the verified federated owner set one via reset
                user.setPasswordHash(null);
                user.setEmailVerified(true);
                log.warn("Cleared unverified local password while linking {}/{} to user {}",
                        identity.provider(), identity.subject(), user.getId());
            }
            user.getIdentities().add(new User.UserIdentity(identity.provider(), identity.subject()));
            User saved = users.save(user);
            emailVerificationTokenRepository.deleteByUserId(saved.getId());
            log.info("Linked identity {}/{} to existing user {}",
                    identity.provider(), identity.subject(), saved.getId());
            return saved;
        }

        User user = new User();
        user.setEmail(identity.email());
        user.setDisplayName(identity.displayName());
        user.getRoles().add(Role.USER);
        user.getIdentities().add(new User.UserIdentity(identity.provider(), identity.subject()));
        user.setEmailVerified(identity.emailVerified());
        User saved = users.save(user);
        log.info("Provisioned new user {} from provider {}", saved.getId(), identity.provider());
        return saved;
    }
}
