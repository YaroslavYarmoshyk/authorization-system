package com.auth.authorizationserver.config.federation;

import com.auth.authorizationserver.error.FederatedProvisioningException;
import com.auth.authorizationserver.model.FederatedIdentity;
import com.auth.authorizationserver.service.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class FederatedLoginSuccessHandler implements AuthenticationSuccessHandler {
    private final AuthenticationSuccessHandler delegate = new SavedRequestAwareAuthenticationSuccessHandler();
    private final FederatedIdentityExtractor extractor;
    private final UserService userService;

    @Override
    public void onAuthenticationSuccess(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                                        @NonNull Authentication authentication) throws IOException, ServletException {

        if (authentication instanceof OAuth2AuthenticationToken token) {
            FederatedIdentity identity = extractor.extract(token.getAuthorizedClientRegistrationId(), token.getPrincipal());
            try {
                userService.provisionFederated(identity);
            } catch (FederatedProvisioningException e) {
                log.warn("Federated provisioning rejected for provider '{}': {}",
                        identity.provider(), e.getMessage());
                request.getSession().invalidate();
                response.sendRedirect("/login?error");
                return;
            }
        }

        delegate.onAuthenticationSuccess(request, response, authentication);
    }
}
