package com.auth.gatewayservice.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class UserController {

    record CurrentUser(String name, String email, List<String> roles) {
    }

    @GetMapping("/user")
    CurrentUser currentUser(@AuthenticationPrincipal OidcUser oidcUser) {
        return new CurrentUser(
                oidcUser.getFullName() != null ? oidcUser.getFullName() : oidcUser.getSubject(),
                oidcUser.getClaimAsString("email"),
                oidcUser.getClaimAsStringList("roles"));
    }
}
