package com.auth.myappsecuritystarter.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.http.HttpMethod;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

@ConfigurationProperties(prefix = "myapp.security")
public record MyappSecurityProperties(String rolesClaim, String audience, Map<String, Set<String>> permitAll) {

    /**
     * Key under {@code permit-all} that exposes its paths for every HTTP method.
     */
    public static final String ANY_METHOD = "ANY";

    public MyappSecurityProperties {
        rolesClaim = rolesClaim != null ? rolesClaim : "roles";
        permitAll = permitAll == null || permitAll.isEmpty()
                ? Map.of(ANY_METHOD, Set.of("/actuator/health/**"))
                : Collections.unmodifiableMap(new LinkedHashMap<>(permitAll));
    }

    /**
     * Resolves a {@code permit-all} key to the method it exposes, or {@code null} for {@link #ANY_METHOD}.
     * Keys are matched case-insensitively, so both YAML keys and relaxed-binding forms resolve the same way.
     * <p>
     * Unknown methods are rejected rather than passed to {@link HttpMethod#valueOf}, which happily builds a
     * method object for any name — a typo would otherwise register a matcher nothing ever matches and leave
     * the configured paths quietly requiring authentication.
     */
    public static HttpMethod toHttpMethod(String method) {
        if (method == null || method.isBlank() || ANY_METHOD.equalsIgnoreCase(method.trim())) {
            return null;
        }
        String name = method.trim().toUpperCase(Locale.ROOT);
        return Arrays.stream(HttpMethod.values())
                .filter(candidate -> candidate.name().equals(name))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        "Unknown HTTP method '%s' under myapp.security.permit-all; expected %s or '%s'"
                                .formatted(method, Arrays.toString(HttpMethod.values()), ANY_METHOD)));
    }
}
