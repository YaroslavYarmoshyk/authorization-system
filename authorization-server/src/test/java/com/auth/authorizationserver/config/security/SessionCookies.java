package com.auth.authorizationserver.config.security;

import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

/**
 * Shared plumbing for the session tests. The login page renders a CSRF-protected form, so a plain
 * GET is enough to make the server create — or refuse to reuse — a session.
 */
final class SessionCookies {

    static final String NAME = "AUTH_SESSION";

    private SessionCookies() {
    }

    static HttpResponse<Void> getLogin(int port, @Nullable String cookie) throws IOException, InterruptedException {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/login"));
        if (cookie != null) {
            request.header("Cookie", cookie);
        }
        try (HttpClient client = HttpClient.newHttpClient()) {
            return client.send(request.build(), HttpResponse.BodyHandlers.discarding());
        }
    }

    static Optional<String> issued(HttpResponse<?> response) {
        return response.headers()
                .allValues("set-cookie")
                .stream()
                .filter(header -> header.startsWith(NAME + "="))
                .findFirst();
    }

    /** Turns a {@code Set-Cookie} value into the {@code Cookie} header that sends it back. */
    static String asRequestCookie(String setCookie) {
        return setCookie.substring(0, setCookie.indexOf(';'));
    }

    /** {@code DefaultCookieSerializer} base64-encodes the value; the table stores the raw id. */
    static String idOf(String setCookie) {
        String value = setCookie.substring(setCookie.indexOf('=') + 1, setCookie.indexOf(';'));
        return new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8);
    }
}
