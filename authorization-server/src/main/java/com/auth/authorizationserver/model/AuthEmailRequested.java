package com.auth.authorizationserver.model;

public record AuthEmailRequested(String email, String subject, String text) {
}
