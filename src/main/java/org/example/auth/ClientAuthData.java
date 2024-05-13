package org.example.auth;

public record ClientAuthData(String username, String pbKdf2Token, long timestamp) {
}
