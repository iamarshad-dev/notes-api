package com.arshad.notes.auth.dto;

public record AuthResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        long accessTokenExpiresIn,
        long refreshTokenExpiresIn,
        AuthenticatedUserResponse user
) {
}
