package com.arshad.notes.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record RefreshTokenRequest(

        @NotBlank
        @Pattern(regexp = "[A-Za-z0-9_-]{43}", message = "must be a valid refresh token")
        String refreshToken
) { }
