package com.arshad.notes.auth.dto;

public record AuthenticatedUserResponse(
        Long id,
        String name,
        String email
) {
}
