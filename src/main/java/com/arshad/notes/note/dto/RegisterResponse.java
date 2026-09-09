package com.arshad.notes.note.dto;

public record RegisterResponse(
        Long id,
        String name,
        String email
) {
}
