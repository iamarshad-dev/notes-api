package com.arshad.notes.security.jwt;

public record GeneratedToken(
        String value,
        long expiresIn
) { }
