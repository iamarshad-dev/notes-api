package com.arshad.notes.exception;

public record ApiFieldError(
        String field,
        String message
) { }
