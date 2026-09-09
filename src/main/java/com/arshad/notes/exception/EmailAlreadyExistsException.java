package com.arshad.notes.exception;

public class EmailAlreadyExistsException extends RuntimeException {

    public EmailAlreadyExistsException(String email) {
        super("An already exists with email: "+email);
    }
}
