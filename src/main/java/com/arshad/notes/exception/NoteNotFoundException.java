package com.arshad.notes.exception;

public class NoteNotFoundException extends RuntimeException {
    public NoteNotFoundException() { super("Note not found"); }
}
