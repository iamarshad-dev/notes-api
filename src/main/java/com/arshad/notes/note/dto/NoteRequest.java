package com.arshad.notes.note.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record NoteRequest(
        @NotBlank @Size(max = 255) String title,
        @Size(max = 100000) String content
) { }
