package com.arshad.notes.note.dto;

import java.util.List;

public record NotePageResponse(List<NoteResponse> content, int page, int size,
                               long totalElements, int totalPages) { }
