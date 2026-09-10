package com.arshad.notes.note.service;

import com.arshad.notes.exception.NoteNotFoundException;
import com.arshad.notes.note.dto.*;
import com.arshad.notes.note.entity.Note;
import com.arshad.notes.note.repository.NoteRepository;
import com.arshad.notes.security.context.CurrentUser;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class NoteService {
    private final NoteRepository repository;
    private final CurrentUser currentUser;

    @Transactional
    public NoteResponse create(NoteRequest request) {
        var note = Note.builder().title(request.title()).content(request.content())
                .owner(currentUser.user()).build();
        return NoteResponse.from(repository.saveAndFlush(note));
    }

    public NotePageResponse list(int page, int size) {
        var notes = repository.findAllByOwnerId(currentUser.id(), PageRequest.of(page, size,
                Sort.by(Sort.Order.desc("createdAt"), Sort.Order.desc("id"))));
        return new NotePageResponse(notes.map(NoteResponse::from).getContent(), page, size,
                notes.getTotalElements(), notes.getTotalPages());
    }

    public NoteResponse get(Long id) { return NoteResponse.from(ownedNote(id)); }

    @Transactional
    public NoteResponse update(Long id, NoteRequest request) {
        var note = ownedNote(id);
        note.update(request.title(), request.content());
        repository.flush();
        return NoteResponse.from(note);
    }

    @Transactional
    public void delete(Long id) { repository.delete(ownedNote(id)); }

    private Note ownedNote(Long id) {
        return repository.findByIdAndOwnerId(id, currentUser.id()).orElseThrow(NoteNotFoundException::new);
    }
}
