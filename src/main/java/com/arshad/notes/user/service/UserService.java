package com.arshad.notes.user.service;

import com.arshad.notes.auth.dto.AuthenticatedUserResponse;
import com.arshad.notes.security.context.CurrentUser;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {
    private final CurrentUser currentUser;

    public AuthenticatedUserResponse me() {
        var user = currentUser.user();
        return new AuthenticatedUserResponse(user.getId(), user.getName(), user.getEmail());
    }
}
