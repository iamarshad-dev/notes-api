package com.arshad.notes.security.context;

import com.arshad.notes.user.entity.User;
import com.arshad.notes.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CurrentUser {
    private final UserRepository userRepository;

    public Long id() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken jwt && jwt.isAuthenticated()) {
            try {
                long id = Long.parseLong(jwt.getToken().getSubject());
                if (id > 0) return id;
            } catch (NumberFormatException ignored) {
                // Defensive check; the JWT validator rejects these subjects first.
            }
        }
        throw new AuthenticationCredentialsNotFoundException("Authentication required");
    }

    public User user() {
        return userRepository.findById(id()).orElseThrow(() ->
                new AuthenticationCredentialsNotFoundException("Authentication required"));
    }
}
