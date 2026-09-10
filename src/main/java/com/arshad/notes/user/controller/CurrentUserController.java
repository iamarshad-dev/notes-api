package com.arshad.notes.user.controller;

import com.arshad.notes.auth.dto.AuthenticatedUserResponse;
import com.arshad.notes.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class CurrentUserController {
    private final UserService userService;

    @GetMapping("/api/v1/users/me")
    public AuthenticatedUserResponse me() { return userService.me(); }
}
