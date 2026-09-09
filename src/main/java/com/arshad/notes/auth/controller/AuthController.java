package com.arshad.notes.auth.controller;

import com.arshad.notes.auth.dto.AuthenticatedUserResponse;
import com.arshad.notes.auth.dto.LoginRequest;
import com.arshad.notes.auth.dto.RegisterRequest;
import com.arshad.notes.auth.service.AuthService;
import com.arshad.notes.user.entity.User;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticatedUserResponse> register(
            @Valid @RequestBody RegisterRequest request
            ) {
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticatedUserResponse> login(
            @Valid @RequestBody LoginRequest request
            ) {
        return ResponseEntity.ok(
                authService.login(request)
        );
    }
}
