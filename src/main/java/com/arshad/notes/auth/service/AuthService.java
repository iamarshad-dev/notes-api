package com.arshad.notes.auth.service;

import com.arshad.notes.auth.dto.*;
import com.arshad.notes.exception.EmailAlreadyExistsException;
import com.arshad.notes.security.jwt.GeneratedToken;
import com.arshad.notes.security.jwt.JwtService;
import com.arshad.notes.security.token.GeneratedRefreshToken;
import com.arshad.notes.security.token.service.RefreshTokenService;
import com.arshad.notes.user.entity.User;
import com.arshad.notes.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    @Transactional
    public AuthResponse register(RegisterRequest request) {

        String normalizedEmail = normalizeEmail(request.email());

        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new EmailAlreadyExistsException(normalizedEmail);
        }

        User user = User.builder()
                .name(request.name())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .build();

        User savedUser = userRepository.save(user);

        return createAuthResponse(savedUser);
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {

        String normalizedEmail = normalizeEmail(request.email());

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        normalizedEmail,
                        request.password()
                )
        );

        User user = userRepository.findByEmail(normalizedEmail)
                .orElseThrow();

        return createAuthResponse(user);
    }

    @Transactional
    public AuthResponse refresh(RefreshTokenRequest request) {

        User user = refreshTokenService.rotate(
                request.refreshToken()
        );

        return createAuthResponse(user);
    }

    private AuthResponse createAuthResponse(User user) {

        GeneratedToken accessToken =
                jwtService.generateAccessToken(user);

        GeneratedRefreshToken refreshToken =
                refreshTokenService.create(user);

        AuthenticatedUserResponse authenticatedUser =
                new AuthenticatedUserResponse(
                        user.getId(),
                        user.getName(),
                        user.getEmail()
                );

        return new AuthResponse(
                accessToken.value(),
                refreshToken.value(),
                "Bearer",
                accessToken.expiresIn(),
                refreshToken.expiresIn(),
                authenticatedUser
        );

    }

    private String normalizeEmail(String email) {
        return email
                .trim()
                .toLowerCase(Locale.ROOT);
    }
}
