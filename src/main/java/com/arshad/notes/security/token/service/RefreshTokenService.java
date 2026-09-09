package com.arshad.notes.security.token.service;


import com.arshad.notes.security.token.GeneratedRefreshToken;
import com.arshad.notes.security.token.RefreshTokenProperties;
import com.arshad.notes.security.token.entity.RefreshToken;
import com.arshad.notes.security.token.repository.RefreshTokenRepository;
import com.arshad.notes.user.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private static final int TOKEN_BYTES = 32;

    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenProperties properties;

    private final SecureRandom secureRandom = new SecureRandom();

    @Transactional
    public GeneratedRefreshToken create(User user) {

        String rawToken = generateSecureToken();

        String tokenHash = hash(rawToken);

        Instant expiresAt = Instant.now()
                .plus(properties.ttl());

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .tokenHash(tokenHash)
                .expiresAt(expiresAt)
                .build();

        refreshTokenRepository.save(refreshToken);

        return new GeneratedRefreshToken(
                rawToken,
                properties.ttl().toSeconds()
        );
    }


    private String generateSecureToken() {

        byte[] randomBytes = new byte[TOKEN_BYTES];

        secureRandom.nextBytes(randomBytes);

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(randomBytes);
    }

    private String hash(String token) {

        try {
            MessageDigest digest =
                    MessageDigest.getInstance("SHA-256");

            byte[] hash = digest.digest(
                    token.getBytes(StandardCharsets.UTF_8)
            );

            return HexFormat.of().formatHex(hash);

        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(
                    "SHA-256 is not available",
                    exception
            );
        }
    }
}
