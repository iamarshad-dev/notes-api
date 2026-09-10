package com.arshad.notes.security.token.service;

import com.arshad.notes.exception.InvalidRefreshTokenException;
import com.arshad.notes.security.token.*;
import com.arshad.notes.security.token.entity.RefreshToken;
import com.arshad.notes.security.token.entity.RefreshTokenFamily;
import com.arshad.notes.security.token.repository.RefreshTokenRepository;
import com.arshad.notes.security.token.repository.RefreshTokenFamilyRepository;
import com.arshad.notes.user.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenFamilyRepository familyRepository;
    private final RefreshTokenProperties properties;
    private final SecureRandom secureRandom = new SecureRandom();

    @Transactional
    public GeneratedRefreshToken create(User user) {
        var family = familyRepository.save(new RefreshTokenFamily(user, Instant.now().plus(properties.ttl())));
        return create(family);
    }

    // The caller must also preserve this exception's commit: replay revocation
    // must survive the 401 response instead of being rolled back.
    @Transactional(noRollbackFor = InvalidRefreshTokenException.class)
    public RotatedRefreshToken rotate(String rawToken) {
        String tokenHash = hash(rawToken);
        var family = lockFamily(tokenHash).orElseThrow(InvalidRefreshTokenException::new);
        Instant now = Instant.now();
        if (!family.isActive(now)) throw new InvalidRefreshTokenException();
        // Read only after locking the family so another rotation cannot leave a stale entity.
        var token = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(InvalidRefreshTokenException::new);
        if (!token.isActive()) {
            family.revoke(now);
            throw new InvalidRefreshTokenException();
        }
        token.revoke();
        return new RotatedRefreshToken(family.getUser(), create(family));
    }

    @Transactional
    public void revoke(String rawToken) {
        lockFamily(hash(rawToken)).ifPresent(family -> family.revoke(Instant.now()));
    }

    private Optional<RefreshTokenFamily> lockFamily(String hash) {
        return refreshTokenRepository.findFamilyIdByTokenHash(hash)
                .flatMap(familyRepository::findLockedById);
    }

    private GeneratedRefreshToken create(RefreshTokenFamily family) {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        refreshTokenRepository.save(RefreshToken.builder().user(family.getUser()).family(family)
                .tokenHash(hash(rawToken)).expiresAt(family.getExpiresAt()).build());
        return new GeneratedRefreshToken(rawToken,
                Math.max(0, Duration.between(Instant.now(), family.getExpiresAt()).toSeconds()));
    }

    private String hash(String token) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available", exception);
        }
    }
}
