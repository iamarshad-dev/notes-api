package com.arshad.notes.security.token.service;

import com.arshad.notes.security.token.repository.RefreshTokenFamilyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;

@Component
@RequiredArgsConstructor
@ConditionalOnProperty(name = "app.refresh-token.cleanup-enabled", havingValue = "true", matchIfMissing = true)
public class RefreshTokenCleanup {
    private final RefreshTokenFamilyRepository repository;

    // Keep spent tokens until the absolute family expiry so replay stays detectable.
    // Database cascade removes the tokens. Batches bound each transaction's work.
    @Scheduled(fixedDelayString = "${app.refresh-token.cleanup-interval:PT1H}")
    @Transactional
    public void deleteExpired() {
        repository.deleteExpiredBatch(Instant.now(), 1000);
    }
}
