package com.arshad.notes.security.token;

import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;
import java.time.Duration;

@Validated
@ConfigurationProperties(prefix = "app.refresh-token")
public record RefreshTokenProperties(@NotNull Duration ttl) {
    public RefreshTokenProperties {
        if (ttl != null && (ttl.compareTo(Duration.ofSeconds(1)) < 0 || ttl.compareTo(Duration.ofDays(30)) > 0)) {
            throw new IllegalArgumentException("Refresh token TTL must be between 1 second and 30 days");
        }
    }
}
