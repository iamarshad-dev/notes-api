package com.arshad.notes.security.jwt;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;
import java.time.Duration;

@Validated
@ConfigurationProperties(prefix = "app.jwt")
public record JwtProperties(@NotBlank String issuer, @NotBlank String secret,
                            @NotNull Duration accessTokenTtl, @NotBlank String audience) {
    public JwtProperties {
        if (accessTokenTtl != null && (accessTokenTtl.compareTo(Duration.ofSeconds(1)) < 0
                || accessTokenTtl.compareTo(Duration.ofMinutes(30)) > 0)) {
            throw new IllegalArgumentException("Access token TTL must be between 1 second and 30 minutes");
        }
    }

    @Override
    public String toString() { return "JwtProperties[secret=REDACTED]"; }
}
