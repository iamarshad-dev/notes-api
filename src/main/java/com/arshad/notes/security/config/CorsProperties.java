package com.arshad.notes.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import java.util.List;

@ConfigurationProperties(prefix = "app.cors")
public record CorsProperties(List<String> allowedOrigins) {
    public CorsProperties {
        allowedOrigins = allowedOrigins == null ? List.of() : List.copyOf(allowedOrigins);
        for (String origin : allowedOrigins) {
            if (origin.contains("*") || !(origin.startsWith("https://") || origin.startsWith("http://"))) {
                throw new IllegalArgumentException("CORS origins must be explicit HTTP(S) origins");
            }
        }
    }
}
