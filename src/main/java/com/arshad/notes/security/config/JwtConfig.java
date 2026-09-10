package com.arshad.notes.security.config;

import com.arshad.notes.security.jwt.JwtProperties;
import com.arshad.notes.security.token.RefreshTokenProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Configuration
@EnableConfigurationProperties({
        JwtProperties.class,
        RefreshTokenProperties.class
})
public class JwtConfig {

    @Bean
    public SecretKey jwtSecretKey(JwtProperties properties) {
        byte[] keyBytes = Base64.getDecoder()
                .decode(properties.secret());

        if (keyBytes.length < 32) {
            throw new IllegalStateException(
                    "JWT secret must contain at least 256 bits"
            );
        }

        return new SecretKeySpec(
                keyBytes,
                "HmacSHA256"
        );
    }

    @Bean
    public JwtEncoder jwtEncoder(SecretKey secretKey) {
        return new NimbusJwtEncoder(
                new com.nimbusds.jose.jwk.source.ImmutableSecret<>(secretKey)
        );
    }

    @Bean
    public JwtDecoder jwtDecoder(
            SecretKey secretKey,
            JwtProperties properties) {
        NimbusJwtDecoder decoder =
                NimbusJwtDecoder
                        .withSecretKey(secretKey)
                        .macAlgorithm(MacAlgorithm.HS256)
                        .build();

        OAuth2TokenValidator<Jwt> issuerValidator =
                JwtValidators.createDefaultWithIssuer(
                        properties.issuer()
                );

        OAuth2TokenValidator<Jwt> accessTokenValidator =
                new JwtClaimValidator<>(
                        "type",
                        "access"::equals
                );

        decoder.setJwtValidator(
                new DelegatingOAuth2TokenValidator<>(
                        issuerValidator,
                        accessTokenValidator,
                        new JwtClaimValidator<java.util.List<String>>("aud",
                                aud -> aud != null && aud.contains(properties.audience())),
                        new JwtClaimValidator<String>("sub", this::validSubject),
                        new JwtClaimValidator<java.time.Instant>("exp", java.util.Objects::nonNull),
                        new JwtClaimValidator<java.time.Instant>("iat", issuedAt -> issuedAt != null
                                && !issuedAt.isAfter(java.time.Instant.now().plusSeconds(60)))
                )
        );

        return decoder;
    }
    private boolean validSubject(String subject) {
        if (subject == null || !subject.matches("[1-9][0-9]{0,18}")) return false;
        try { return Long.parseLong(subject) > 0; }
        catch (NumberFormatException ignored) { return false; }
    }
}
