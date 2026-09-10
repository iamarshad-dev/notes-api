package com.arshad.notes.security;

import com.arshad.notes.security.token.repository.RefreshTokenFamilyRepository;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import java.sql.DriverManager;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {
        "app.jwt.secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "app.refresh-token.cleanup-enabled=false",
        "app.cors.allowed-origins=https://client.example"
})
@AutoConfigureMockMvc
@Import(SecurityIntegrationTest.ProbeConfig.class)
class SecurityIntegrationTest {
    private static final String SCHEMA = "security_test_" + UUID.randomUUID().toString().replace("-", "");
    private static PostgreSQLContainer postgres;
    private static String url;
    private static String username;
    private static String password;
    private static final String PASSWORD = "correct-test-password";

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        url = System.getenv("TEST_DB_URL");
        if (url == null || url.isBlank()) {
            postgres = new PostgreSQLContainer("postgres:18-alpine");
            postgres.start();
            url = postgres.getJdbcUrl();
            username = postgres.getUsername();
            password = postgres.getPassword();
        } else {
            username = System.getenv("TEST_DB_USERNAME");
            password = System.getenv("TEST_DB_PASSWORD");
        }
        registry.add("spring.datasource.url", () -> url);
        registry.add("spring.datasource.username", () -> username);
        registry.add("spring.datasource.password", () -> password);
        registry.add("spring.flyway.default-schema", () -> SCHEMA);
        registry.add("spring.jpa.properties.hibernate.default_schema", () -> SCHEMA);
        registry.add("spring.datasource.hikari.schema", () -> SCHEMA);
    }

    @AfterAll
    static void cleanDatabase() throws Exception {
        // Only this suite's generated schema is removed; never touch public/application tables.
        if (url != null && SCHEMA.matches("security_test_[a-f0-9]{32}")) {
            try (var connection = DriverManager.getConnection(url, username, password);
                 var statement = connection.createStatement()) {
                statement.execute("DROP SCHEMA IF EXISTS " + SCHEMA + " CASCADE");
            }
        }
        if (postgres != null) postgres.stop();
    }

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcTemplate jdbc;
    @Autowired PasswordEncoder passwordEncoder;
    @Autowired JwtEncoder encoder;
    @Autowired RefreshTokenFamilyRepository families;
    @Autowired PlatformTransactionManager transactionManager;

    @Test
    void registrationLoginAndCurrentUser() throws Exception {
        String email = UUID.randomUUID() + "@example.com";
        var registered = register(email.toUpperCase());
        assertThat(registered.path("user").path("email").asText()).isEqualTo(email);
        assertThat(registered.has("password")).isFalse();
        assertThat(registered.path("user").has("password")).isFalse();
        assertThat(registered.path("tokenType").asText()).isEqualTo("Bearer");
        String stored = jdbc.queryForObject("select password from users where email = ?", String.class, email);
        assertThat(passwordEncoder.matches(PASSWORD, stored)).isTrue();
        var login = postJson("/api/v1/auth/login", Map.of("email", email, "password", PASSWORD), 200);
        mvc.perform(get("/api/v1/users/me").header("Authorization", bearer(login)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().doesNotExist("Set-Cookie"));
    }

    @Test
    void wrongPasswordAndUnknownEmailHaveSameResponse() throws Exception {
        String email = UUID.randomUUID() + "@example.com";
        register(email);
        var wrong = postJson("/api/v1/auth/login", Map.of("email", email, "password", "wrong"), 401);
        var unknown = postJson("/api/v1/auth/login", Map.of("email", "missing-" + email, "password", "wrong"), 401);
        assertThat(wrong.path("message").asText()).isEqualTo("Invalid email or password");
        assertThat(unknown.path("message")).isEqualTo(wrong.path("message"));
        assertThat(wrong.path("errors").isEmpty()).isTrue();
    }

    @Test
    void refreshRotatesHashedTokensAndReplayRevokesDescendantsOnly() throws Exception {
        String email = UUID.randomUUID() + "@example.com";
        var first = register(email);
        var otherLogin = postJson("/api/v1/auth/login", Map.of("email", email, "password", PASSWORD), 200);
        String raw = first.path("refreshToken").asText();
        assertThat(raw).hasSize(43);
        assertThat(jdbc.queryForObject("select count(*) from refresh_tokens where token_hash = ?", Integer.class, raw)).isZero();
        var second = refresh(raw, 200);
        assertThat(second.path("refreshToken").asText()).isNotEqualTo(raw);
        refresh(raw, 401);
        refresh(second.path("refreshToken").asText(), 401);
        refresh(otherLogin.path("refreshToken").asText(), 200);
    }

    @Test
    void logoutIsIdempotentAndAccessTokenSurvivesUntilExpiry() throws Exception {
        var first = register();
        var second = refresh(first.path("refreshToken").asText(), 200);
        // A spent token still identifies the same session during logout.
        postJson("/api/v1/auth/logout", Map.of("refreshToken", first.path("refreshToken").asText()), 204);
        postJson("/api/v1/auth/logout", Map.of("refreshToken", first.path("refreshToken").asText()), 204);
        postJson("/api/v1/auth/logout", Map.of("refreshToken", "a".repeat(43)), 204);
        refresh(second.path("refreshToken").asText(), 401);
        mvc.perform(get("/api/v1/users/me").header("Authorization", bearer(first))).andExpect(status().isOk());
    }

    @Test
    void concurrentRefreshAllowsOneWinnerAndRevokesSessionOnReplay() throws Exception {
        var auth = register();
        String token = auth.path("refreshToken").asText();
        var gate = new CountDownLatch(1);
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Callable<MvcResult> action = () -> {
                gate.await();
                return mvc.perform(post("/api/v1/auth/refresh").contentType("application/json")
                        .content(mapper.writeValueAsString(Map.of("refreshToken", token)))).andReturn();
            };
            var one = executor.submit(action);
            var two = executor.submit(action);
            gate.countDown();
            var results = List.of(one.get(15, TimeUnit.SECONDS), two.get(15, TimeUnit.SECONDS));
            assertThat(results.stream().map(r -> r.getResponse().getStatus()).toList())
                    .containsExactlyInAnyOrder(200, 401);
            var winner = results.stream().filter(r -> r.getResponse().getStatus() == 200).findFirst().orElseThrow();
            refresh(mapper.readTree(winner.getResponse().getContentAsString()).path("refreshToken").asText(), 401);
        }
    }

    @Test
    void notesEnforceOwnershipAcrossAllOperations() throws Exception {
        var a = register();
        var b = register();
        var created = mvc.perform(post("/api/v1/notes").header("Authorization", bearer(a))
                        .contentType("application/json")
                        .content(mapper.writeValueAsString(Map.of("title", "Private", "content", "secret",
                                "ownerId", b.path("user").path("id").asLong()))))
                .andExpect(status().isCreated()).andReturn();
        long id = mapper.readTree(created.getResponse().getContentAsString()).path("id").asLong();
        String path = "/api/v1/notes/" + id;
        mvc.perform(get(path).header("Authorization", bearer(a)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.content").value("secret"));
        mvc.perform(get(path).header("Authorization", bearer(b))).andExpect(status().isNotFound());
        mvc.perform(put(path).header("Authorization", bearer(b)).contentType("application/json")
                .content("{\"title\":\"stolen\"}")).andExpect(status().isNotFound());
        mvc.perform(delete(path).header("Authorization", bearer(b))).andExpect(status().isNotFound());
        mvc.perform(get("/api/v1/notes").param("userId", a.path("user").path("id").asText())
                .header("Authorization", bearer(b))).andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(0));
        mvc.perform(put(path).header("Authorization", bearer(a)).contentType("application/json")
                .content("{\"title\":\"Updated\",\"content\":\"updated\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.title").value("Updated"));
        mvc.perform(delete(path).header("Authorization", bearer(a))).andExpect(status().isNoContent());
        mvc.perform(get(path).header("Authorization", bearer(a))).andExpect(status().isNotFound());
    }

    @Test
    void missingAuthenticationIs401AndInsufficientPermissionIs403() throws Exception {
        mvc.perform(get("/test/admin")).andExpect(status().isUnauthorized());
        mvc.perform(get("/test/admin").header("Authorization", bearer(register())))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.message").value("Access denied"));
    }

    @Test
    void browserCorsAndValidation() throws Exception {
        mvc.perform(options("/api/v1/notes").header("Origin", "https://client.example")
                .header("Access-Control-Request-Method", "POST")
                .header("Access-Control-Request-Headers", "authorization,content-type"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "https://client.example"))
                .andExpect(header().doesNotExist("Access-Control-Allow-Credentials"));
        mvc.perform(options("/api/v1/notes").header("Origin", "https://evil.example")
                .header("Access-Control-Request-Method", "GET")).andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403)).andExpect(jsonPath("$.message").value("Access denied"));
        mvc.perform(get("/api/v1/notes").param("size", "101").header("Authorization", bearer(register())))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.status").value(400));
        postJson("/api/v1/auth/register", Map.of("name", "Test", "email", "unicode@example.com",
                "password", "é".repeat(40)), 400);
    }

    @Test
    void refreshExpiryAndCleanup() throws Exception {
        var auth = register();
        long userId = auth.path("user").path("id").asLong();
        jdbc.update("update refresh_token_families set expires_at = CURRENT_TIMESTAMP - interval '1 minute' where user_id = ?", userId);
        refresh(auth.path("refreshToken").asText(), 401);
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> families.deleteExpiredBatch(Instant.now(), 1000));
        assertThat(jdbc.queryForObject("select count(*) from refresh_tokens where user_id = ?", Integer.class, userId)).isZero();
    }

    @Test
    void jwtClaimsMustIdentifyThisApiAndAValidUserId() throws Exception {
        for (String subject : List.of("", "email@example.com", "0", "-1", "9223372036854775808")) {
            assertRejectedJwt(subject, "notes-api", "notes-api", "access", true);
        }
        assertRejectedJwt("1", "other-issuer", "notes-api", "access", true);
        assertRejectedJwt("1", "notes-api", "other-api", "access", true);
        assertRejectedJwt("1", "notes-api", "notes-api", "refresh", true);
        assertRejectedJwt("1", "notes-api", "notes-api", "access", false);
    }

    @Test
    void upgradingLegacyTokensRevokesThemAndPreservesUserData() throws Exception {
        String legacySchema = SCHEMA + "_legacy";
        try {
            org.flywaydb.core.Flyway.configure().dataSource(url, username, password)
                    .defaultSchema(legacySchema).target("5").load().migrate();
            try (var connection = DriverManager.getConnection(url, username, password);
                 var statement = connection.createStatement()) {
                connection.setSchema(legacySchema);
                statement.executeUpdate("insert into users (name, email, password) values ('Legacy', 'legacy@example.com', 'test-only-hash')");
                statement.executeUpdate("insert into refresh_tokens (user_id, token_hash, expires_at) values (1, repeat('a',64), CURRENT_TIMESTAMP + interval '1 day')");
            }
            org.flywaydb.core.Flyway.configure().dataSource(url, username, password)
                    .defaultSchema(legacySchema).load().migrate();
            try (var connection = DriverManager.getConnection(url, username, password);
                 var statement = connection.createStatement()) {
                connection.setSchema(legacySchema);
                try (var results = statement.executeQuery("select count(*) from refresh_tokens t join refresh_token_families f on t.family_id = f.id where t.revoked_at is not null and f.revoked_at is not null")) {
                    results.next();
                    assertThat(results.getInt(1)).isEqualTo(1);
                }
                try (var results = statement.executeQuery("select count(*) from users")) {
                    results.next();
                    assertThat(results.getInt(1)).isEqualTo(1);
                }
            }
        } finally {
            try (var connection = DriverManager.getConnection(url, username, password);
                 var statement = connection.createStatement()) {
                statement.execute("DROP SCHEMA IF EXISTS " + legacySchema + " CASCADE");
            }
        }
    }

    @Test
    void duplicateRegistrationIsAConflict() throws Exception {
        String email = UUID.randomUUID() + "@example.com";
        register(email);
        postJson("/api/v1/auth/register", Map.of("name", "Duplicate", "email", email.toUpperCase(),
                "password", PASSWORD), 409);
    }

    @Test
    void cleanupRetainsSpentTokensWhileTheFamilyCanStillBeUsed() throws Exception {
        var auth = register();
        refresh(auth.path("refreshToken").asText(), 200);
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> families.deleteExpiredBatch(Instant.now(), 1000));
        assertThat(jdbc.queryForObject("select count(*) from refresh_tokens where user_id = ?", Integer.class,
                auth.path("user").path("id").asLong())).isEqualTo(2);
    }

    private void assertRejectedJwt(String subject, String issuer, String audience, String type, boolean expiry) throws Exception {
        var claims = JwtClaimsSet.builder().subject(subject).issuer(issuer).audience(List.of(audience))
                .issuedAt(Instant.now()).claim("type", type);
        if (expiry) claims.expiresAt(Instant.now().plusSeconds(900));
        var token = encoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims.build()));
        mvc.perform(get("/api/v1/notes").header("Authorization", "Bearer " + token.getTokenValue()))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.status").value(401));
    }

    private JsonNode register() throws Exception { return register(UUID.randomUUID() + "@example.com"); }
    private JsonNode register(String email) throws Exception {
        return postJson("/api/v1/auth/register", Map.of("name", "Test", "email", email, "password", PASSWORD), 201);
    }
    private JsonNode refresh(String token, int status) throws Exception {
        return postJson("/api/v1/auth/refresh", Map.of("refreshToken", token), status);
    }
    private String bearer(JsonNode auth) { return "Bearer " + auth.path("accessToken").asText(); }
    private JsonNode postJson(String path, Map<String, String> body, int expected) throws Exception {
        var result = mvc.perform(post(path).contentType("application/json").content(mapper.writeValueAsString(body)))
                .andExpect(status().is(expected)).andReturn();
        return expected == 204 ? mapper.nullNode() : mapper.readTree(result.getResponse().getContentAsString());
    }

    @TestConfiguration
    static class ProbeConfig {
        @Bean AdminProbe adminProbe() { return new AdminProbe(); }
    }

    @RestController
    static class AdminProbe {
        @GetMapping("/test/admin")
        @PreAuthorize("hasAuthority('ADMIN')")
        public String restricted() { return "restricted"; }
    }
}
