# Notes API

A Spring Boot API with PostgreSQL authentication, short-lived JWT access tokens, rotating opaque refresh tokens, and private notes.

Java 25 · Spring Boot 4.1.1 · Gradle Kotlin · PostgreSQL · Flyway · Spring Security

## Run locally

1. Install Java 25 and start PostgreSQL. Create an application database and database user.
2. Copy `.env.example` to `.env` and set the database credentials and `JWT_SECRET`. The secret must be Base64-encoded cryptographically random bytes, at least 32 bytes before encoding. Never commit it.
3. On Windows, run `./scripts/run.ps1`. It loads the supported `.env` values into the process and starts Gradle `bootRun`.

Spring Boot does not automatically load `.env`. When running through an IDE, Linux shell, or deployment service, supply these values as environment variables instead and run `./gradlew bootRun` or the packaged jar.

Flyway applies migrations at startup; Hibernate validates the schema. **V6 invalidates pre-existing refresh sessions once. Existing users and notes remain intact.** Previously issued JWTs without the new audience claim are rejected, so sign in again after this upgrade.

## API

Base URL: `http://localhost:8080`.

| Method | Path | Authentication / result |
|---|---|---|
| POST | `/api/v1/auth/register` | Public; name, email, password → 201 with tokens and user |
| POST | `/api/v1/auth/login` | Public; email, password → 200 with tokens and user |
| POST | `/api/v1/auth/refresh` | Public; refreshToken → rotated tokens |
| POST | `/api/v1/auth/logout` | Public; refreshToken → idempotent 204 |
| GET | `/api/v1/users/me` | Bearer JWT → current user |
| POST | `/api/v1/notes` | Bearer JWT; title, content → 201 + Location |
| GET | `/api/v1/notes?page=0&size=20` | Bearer JWT → own notes, newest first |
| GET | `/api/v1/notes/{id}` | Bearer JWT → own note |
| PUT | `/api/v1/notes/{id}` | Bearer JWT; title, content → updated own note |
| DELETE | `/api/v1/notes/{id}` | Bearer JWT → 204 |

Use `Authorization: Bearer <accessToken>` for protected requests. Ownership is derived from the validated JWT `sub`; request body/query ownership IDs are never used. Note titles are required and limited to 255 characters; content is optional and limited to 100,000 characters. Pagination is zero-based and size is limited to 1–100.

Logout/refresh requests contain `{"refreshToken":"<token>"}`. Send them without an old/expired Authorization header: an invalid Bearer header is rejected even on public endpoints. Logout revokes the entire refresh session, including rotated descendants. It does not invalidate already-issued access JWTs; discard both tokens on the client.

## Tests

With Docker available, `./gradlew test` (Windows: `./gradlew.bat test`) starts PostgreSQL 18 through Testcontainers.

Without Docker, use an existing PostgreSQL server:

```powershell
./scripts/test.ps1 -UseLocalDatabase
```

This reads only database credentials from `.env`, creates a randomly named test schema, applies real migrations, and removes that schema afterward. It does not migrate or erase application tables. The database user needs permission to create schemas. Alternatively provide `TEST_DB_URL`, `TEST_DB_USERNAME`, and `TEST_DB_PASSWORD` directly to Gradle. The test JWT secret is synthetic and isolated from the application secret.

Reports: `build/reports/tests/test/index.html`.

## Project layout

```text
src/main/java/com/arshad/notes/
  auth/          controller, DTOs, registration/login/refresh/logout service
  user/          entity, repository, current-user endpoint and service
  note/          entity, repository, DTOs, controller and ownership-enforcing service
  exception/     common API error model and controller exception handling
  security/
    config/      filter chain, credentials, JWT and CORS configuration
    context/     trusted current-user lookup
    handler/     JSON authentication, authorization and CORS failure adapters
    jwt/         JWT properties and generation
    service/     database-backed UserDetailsService
    token/       refresh-token families, repositories, rotation and cleanup
src/main/resources/db/migration/  immutable versioned Flyway migrations
src/test/java/com/arshad/notes/security/  focused and PostgreSQL integration tests
scripts/         local run and test commands
docs/            security design and verification guide
```

See [security design and manual verification](docs/security.md). Google/social login remains intentionally postponed.
