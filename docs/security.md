# Security design and verification

## Authentication and errors — Tasks 19–20

Spring Security's resource-server filter authenticates Bearer JWTs. Its AuthenticationEntryPoint returns the existing ApiErrorResponse JSON and a WWW-Authenticate: Bearer challenge for missing/invalid authentication. Credential failures raised by the login service are handled by GlobalExceptionHandler, with the same generic message for wrong passwords and unknown accounts. Database/authentication-service failures are not disguised as incorrect passwords.

Authenticated permission failures use JsonAccessDeniedHandler in the filter chain and the matching advice handler for method security. CORS rejection also uses that JSON handler. Error bodies do not include decoder exception messages, passwords, or token values. The API error fields remain timestamp, status, error, message, path, and errors.

- 400: request/validation error.
- 401: missing, invalid or expired credentials.
- 403: authenticated permission failure or disallowed cross-origin browser request.
- 404: missing note or a note owned by another user (identical responses).
- 409: duplicate registration/data conflict.

The API currently has no administrator feature or roles endpoint. Method security is enabled; the integration suite has a test-only restricted endpoint to verify 401 vs 403. It is not shipped in production.

## Logout and refresh lifecycle — Tasks 21–22

Each registration/login creates an independent refresh-token family with an absolute seven-day expiry. Every raw token contains 32 SecureRandom bytes encoded as URL-safe Base64 without padding. Only its SHA-256 hash is stored. Refresh rotates the token atomically within a transaction; each descendant keeps the original family's expiry rather than extending a login indefinitely.

Rotation first locks the family row using PostgreSQL SELECT FOR UPDATE, then reads the token. Requests for any token in the same family serialize on the same lock. Reusing a spent token revokes the family and returns 401, including when requests race. Both transactional service boundaries use noRollbackFor for InvalidRefreshTokenException so this security revocation is committed. Other failures still roll back token issuance/rotation. Clients must serialize refresh attempts: retrying an already-consumed token forces a new login.

Logout revokes the presented token's family. An unknown but correctly shaped token, repeated logout, or a spent token returns the same 204. A spent token still revokes its active descendants. Other login sessions are unaffected. Because access JWT verification is stateless, logout/replay detection does not revoke an existing access token; it remains usable until expiry plus timestamp tolerance. Clients must discard local credentials on logout and sign in again after a refresh 401.

Cleanup removes at most 1,000 expired families per hourly transaction; PostgreSQL cascades deletion to their token rows. Spent/revoked tokens are retained until the family's expiry to preserve replay detection. SKIP LOCKED supports multiple application instances without overlapping batches. Configure app.refresh-token.cleanup-interval for higher-volume installations; disable the job with app.refresh-token.cleanup-enabled=false if an external job owns it.

V6 adds family tracking and revokes legacy refresh sessions. V1–V5 are unchanged. Legacy ancestry cannot be reconstructed safely, so the upgrade requires users to sign in again. The migration is tested both on a fresh database and against V5 data.

Rotation/replay handling follows [RFC 9700 section 4.14](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14).

## Current user and private notes — Tasks 23–24

CurrentUser accepts only an authenticated JwtAuthenticationToken and reads its validated positive Long subject. Controllers never accept an ownership ID as an authoritative input. Services own transaction boundaries and map entities to DTOs while those transactions are active; Open Session in View is disabled.

The existing owner-filtered repository queries are used for all note reads and for loading notes before mutation/deletion. A failed lookup always returns 404. List queries are also scoped to the current user. Note creation loads the current database user and assigns that entity as owner. Request body/query ownership fields are ignored, and neither entity associations nor password hashes are serialized in responses.

## Hardening and deployment — Task 25

JWT decoding pins HS256, validates issuer, requires the notes-api audience and type=access, requires expiry/issued-at, and requires a positive internal Long subject. Spring's timestamp validator handles expiration/not-before with its default 60-second clock-skew tolerance; future issued-at is bounded by the same tolerance. Configured access-token TTL must be between 1 second and 30 minutes (default 15 minutes); refresh lifetime must be between 1 second and 30 days (default seven days). Signing keys must decode from Base64 to at least 32 bytes. Supply keys through environment/secret management and use HTTPS in deployment. Changing the symmetric key invalidates existing JWTs; a rolling key-ring design is outside this scope.

Registration normalizes email consistently with login and database lookup. BCrypt limits are validated in UTF-8 bytes as well as registration's minimum length. DTO toString implementations for credential requests redact passwords. Stateless sessions, disabled request caching, and disabled form/basic/default logout mechanisms prevent accidental cookie/session login flows. CSRF remains disabled because credentials are explicitly supplied in Authorization or request bodies; changing to cookie authentication requires revisiting CSRF protection.

CORS defaults to no cross-origin browser access. Set CORS_ALLOWED_ORIGINS to comma-separated exact HTTP(S) origins, such as http://localhost:5173 for local Flutter web. Wildcards are rejected. Allowed methods/headers are explicit, credentials are disabled, and Authorization is permitted. Native Flutter clients do not depend on browser CORS. Spring Security's default cache-control, nosniff, frame-denial and HTTPS HSTS headers remain enabled; a restrictive content security policy is added for this JSON API.

Application secrets remain outside Git. The scripts load a limited set of .env keys as data, never execute it as shell code, and restore previous process environment values afterward. The application deliberately does not trust forwarded headers by default. If TLS terminates at a proxy, configure forwarding only with a trusted proxy that strips client-supplied forwarding headers. Configure authentication rate limits and request-size limits at that proxy/gateway before exposing the service publicly; no custom in-memory limiter is presented as a distributed production control.

JWT validation uses the built-in validators described in the [Spring Security resource-server documentation](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html).

## Manual verification — Task 26

Run the application with scripts/run.ps1 or environment variables. Use Postman with base URL http://localhost:8080. Register two users A and B, save their responses locally, and do not paste real credentials/tokens into logs or shared documents.

| Check | Request | Expected |
|---|---|---|
| Wrong password | POST /api/v1/auth/login with A's email and a wrong nonempty password | JSON 401, Invalid email or password |
| Unknown email | Same endpoint with an unregistered valid email | Same 401/message |
| Missing JWT | GET /api/v1/notes, no Authorization | JSON 401 and Bearer challenge |
| Malformed JWT | GET /api/v1/notes, Authorization: Bearer not-a-jwt | JSON 401 |
| Invalid signature | Change the first character of the signature (third dot-separated segment) of a valid JWT and use it | JSON 401 |
| Expired JWT | Keep a token until 15 minutes + 60 seconds after issue, then use it | JSON 401 |
| Faster expiry test | Locally set JWT_ACCESS_TOKEN_TTL=5s, restart, sign in, wait over 65 seconds | JSON 401; restore 15m afterward |
| Refresh | POST /api/v1/auth/refresh with R1 | 200 with R2 |
| Replay | Send R1 again, then R2 | Both 401; family is revoked |
| Logout | Fresh login, POST /api/v1/auth/logout with its refresh token, then refresh it | 204, then 401 |
| Stateless access after logout | Use the unexpired access JWT from the logged-out session | Still succeeds until expiry |
| Own notes | A creates a note and reads/updates/deletes it | 201/200/200/204 |
| Cross-user access | B reads/updates/deletes A's note | 404 each time |
| List isolation | B lists notes with userId=A in query | Only B's notes |
| CORS | OPTIONS /api/v1/notes with an unlisted Origin and preflight headers | JSON 403 |

Automated tests use real BCrypt, JWT generation/decoding, the Spring Security filter chain, services, JPA and PostgreSQL/Flyway. Focused filter tests cover malformed headers/signatures/expiry; the integration suite covers persistence, normalization, rotation/replay, simultaneous refresh, logout, cleanup, migration upgrades, 401/403, note ownership, CORS and validation.

## Files by responsibility

- Authentication: auth/controller/AuthController, auth/service/AuthService, credential/refresh DTOs.
- Errors: exception/GlobalExceptionHandler and security/handler/*; existing ApiErrorResponse is reused.
- Token lifecycle: security/token/entity/RefreshTokenFamily, RefreshToken, repositories, service/RefreshTokenService, service/RefreshTokenCleanup, and V6 migration.
- Trusted ownership: security/context/CurrentUser; note/controller, note/service, note/dto; user/controller and user/service.
- Configuration: security/config/*, security/jwt/JwtProperties, JwtService, token/RefreshTokenProperties, application.yaml and .env.example.
- Verification: security/AuthenticationErrorsTest and security/SecurityIntegrationTest replace the environment-dependent context smoke test.
- Project setup: README.md, scripts/run.ps1, scripts/test.ps1 and this guide.
