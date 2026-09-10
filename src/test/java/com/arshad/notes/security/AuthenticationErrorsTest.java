package com.arshad.notes.security;

import com.arshad.notes.security.handler.JsonAuthenticationEntryPoint;
import com.arshad.notes.security.handler.JsonAccessDeniedHandler;

import com.arshad.notes.auth.controller.AuthController;
import com.arshad.notes.auth.service.AuthService;
import com.arshad.notes.exception.GlobalExceptionHandler;
import com.arshad.notes.security.config.SecurityConfig;
import com.arshad.notes.security.config.JwtConfig;
import com.arshad.notes.security.jwt.JwtProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = AuthController.class, properties = {
        "app.jwt.issuer=notes-api",
        "app.jwt.audience=notes-api",
        "app.refresh-token.ttl=7d",
        "app.jwt.secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "app.jwt.access-token-ttl=15m"
})
@Import({SecurityConfig.class, JsonAuthenticationEntryPoint.class, GlobalExceptionHandler.class, JwtConfig.class, JsonAccessDeniedHandler.class})
class AuthenticationErrorsTest {
    @Autowired MockMvc mvc;
    @Autowired JwtEncoder encoder;
    @MockitoBean AuthService authService;

    @Test
    void badCredentialsAreGeneric() throws Exception {
        when(authService.login(any())).thenThrow(new BadCredentialsException("sensitive details"));
        mvc.perform(post("/api/v1/auth/login").contentType("application/json")
                .content("{\"email\":\"someone@example.com\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid email or password"))
                .andExpect(jsonPath("$.errors").isEmpty());
    }

    @Test
    void missingToken() throws Exception { assertUnauthorized(null); }

    @Test
    void malformedJwt() throws Exception { assertUnauthorized("not-a-jwt"); }

    @Test
    void malformedBearerHeader() throws Exception { assertUnauthorized("bad token"); }

    @Test
    void expiredJwt() throws Exception {
        assertUnauthorized(token(encoder, Instant.now().minusSeconds(120)));
    }

    @Test
    void invalidSignature() throws Exception {
        var otherKey = new SecretKeySpec(new byte[32], "HmacSHA256");
        byte[] bytes = otherKey.getEncoded();
        bytes[0] = 1;
        var otherEncoder = new NimbusJwtEncoder(new com.nimbusds.jose.jwk.source.ImmutableSecret<>(
                new SecretKeySpec(bytes, "HmacSHA256")));
        assertUnauthorized(token(otherEncoder, Instant.now().plusSeconds(900)));
    }

    @Test
    void validTokenPassesAuthentication() throws Exception {
        mvc.perform(get("/api/v1/security-probe").header("Authorization", "Bearer " +
                token(encoder, Instant.now().plusSeconds(900))))
                .andExpect(status().isNotFound());
    }

    private String token(JwtEncoder signer, Instant expiry) {
        return signer.encode(JwtEncoderParameters.from(
                JwsHeader.with(MacAlgorithm.HS256).build(),
                JwtClaimsSet.builder().issuer("notes-api").subject("1").audience(java.util.List.of("notes-api"))
                        .issuedAt(Instant.now().minusSeconds(300)).expiresAt(expiry)
                        .claim("type", "access").build())).getTokenValue();
    }

    private void assertUnauthorized(String token) throws Exception {
        var request = get("/api/v1/security-probe");
        if (token != null) request.header("Authorization", "Bearer " + token);
        mvc.perform(request).andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", "Bearer"))
                .andExpect(content().contentTypeCompatibleWith("application/json"))
                .andExpect(jsonPath("$.timestamp").exists())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").value("Authentication required or access token is invalid"))
                .andExpect(jsonPath("$.path").value("/api/v1/security-probe"))
                .andExpect(jsonPath("$.errors").isEmpty());
    }
}
