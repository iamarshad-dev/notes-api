package com.arshad.notes.security.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.DefaultCorsProcessor;
import java.io.IOException;

@RequiredArgsConstructor
public class JsonCorsProcessor extends DefaultCorsProcessor {
    private final JsonAccessDeniedHandler accessDeniedHandler;

    @Override
    public boolean processRequest(CorsConfiguration configuration, HttpServletRequest request,
                                  HttpServletResponse response) throws IOException {
        boolean allowed = super.processRequest(configuration, request, response);
        if (!allowed) accessDeniedHandler.handle(request, response, new AccessDeniedException("Access denied"));
        return allowed;
    }

    @Override
    protected void rejectRequest(ServerHttpResponse response) {
        // Leave the body uncommitted so the same JSON 403 handler can write it.
        response.setStatusCode(HttpStatus.FORBIDDEN);
    }
}
