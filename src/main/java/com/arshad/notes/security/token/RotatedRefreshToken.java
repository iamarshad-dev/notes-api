package com.arshad.notes.security.token;

import com.arshad.notes.user.entity.User;

public record RotatedRefreshToken(User user, GeneratedRefreshToken token) { }
