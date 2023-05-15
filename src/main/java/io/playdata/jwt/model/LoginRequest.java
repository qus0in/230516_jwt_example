package io.playdata.jwt.model;

import lombok.Data;

@Data
public class LoginRequest {
    private String username;
    private String password;
}
