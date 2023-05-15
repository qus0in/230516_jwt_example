package io.playdata.jwt.model;

import lombok.Data;

@Data
public class SignupRequest {
    private String username;
    private String password;
}
