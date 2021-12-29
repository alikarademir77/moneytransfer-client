package com.okta.spring.example.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Tokens {
    private String idToken;
    private String accessToken;
    private String refreshToken;
    private String refreshTokenIssuedAt;
}
