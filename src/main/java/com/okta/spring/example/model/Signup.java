package com.okta.spring.example.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Signup {
    private String firstName;
    private String lastName;
    private String email;
    private String password;
}

