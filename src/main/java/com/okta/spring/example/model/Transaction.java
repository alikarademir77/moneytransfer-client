package com.okta.spring.example.model;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Transaction {
    private String email;
    private String fromAccount;
    private BigDecimal amount;
    private Currency currency;
    private String toAccount;

    private Instant created;
    private UUID id;

}
