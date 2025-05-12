package com.yevsieiev.authstarter.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * Entity for storing revoked JWT tokens.
 */
@Entity
@Table(name = "revoked_token")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class RevokedToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String jwtTokenDigest;

    @Column(name = "revocation_date")
    private Instant revocationDate;
}