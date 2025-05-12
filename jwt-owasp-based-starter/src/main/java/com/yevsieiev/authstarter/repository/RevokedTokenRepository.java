package com.yevsieiev.authstarter.repository;

import com.yevsieiev.authstarter.entity.RevokedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository for managing revoked JWT tokens.
 */

public interface RevokedTokenRepository extends JpaRepository<RevokedToken, Long> {
    /**
     * Find a revoked token by its digest.
     *
     * @param jwtTokenDigest the digest of the JWT token
     * @return an Optional containing the revoked token if found, or empty if not found
     */
    Optional<RevokedToken> findByJwtTokenDigest(String jwtTokenDigest);
}