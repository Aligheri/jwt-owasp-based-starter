package com.example.demo.repositories;

import com.example.demo.entities.RevokedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
@Repository
public interface RevokedTokenRepository extends JpaRepository<RevokedToken, String> {
    Optional<RevokedToken> findByJwtTokenDigest(String jwtTokenDigest);
}
