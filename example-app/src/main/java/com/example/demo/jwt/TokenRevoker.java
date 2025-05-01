package com.example.demo.jwt;

import com.example.demo.entities.RevokedToken;
import com.example.demo.repositories.RevokedTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;

@Service
public class TokenRevoker {
    private final RevokedTokenRepository revokedTokenRepository;
    private final TokenCipher tokenCipher;

    @Autowired
    public TokenRevoker(RevokedTokenRepository revokedTokenRepository, TokenCipher tokenCipher) {
        this.revokedTokenRepository = revokedTokenRepository;
        this.tokenCipher = tokenCipher;
    }

    public boolean isTokenRevoked(String jwtInHex) throws Exception {
        System.out.println("Deciphering token: " + jwtInHex);
        String decipheredToken = tokenCipher.decipherToken(jwtInHex);

        byte[] cipheredToken = decipheredToken.getBytes();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] cipheredTokenDigest = digest.digest(cipheredToken);
        String jwtTokenDigestInHex = Base64.getEncoder().encodeToString(cipheredTokenDigest);

        return revokedTokenRepository.findByJwtTokenDigest(jwtTokenDigestInHex).isPresent();
    }

    public void revokeToken(String jwtInHex) throws Exception {
        System.out.println("Deciphering token for revocation: " + jwtInHex);
        String decipheredToken = tokenCipher.decipherToken(jwtInHex);

        byte[] cipheredToken = decipheredToken.getBytes();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] cipheredTokenDigest = digest.digest(cipheredToken);
        String jwtTokenDigestInHex = Base64.getEncoder().encodeToString(cipheredTokenDigest);

        if (!isTokenRevoked(jwtInHex)) {
            RevokedToken revokedToken = new RevokedToken();
            revokedToken.setJwtTokenDigest(jwtTokenDigestInHex);
            revokedToken.setRevocationDate(Instant.now());
            revokedTokenRepository.save(revokedToken);
        }
    }
}
