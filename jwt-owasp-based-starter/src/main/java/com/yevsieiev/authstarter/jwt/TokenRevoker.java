package com.yevsieiev.authstarter.jwt;
import com.yevsieiev.authstarter.entity.RevokedToken;
import com.yevsieiev.authstarter.repository.RevokedTokenRepository;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;

/**
 * Service for revoking and checking revoked JWT tokens.
 */

public class TokenRevoker {
    private final RevokedTokenRepository revokedTokenRepository;
    private final TokenCipher tokenCipher;

    public TokenRevoker(RevokedTokenRepository revokedTokenRepository, TokenCipher tokenCipher) {
        this.revokedTokenRepository = revokedTokenRepository;
        this.tokenCipher = tokenCipher;
    }
    /**
     * Checks if a token is revoked.
     *
     * @param jwtInHex the encrypted JWT token
     * @return true if the token is revoked, false otherwise
     * @throws Exception if an error occurs
     */
    public boolean isTokenRevoked(String jwtInHex) throws Exception {
        System.out.println("Deciphering token: " + jwtInHex);
        String decipheredToken = tokenCipher.decipherToken(jwtInHex);

        byte[] cipheredToken = decipheredToken.getBytes();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] cipheredTokenDigest = digest.digest(cipheredToken);
        String jwtTokenDigestInHex = Base64.getEncoder().encodeToString(cipheredTokenDigest);

        return revokedTokenRepository.findByJwtTokenDigest(jwtTokenDigestInHex).isPresent();
    }

    /**
     * Revokes a token.
     *
     * @param jwtInHex the encrypted JWT token
     * @throws Exception if an error occurs
     */
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