package com.yevsieiev.authstarter.email;

public interface ActivationService {
    String generateActivationCode(String identifier);
    boolean validateActivationCode(String identifier, String code);
    void sendActivationEmail(String email, String code);
    void invalidateCode(String identifier);
}
