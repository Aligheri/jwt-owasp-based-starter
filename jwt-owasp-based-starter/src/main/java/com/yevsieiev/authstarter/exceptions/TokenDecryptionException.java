package com.yevsieiev.authstarter.exceptions;

public class TokenDecryptionException extends RuntimeException {
    public TokenDecryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
