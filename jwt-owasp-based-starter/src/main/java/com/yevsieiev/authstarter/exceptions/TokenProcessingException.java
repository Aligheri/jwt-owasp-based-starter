package com.yevsieiev.authstarter.exceptions;

public class TokenProcessingException extends RuntimeException {
    public TokenProcessingException(String message) {
        super(message);
    }

    public TokenProcessingException(String message, Throwable cause) {
        super(message, cause);
    }
}
