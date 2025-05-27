package com.yevsieiev.authstarter.exceptions;

public class TokenRevocationException extends RuntimeException {
    public TokenRevocationException(String message, Throwable cause) {
        super(message, cause);
    }
}
