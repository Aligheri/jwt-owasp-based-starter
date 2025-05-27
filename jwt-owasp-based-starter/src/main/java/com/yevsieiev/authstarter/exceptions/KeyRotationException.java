package com.yevsieiev.authstarter.exceptions;

public class KeyRotationException extends RuntimeException {
    public KeyRotationException(String message, Throwable cause) {
        super(message, cause);
    }
}
