package com.yevsieiev.authstarter.exceptions;

public class FingerprintValidationException extends RuntimeException {
    public FingerprintValidationException(String message) {
        super(message);
    }
}
