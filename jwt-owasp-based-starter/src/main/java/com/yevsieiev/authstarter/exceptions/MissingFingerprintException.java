package com.yevsieiev.authstarter.exceptions;

public class MissingFingerprintException extends RuntimeException {
    public MissingFingerprintException(String message) {
        super(message);
    }
}
