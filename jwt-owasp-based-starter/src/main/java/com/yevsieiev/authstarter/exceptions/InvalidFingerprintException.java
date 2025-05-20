package com.yevsieiev.authstarter.exceptions;

public class InvalidFingerprintException extends RuntimeException {
    public InvalidFingerprintException(String message) {
        super(message);
    }
}
