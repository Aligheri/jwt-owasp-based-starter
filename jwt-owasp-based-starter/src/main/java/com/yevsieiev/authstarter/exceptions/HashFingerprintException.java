package com.yevsieiev.authstarter.exceptions;

public class HashFingerprintException extends RuntimeException {
    public HashFingerprintException(String message) {
        super(message);
    }

    public HashFingerprintException(String message, Throwable cause) {
        super(message, cause);
    }
}
