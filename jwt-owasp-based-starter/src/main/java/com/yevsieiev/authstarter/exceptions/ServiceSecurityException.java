package com.yevsieiev.authstarter.exceptions;

public class ServiceSecurityException extends RuntimeException {
    public ServiceSecurityException(String message, Throwable cause) {
        super(message, cause);
    }
}
