package com.yevsieiev.authstarter.exceptions;

public class AuthenticationFailureException extends RuntimeException {
    public AuthenticationFailureException(String message, Throwable cause) {
        super(message, cause);
    }
}
