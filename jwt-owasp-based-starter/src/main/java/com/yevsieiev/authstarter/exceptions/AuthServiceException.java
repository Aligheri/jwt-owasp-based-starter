package com.yevsieiev.authstarter.exceptions;

public class AuthServiceException extends RuntimeException {
    public AuthServiceException(String message , Throwable cause ) {
        super(message, cause);
    }
}
