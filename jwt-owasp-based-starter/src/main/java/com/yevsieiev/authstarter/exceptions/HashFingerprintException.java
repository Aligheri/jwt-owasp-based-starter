package com.yevsieiev.authstarter.exceptions;

import java.security.NoSuchAlgorithmException;

public class HashFingerprintException extends RuntimeException {
    public HashFingerprintException(NoSuchAlgorithmException message) {
        super(message);
    }
}
