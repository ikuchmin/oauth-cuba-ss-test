package com.company.oauth.exception;

import com.haulmont.cuba.core.global.SupportedByClient;

@SupportedByClient
public class CubaUserSessionNotFound extends RuntimeException {
    public CubaUserSessionNotFound() {
    }

    public CubaUserSessionNotFound(String message) {
        super(message);
    }

    public CubaUserSessionNotFound(String message, Throwable cause) {
        super(message, cause);
    }

    public CubaUserSessionNotFound(Throwable cause) {
        super(cause);
    }

    public CubaUserSessionNotFound(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
