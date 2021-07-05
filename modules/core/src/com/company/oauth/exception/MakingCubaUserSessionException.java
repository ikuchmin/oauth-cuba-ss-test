package com.company.oauth.exception;

import com.haulmont.cuba.core.global.SupportedByClient;

@SupportedByClient
public class MakingCubaUserSessionException extends RuntimeException {

    public MakingCubaUserSessionException() {
        super();
    }

    public MakingCubaUserSessionException(String message) {
        super(message);
    }

    public MakingCubaUserSessionException(String message, Throwable cause) {
        super(message, cause);
    }

    public MakingCubaUserSessionException(Throwable cause) {
        super(cause);
    }

    protected MakingCubaUserSessionException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
