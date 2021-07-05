package com.company.oauth.exception;

import com.haulmont.cuba.core.global.SupportedByClient;
import com.haulmont.cuba.security.global.LoginException;

@SupportedByClient
public class MakingCubaUserSessionException extends LoginException {

    protected String login;

    protected String ipAddress;

    public MakingCubaUserSessionException(String message, String login, String ipAddress) {
        super(message);
        this.login = login;
        this.ipAddress = ipAddress;
    }

    public MakingCubaUserSessionException(Throwable t, String login, String ipAddress) {
        super(t);
        this.login = login;
        this.ipAddress = ipAddress;
    }

    public MakingCubaUserSessionException(String message, Throwable cause, String login, String ipAddress) {
        super(message, cause);
        this.login = login;
        this.ipAddress = ipAddress;
    }

    public MakingCubaUserSessionException(String template, String login, String ipAddress, Object... params) {
        super(template, params);
        this.login = login;
        this.ipAddress = ipAddress;
    }

    public String getLogin() {
        return login;
    }

    public String getIpAddress() {
        return ipAddress;
    }
}
