package com.company.oauth.rest.auth;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;

import javax.security.auth.Subject;
import java.util.Collection;

public class CubaBearerTokenAuthentication implements Authentication,
        CredentialsContainer {

     protected BearerTokenAuthenticationToken bearerTokenAuthenticationToken;

     protected String cubaSessionId;

    public CubaBearerTokenAuthentication(BearerTokenAuthenticationToken bearerTokenAuthenticationToken,
                                         String cubaSessionId) {
        this.bearerTokenAuthenticationToken = bearerTokenAuthenticationToken;
        this.cubaSessionId = cubaSessionId;
    }

    public String getCubaSessionId() {
        return cubaSessionId;
    }

    // boiler plate

    public String getToken() {
        return bearerTokenAuthenticationToken.getToken();
    }

    @Override
    public Object getCredentials() {
        return bearerTokenAuthenticationToken.getCredentials();
    }

    @Override
    public Object getPrincipal() {
        return bearerTokenAuthenticationToken.getPrincipal();
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        return bearerTokenAuthenticationToken.getAuthorities();
    }

    @Override
    public String getName() {
        return bearerTokenAuthenticationToken.getName();
    }

    @Override
    public boolean isAuthenticated() {
        return bearerTokenAuthenticationToken.isAuthenticated();
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        bearerTokenAuthenticationToken.setAuthenticated(authenticated);
    }

    @Override
    public Object getDetails() {
        return bearerTokenAuthenticationToken.getDetails();
    }

    public void setDetails(Object details) {
        bearerTokenAuthenticationToken.setDetails(details);
    }

    @Override
    public void eraseCredentials() {
        bearerTokenAuthenticationToken.eraseCredentials();
    }

    @Override
    public boolean equals(Object obj) {
        return bearerTokenAuthenticationToken.equals(obj);
    }

    @Override
    public int hashCode() {
        return bearerTokenAuthenticationToken.hashCode();
    }

    @Override
    public String toString() {
        return bearerTokenAuthenticationToken.toString();
    }

    @Override
    public boolean implies(Subject subject) {
        return bearerTokenAuthenticationToken.implies(subject);
    }
}
