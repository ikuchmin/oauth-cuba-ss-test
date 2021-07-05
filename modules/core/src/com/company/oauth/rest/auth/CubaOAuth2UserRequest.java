package com.company.oauth.rest.auth;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Map;

public class CubaOAuth2UserRequest extends OAuth2UserRequest {

    protected Jwt jwt;

    public CubaOAuth2UserRequest(ClientRegistration clientRegistration, OAuth2AccessToken accessToken, Jwt jwt) {
        super(clientRegistration, accessToken);
        this.jwt = jwt;
    }

    public CubaOAuth2UserRequest(ClientRegistration clientRegistration, OAuth2AccessToken accessToken, Map<String, Object> additionalParameters, Jwt jwt) {
        super(clientRegistration, accessToken, additionalParameters);
        this.jwt = jwt;
    }

    public Jwt getJwt() {
        return jwt;
    }
}
