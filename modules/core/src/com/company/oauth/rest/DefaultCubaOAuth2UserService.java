package com.company.oauth.rest;

import com.company.oauth.rest.auth.CubaOAuth2UserService;
import com.haulmont.cuba.security.entity.User;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class DefaultCubaOAuth2UserService
        implements CubaOAuth2UserService<OAuth2UserRequest, User> {

    protected DefaultOAuth2UserService defaultOAuth2UserService;

    public DefaultCubaOAuth2UserService() {
        this.defaultOAuth2UserService = new DefaultOAuth2UserService();
    }

    @Override
    public User registerUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        defaultOAuth2UserService.loadUser(userRequest);

        return null;
    }
}
