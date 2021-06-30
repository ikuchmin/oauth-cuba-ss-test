package com.company.oauth.rest;

import com.company.oauth.rest.auth.CubaUserJwtAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

import javax.inject.Inject;

@EnableWebSecurity
public class DirectlyConfiguredJwkSetUri extends WebSecurityConfigurerAdapter {

    @Inject
    protected CubaUserJwtAuthenticationProvider cubaUserJwtAuthenticationProvider;

    @Inject
    protected JwtDecoder jwtDecoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(cubaUserJwtAuthenticationProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authenticationProvider(cubaUserJwtAuthenticationProvider);
        http
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .oauth2ResourceServer().jwt()
//                .authenticationManager(http.getSharedObject(AuthenticationManager.class))
                .decoder(jwtDecoder)
//                .jwkSetUri("http://bespoke-hse2.haulmont.com/app/realms/master/protocol/openid-connect/certs")
//        .and().and()
//                .addFilter(new OAuth2ClientAuthenticationProcessingFilter())
        ;
    }
}