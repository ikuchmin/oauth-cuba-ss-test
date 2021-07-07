package com.company.oauth.rest;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class WebDirectlyConfiguredJwkSetUri extends WebSecurityConfigurerAdapter {

//    @Inject
//    protected KeyCloakClientRegistrationConfig keyCloakConfig;

//    @Inject
//    protected CubaUserJwtAuthenticationProvider cubaUserJwtAuthenticationProvider;

//    @Inject
//    protected JwtDecoder jwtDecoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.authenticationProvider(cubaUserJwtAuthenticationProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.authenticationProvider(cubaUserJwtAuthenticationProvider);
        http
//                .authorizeRequests()
//                .anyRequest().authenticated().and()
        .oauth2ResourceServer().jwt()
//                .oauth2Login()
//                .loginPage("/rest/login/oauth2")
//                .clientRegistrationRepository(clientRegistrationRepository())
//                .authorizedClientService(authorizedClientService()).and()
//                .oauth2Client().and()
//                .oauth2ResourceServer().jwt()
//                .authenticationManager(http.getSharedObject(AuthenticationManager.class))
//                .decoder(jwtDecoder)
                .jwkSetUri("http://bespoke-hse2.haulmont.com/app/realms/master/protocol/openid-connect/certs")
//        .and().and()
//                .addFilter(new OAuth2ClientAuthenticationProcessingFilter())
        ;

//        getHttp()
    }

}