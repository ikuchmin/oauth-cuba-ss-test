package com.company.oauth.rest;

import com.company.oauth.rest.auth.CubaUserJwtAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

import javax.inject.Inject;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

//@EnableWebSecurity
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
                .anyRequest().authenticated().and()
//                .oauth2Login()
//                .loginPage("/rest/login/oauth2")
//                .clientRegistrationRepository(clientRegistrationRepository())
//                .authorizedClientService(authorizedClientService()).and()
//                .oauth2Client().and()
                .oauth2ResourceServer().jwt()
//                .authenticationManager(http.getSharedObject(AuthenticationManager.class))
                .decoder(jwtDecoder)
//                .jwkSetUri("http://bespoke-hse2.haulmont.com/app/realms/master/protocol/openid-connect/certs")
//        .and().and()
//                .addFilter(new OAuth2ClientAuthenticationProcessingFilter())
        ;
    }

    private static List<String> clients = Arrays.asList("google", "facebook");

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService() {
        return new InMemoryOAuth2AuthorizedClientService(
                clientRegistrationRepository());
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(keycloakClientRegistration());
    }

    private ClientRegistration keycloakClientRegistration() {
        return ClientRegistration.withRegistrationId("keycloak")
                .clientId("marketplace")
                .clientSecret("c1ea8004-1cae-4b80-949e-75769e90218b")
                .build();
    }
}