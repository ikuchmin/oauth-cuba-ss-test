package com.company.oauth.rest;

import com.company.oauth.config.KeyCloakClientRegistrationConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

import javax.inject.Inject;

//@Configuration
public class OAuth2LoginConfig {

    @Inject
    protected KeyCloakClientRegistrationConfig keyCloakConfig;

//    @EnableWebSecurity
    public static class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests().anyRequest().authenticated().and()
                    .oauth2Login().authorizationEndpoint().baseUri("/rest/oauth2/authorization").and()
                                  .redirectionEndpoint().baseUri("/rest/login/oauth2/code/*");
        }
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(this.keycloakClientRegistration());
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(
            ClientRegistrationRepository clientRegistrationRepository) {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
    }

    @Bean
    public OAuth2AuthorizedClientRepository authorizedClientRepository(
            OAuth2AuthorizedClientService authorizedClientService) {
        return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
    }

    private ClientRegistration keycloakClientRegistration() {
        return ClientRegistration.withRegistrationId(keyCloakConfig.getKeyCloakClientRegistrationId())
                .clientId("marketplace")
                .clientSecret("ef3e4e98-1e90-4811-948f-c38c22a73a54")
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUriTemplate("{baseUrl}/rest/login/oauth2/code/{registrationId}")
                .scope("openid", "profile", "email", "address", "phone")
                .authorizationUri("http://bespoke-hse2.haulmont.com/app/realms/master/protocol/openid-connect/auth")
                .tokenUri("http://bespoke-hse2.haulmont.com/app/realms/master/protocol/openid-connect/token")
                .userInfoUri("http://bespoke-hse2.haulmont.com/app/realms/master/protocol/openid-connect/userinfo")
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .jwkSetUri("http://bespoke-hse2.haulmont.com/app/realms/master/protocol/openid-connect/certs")
                .clientName("Marketplace")
                .build();
    }
}
