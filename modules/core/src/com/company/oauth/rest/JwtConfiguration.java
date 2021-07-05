package com.company.oauth.rest;

import com.company.oauth.config.KeyCloakClientRegistrationConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import javax.inject.Inject;

@Configuration
public class JwtConfiguration {

    @Inject
    protected KeyCloakClientRegistrationConfig keyCloakConfig;

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withJwkSetUri("http://bespoke-hse2.haulmont.com/app/realms/master/protocol/openid-connect/certs").build();
    }

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
                .clientName(keyCloakConfig.getKeyCloakClientRegistrationId())
                .build();
    }
}
