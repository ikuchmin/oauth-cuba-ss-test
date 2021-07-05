package com.company.oauth.rest.auth;

import com.company.oauth.config.KeyCloakClientRegistrationConfig;
import com.company.oauth.config.KeyCloakResourceServerConfig;
import com.company.oauth.core.UsersRepository;
import com.company.oauth.exception.CubaUserSessionNotFound;
import com.company.oauth.exception.MakingCubaUserSessionException;
import com.google.common.base.Strings;
import com.haulmont.addon.restapi.api.config.RestApiConfig;
import com.haulmont.addon.restapi.exception.RestApiAccessDeniedException;
import com.haulmont.addon.restapi.rest.RestUserSessionInfo;
import com.haulmont.addon.restapi.rest.ServerTokenStore;
import com.haulmont.cuba.core.global.ClientType;
import com.haulmont.cuba.core.global.GlobalConfig;
import com.haulmont.cuba.core.global.Messages;
import com.haulmont.cuba.core.sys.AppContext;
import com.haulmont.cuba.core.sys.SecurityContext;
import com.haulmont.cuba.security.app.TrustedClientService;
import com.haulmont.cuba.security.auth.AuthenticationDetails;
import com.haulmont.cuba.security.auth.AuthenticationService;
import com.haulmont.cuba.security.auth.Credentials;
import com.haulmont.cuba.security.auth.LoginPasswordCredentials;
import com.haulmont.cuba.security.auth.TrustedClientCredentials;
import com.haulmont.cuba.security.entity.User;
import com.haulmont.cuba.security.global.AccountLockedException;
import com.haulmont.cuba.security.global.LoginException;
import com.haulmont.cuba.security.global.UserSession;
import io.vavr.control.Either;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * Combination of {@link org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider}
 * and {@link com.haulmont.addon.restapi.api.auth.CubaUserAuthenticationProvider}
 */
@SuppressWarnings("JavadocReference")
@Component
public class CubaUserJwtAuthenticationProvider implements AuthenticationProvider {

    protected static final String SESSION_ID_DETAILS_ATTRIBUTE = "sessionId";

    private static final Logger log = LoggerFactory.getLogger(CubaUserJwtAuthenticationProvider.class);

    protected JwtAuthenticationProvider jwtAuthenticationProvider;

    protected ClientRegistrationRepository clientRegistrationRepository;

    protected CubaOAuth2UserService<OAuth2UserRequest, User> userService;

    protected AuthenticationService authenticationService;

    protected Messages messages;

    protected UsersRepository usersRepository;

    protected TrustedClientService trustedClientService;

    protected RestAuthUtils restAuthUtils;

    protected RestApiConfig restApiConfig;

    protected GlobalConfig globalConfig;

    protected static final String MSG_PACK = "com.haulmont.addon.restapi.auth";

    protected JwtDecoder jwtDecoder;

    protected ServerTokenStore serverTokenStore;

    protected KeyCloakClientRegistrationConfig keyCloakClientRegistrationConfig;
    protected KeyCloakResourceServerConfig keyCloakResourceServerConfig;

    private Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter = new JwtAuthenticationConverter();

    private static final OAuth2Error DEFAULT_INVALID_TOKEN =
            invalidToken("An error occurred while attempting to decode the Jwt: Invalid token");


    public CubaUserJwtAuthenticationProvider(AuthenticationService authenticationService, Messages messages, UsersRepository usersRepository, TrustedClientService trustedClientService, RestAuthUtils restAuthUtils, RestApiConfig restApiConfig, GlobalConfig globalConfig, JwtDecoder jwtDecoder, ServerTokenStore serverTokenStore, KeyCloakResourceServerConfig keyCloakResourceServerConfig) {
        this.authenticationService = authenticationService;
        this.messages = messages;
        this.usersRepository = usersRepository;
        this.trustedClientService = trustedClientService;
        this.restAuthUtils = restAuthUtils;
        this.restApiConfig = restApiConfig;
        this.globalConfig = globalConfig;
        this.jwtDecoder = jwtDecoder;
        this.serverTokenStore = serverTokenStore;
        this.keyCloakResourceServerConfig = keyCloakResourceServerConfig;
    }

    /**
     * Decode and validate the
     * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer Token</a>.
     *
     * @param authentication the authentication request object.
     * @return A successful authentication
     * @throws org.springframework.security.core.AuthenticationException if authentication failed for some reason
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        var bearer = (BearerTokenAuthenticationToken) authentication;

        // do everytime to control that token isn't expired
        var jwtToken = jwtAuthenticationProvider.authenticate(authentication);

        // CUBA.platform path
        var usFromTokenStore = findUserSessionInTokenStoreByToken(bearer.getToken());
        if (usFromTokenStore != null) {
            AppContext.setSecurityContext(new SecurityContext(usFromTokenStore));

            //noinspection unchecked
            return createExternalAuthenticationToken(authentication,
                    (Map<String, Object>) jwtToken.getDetails(), usFromTokenStore.getId());
        }

        if (! keyCloakResourceServerConfig.getEnableMakingSession()) {
            throw new CubaUserSessionNotFound(bearer.getToken());
        }

        // try to make CUBA.platform user session by existed user
        var newUserSession = makeCubaUserSession(bearer, jwtToken);

        if (newUserSession.isRight()) {
            var us = newUserSession.get();

            AppContext.setSecurityContext(new SecurityContext(us));

            //noinspection unchecked
            return createExternalAuthenticationToken(authentication,
                    (Map<String, Object>) jwtToken.getDetails(), us.getId());
        }

        if (! keyCloakResourceServerConfig.getEnableUserRegistration()) {
            throw mapOnSpringException(newUserSession.getLeft());
        }

        // try to register new user and making session
        var clientRegistration = clientRegistrationRepository
                .findByRegistrationId(keyCloakClientRegistrationConfig
                        .getKeyCloakClientRegistrationId());

        var accessToken = new OAuth2AccessToken();

        User user = userService.registerUser(new OAuth2UserRequest(
                clientRegistration, accessToken, Collections.emptyMap()));

        newUserSession = makeCubaUserSession();
        //noinspection Convert2MethodRef
        newUserSession.map(us -> {
            AppContext.setSecurityContext(new SecurityContext(us));

            //noinspection unchecked
            return createExternalAuthenticationToken(authentication,
                    (Map<String, Object>) jwtToken.getDetails(), us.getId());

        }).getOrElseThrow(ex -> new MakingCubaUserSessionException(ex));


        String login = extractLogin(jwtToken);




        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
        HttpServletRequest request = attributes.getRequest();

        String ipAddress = request.getRemoteAddr();

        WebAuthenticationDetails authenticationDetails = (WebAuthenticationDetails) authentication.getDetails();
        Map<String, Object> details = new HashMap<>();


        UserSession session;
        try {
            TrustedClientCredentials credentials = new TrustedClientCredentials(login, restApiConfig.getTrustedClientPassword(), Locale.ENGLISH);
            credentials.setIpAddress(ipAddress);
            credentials.setClientType(ClientType.REST_API);
            credentials.setClientInfo(makeClientInfo(request.getHeader(HttpHeaders.USER_AGENT)));
            credentials.setSecurityScope(restApiConfig.getSecurityScope());
            credentials.setParams(details);

            //if the locale value is explicitly passed in the Accept-Language header then set its value to the
            //credentials. Otherwise, the locale of the user should be used
            Locale locale = restAuthUtils.extractLocaleFromRequestHeader(request);
            if (locale != null) {
                credentials.setLocale(locale);
                credentials.setOverrideLocale(true);
            } else {
                credentials.setOverrideLocale(false);
            }

            session = loginMiddleware(credentials).getSession();

            serverTokenStore.putSessionInfo(bearer.getToken(),
                    new RestUserSessionInfo(session.getId(), Locale.ENGLISH));
        } catch (AccountLockedException le) {
            log.info("Blocked user login attempt: login={}, ip={}", login, ipAddress);
            throw new LockedException("User temporarily blocked");
        } catch (RestApiAccessDeniedException ex) {
            log.info("User is not allowed to use the REST API {}", login);
            throw new BadCredentialsException("User is not allowed to use the REST API");
        } catch (LoginException e) {
            log.info("REST API authentication failed: {}", login);
            throw new BadCredentialsException("Bad credentials");
        }


        if (session == null && keyCloakResourceServerConfig.getEnableUserRegistration()) {
            // try to registrate user and make session again
        }

        AppContext.setSecurityContext(new SecurityContext(session));

        return createExternalAuthenticationToken(authentication, details, session.getId());
    }

    protected AuthenticationException mapOnSpringException(LoginException ex) {
        if (ex instanceof AccountLockedException) {
            log.info("Blocked user login attempt: login={}, ip={}", login, ipAddress);
            throw new LockedException("User temporarily blocked");
        }

        if (ex instanceof RestApiAccessDeniedException) {
            log.info("User is not allowed to use the REST API {}", login);
            throw new BadCredentialsException("User is not allowed to use the REST API");
        }

        if (ex instanceof LoginException) {
            log.info("REST API authentication failed: {}", login);
            throw new BadCredentialsException("Bad credentials");
        }

        throw ex;
    }

    protected UserSession findUserSessionInTokenStoreByToken(String token) {
        RestUserSessionInfo sessionInfo = serverTokenStore.getSessionInfoByTokenValue(token);

        if (sessionInfo != null) {
            var sessionId = sessionInfo.getId();

            try {
                return trustedClientService.findSession(restApiConfig.getTrustedClientPassword(), sessionId);
            } catch (LoginException e) {
                throw new RuntimeException("Unable to login with trusted client password");
            }
        }

        return null;
    }

    protected Either<LoginException, UserSession> makeCubaUserSession(BearerTokenAuthenticationToken bearer, Authentication jwtToken) {

        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
        HttpServletRequest request = attributes.getRequest();

        String ipAddress = request.getRemoteAddr();

        String login = extractLogin(jwtToken);

        UserSession session;
        try {
            TrustedClientCredentials credentials = new TrustedClientCredentials(login, restApiConfig.getTrustedClientPassword(), Locale.ENGLISH);
            credentials.setIpAddress(ipAddress);
            credentials.setClientType(ClientType.REST_API);
            credentials.setClientInfo(makeClientInfo(request.getHeader(HttpHeaders.USER_AGENT)));
            credentials.setSecurityScope(restApiConfig.getSecurityScope());

            //if the locale value is explicitly passed in the Accept-Language header then set its value to the
            //credentials. Otherwise, the locale of the user should be used
            Locale locale = restAuthUtils.extractLocaleFromRequestHeader(request);
            if (locale != null) {
                credentials.setLocale(locale);
                credentials.setOverrideLocale(true);
            } else {
                credentials.setOverrideLocale(false);
            }

            session = authenticationService.login(credentials).getSession();

            serverTokenStore.putSessionInfo(bearer.getToken(),
                    new RestUserSessionInfo(session.getId(), locale));

        } catch (LoginException e) {
            return Either.left(e);
        }

        log.debug("New session created for token '{}' since the original session has been expired", tokenMasker.maskToken(tokenValue));

        return Either.right(session);

    }
    private ExternalAuthenticationToken createExternalAuthenticationToken(Authentication authentication,
                                                                          Map<String, Object> details, UUID sessionId) {
        ExternalAuthenticationToken result = new ExternalAuthenticationToken(
                authentication.getPrincipal(),
                getRoleUserAuthorities(authentication)
        );
        details.put(SESSION_ID_DETAILS_ATTRIBUTE, String.valueOf(sessionId.toString()));
        result.setDetails(details);

        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return BearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }

    public void setJwtAuthenticationConverter(
            Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter) {

        Assert.notNull(jwtAuthenticationConverter, "jwtAuthenticationConverter cannot be null");
        this.jwtAuthenticationConverter = jwtAuthenticationConverter;
    }

    private Jwt decodeToken(String token) {
        try {
            return this.jwtDecoder.decode(token);
        } catch (JwtException failed) {
            OAuth2Error invalidToken = invalidToken(failed.getMessage());
            throw new OAuth2AuthenticationException(invalidToken, invalidToken.getDescription(), failed);
        }
    }

    private String extractLogin(Authentication token) {
        return extractPrincipalClaim(token, keyCloakResourceServerConfig.getLoginClaim());
    }

    private String extractPrincipalClaim(Authentication token, String claim) {
        return ((Jwt) token.getPrincipal())
                .getClaim(keyCloakResourceServerConfig.getLoginClaim());
    }

    private static OAuth2Error invalidToken(String message) {
        try {
            return new BearerTokenError(
                    BearerTokenErrorCodes.INVALID_TOKEN,
                    HttpStatus.UNAUTHORIZED,
                    message,
                    "https://tools.ietf.org/html/rfc6750#section-3.1");
        } catch (IllegalArgumentException malformed) {
            // some third-party library error messages are not suitable for RFC 6750's error message charset
            return DEFAULT_INVALID_TOKEN;
        }
    }

    protected AuthenticationDetails loginMiddleware(Credentials credentials) throws LoginException {
        return authenticationService.login(credentials);
    }

    protected TrustedClientCredentials createTrustedCredentials(LoginPasswordCredentials credentials) {
        if (Strings.isNullOrEmpty(credentials.getLogin())) {
            throw new IllegalStateException("Empty username extracted from user authentication details");
        }

        TrustedClientCredentials tcCredentials = new TrustedClientCredentials(
                credentials.getLogin(),
                restApiConfig.getTrustedClientPassword(),
                credentials.getLocale(),
                credentials.getParams()
        );

        tcCredentials.setClientInfo(credentials.getClientInfo());
        tcCredentials.setClientType(ClientType.REST_API);
        tcCredentials.setIpAddress(credentials.getIpAddress());
        tcCredentials.setOverrideLocale(credentials.isOverrideLocale());
        tcCredentials.setSyncNewUserSessionReplication(credentials.isSyncNewUserSessionReplication());
        tcCredentials.setSessionAttributes(credentials.getSessionAttributes());
        tcCredentials.setSecurityScope(restApiConfig.getSecurityScope());

        return tcCredentials;
    }


    protected String makeClientInfo(String userAgent) {
        //noinspection UnnecessaryLocalVariable
        String serverInfo = String.format("REST API (%s:%s/%s) %s",
                globalConfig.getWebHostName(),
                globalConfig.getWebPort(),
                globalConfig.getWebContextName(),
                StringUtils.trimToEmpty(userAgent));

        return serverInfo;
    }

    protected List<GrantedAuthority> getRoleUserAuthorities(Authentication authentication) {
        return new ArrayList<>();
    }

    protected void processSession(RestUserSessionInfo sessionInfo, String userSessionId, String tokenValue, String username) {
        UUID sessionId = sessionInfo.getId();
        if (sessionId == null) {
            if (!Strings.isNullOrEmpty(userSessionId)) {
                sessionId = UUID.fromString(userSessionId);
            }
        }

        UserSession session = null;
        if (sessionId != null) {
            session = findSession(sessionId);
        }

        if (session == null) {

            LoginPasswordCredentials loginPasswordCredentials = new LoginPasswordCredentials(username, "", sessionInfo.getLocale());
            TrustedClientCredentials credentials = createTrustedCredentials(loginPasswordCredentials);

            try {
                session = loginMiddleware(credentials).getSession();
            } catch (LoginException e) {
                throw new LoginException("Cannot login to the middleware", e);
            }

            log.debug("New session created for token '{}' since the original session has been expired", tokenValue);
        }

        serverTokenStore.putSessionInfo(tokenValue, new RestUserSessionInfo(session));
        AppContext.setSecurityContext(new SecurityContext(session));
    }

    private UserSession findSession(UUID sessionId) {
        try {
            return trustedClientService.findSession(restApiConfig.getTrustedClientPassword(), sessionId);
        } catch (LoginException e) {
            throw new RuntimeException("Unable to login with trusted client password");
        }
    }
}
