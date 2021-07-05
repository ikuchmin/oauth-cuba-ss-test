package com.company.oauth.rest.auth;

import com.company.oauth.config.KeyCloakClientRegistrationConfig;
import com.company.oauth.config.KeyCloakResourceServerConfig;
import com.company.oauth.exception.CubaUserSessionNotFound;
import com.company.oauth.exception.MakingCubaUserSessionException;
import com.google.common.base.Strings;
import com.haulmont.addon.restapi.api.common.RestTokenMasker;
import com.haulmont.addon.restapi.api.config.RestApiConfig;
import com.haulmont.addon.restapi.exception.RestApiAccessDeniedException;
import com.haulmont.addon.restapi.rest.RestUserSessionInfo;
import com.haulmont.addon.restapi.rest.ServerTokenStore;
import com.haulmont.cuba.core.global.ClientType;
import com.haulmont.cuba.core.global.GlobalConfig;
import com.haulmont.cuba.core.sys.AppContext;
import com.haulmont.cuba.core.sys.SecurityContext;
import com.haulmont.cuba.security.app.TrustedClientService;
import com.haulmont.cuba.security.auth.AuthenticationService;
import com.haulmont.cuba.security.auth.TrustedClientCredentials;
import com.haulmont.cuba.security.entity.User;
import com.haulmont.cuba.security.global.AccountLockedException;
import com.haulmont.cuba.security.global.LoginException;
import com.haulmont.cuba.security.global.UserSession;
import io.vavr.control.Either;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

import static org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER;

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

    protected ServerTokenStore serverTokenStore;

    protected AuthenticationService authenticationService;

    // we can't use UserSessions that provider can be used on different layers
    // or different apps
    protected TrustedClientService trustedClientService;

    protected GlobalConfig globalConfig;

    protected RestApiConfig restApiConfig;

    protected KeyCloakClientRegistrationConfig keyCloakClientRegistrationConfig;

    protected KeyCloakResourceServerConfig keyCloakResourceServerConfig;

    protected RestTokenMasker tokenMasker;


    public CubaUserJwtAuthenticationProvider(JwtDecoder decoder,
                                             ClientRegistrationRepository clientRegistrationRepository,
                                             CubaOAuth2UserService<OAuth2UserRequest, User> userService,
                                             ServerTokenStore serverTokenStore,
                                             AuthenticationService authenticationService,
                                             TrustedClientService trustedClientService,
                                             GlobalConfig globalConfig,
                                             RestApiConfig restApiConfig,
                                             KeyCloakClientRegistrationConfig keyCloakClientRegistrationConfig,
                                             KeyCloakResourceServerConfig keyCloakResourceServerConfig,
                                             RestTokenMasker tokenMasker) {
        this.jwtAuthenticationProvider = new JwtAuthenticationProvider(decoder);
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.userService = userService;
        this.serverTokenStore = serverTokenStore;
        this.authenticationService = authenticationService;
        this.trustedClientService = trustedClientService;
        this.restApiConfig = restApiConfig;
        this.globalConfig = globalConfig;
        this.keyCloakClientRegistrationConfig = keyCloakClientRegistrationConfig;
        this.keyCloakResourceServerConfig = keyCloakResourceServerConfig;
        this.tokenMasker = tokenMasker;
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

        // do everytime to control that token isn't expired
        var jwtToken = (JwtAuthenticationToken) jwtAuthenticationProvider.authenticate(authentication);
        var jwt = (Jwt) jwtToken.getToken();

        // CUBA.platform path
        var usFromTokenStore = findUserSessionInTokenStoreByToken(jwt);
        if (usFromTokenStore != null) {
            AppContext.setSecurityContext(new SecurityContext(usFromTokenStore));

            //noinspection unchecked
            return createExternalAuthenticationToken(authentication,
                    new HashMap<>(), usFromTokenStore.getId());
        }

        if (! keyCloakResourceServerConfig.getEnableMakingSession()) {
            throw new CubaUserSessionNotFound(jwt.getTokenValue());
        }

        // try to make CUBA.platform user session by existed user
        var newUserSession = makeCubaUserSession(jwt);

        if (newUserSession.isRight()) {
            var us = newUserSession.get();

            AppContext.setSecurityContext(new SecurityContext(us));

            //noinspection unchecked
            return createExternalAuthenticationToken(authentication,
                    new HashMap<>(), us.getId());
        }

        if (! keyCloakResourceServerConfig.getEnableUserRegistration()) {
            throw mapOnSpringException(newUserSession.getLeft());
        }

        // try to register new user and making session
        var clientRegistration = clientRegistrationRepository
                .findByRegistrationId(keyCloakClientRegistrationConfig
                        .getKeyCloakClientRegistrationId());

        var oauth2AccessToken = new OAuth2AccessToken(BEARER, jwt.getTokenValue(),
                jwt.getIssuedAt(), jwt.getExpiresAt());

        userService.registerUser(new CubaOAuth2UserRequest(
                clientRegistration, oauth2AccessToken, jwt));

        newUserSession = makeCubaUserSession(jwt);

        //noinspection Convert2MethodRef
        return newUserSession.map(us -> {
            AppContext.setSecurityContext(new SecurityContext(us));

            //noinspection unchecked
            return createExternalAuthenticationToken(authentication,
                    new HashMap<>(), us.getId());

        }).getOrElseThrow(ex -> mapOnSpringException(ex));
    }

    protected UserSession findUserSessionInTokenStoreByToken(Jwt jwt) {
        RestUserSessionInfo sessionInfo = serverTokenStore.getSessionInfoByTokenValue(jwt.getTokenValue());

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

    protected Either<MakingCubaUserSessionException, UserSession> makeCubaUserSession(Jwt jwt) {

        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
        HttpServletRequest request = attributes.getRequest();

        String ipAddress = request.getRemoteAddr();

        String login = extractLogin(jwt);

        UserSession session;
        try {
            TrustedClientCredentials credentials = new TrustedClientCredentials(login, restApiConfig.getTrustedClientPassword(), Locale.ENGLISH);
            credentials.setIpAddress(ipAddress);
            credentials.setClientType(ClientType.REST_API);
            credentials.setClientInfo(makeClientInfo(request.getHeader(HttpHeaders.USER_AGENT)));
            credentials.setSecurityScope(restApiConfig.getSecurityScope());

            //if the locale value is explicitly passed in the Accept-Language header then set its value to the
            //credentials. Otherwise, the locale of the user should be used
            Locale locale = extractLocaleFromRequestHeader(request);
            if (locale != null) {
                credentials.setLocale(locale);
                credentials.setOverrideLocale(true);
            } else {
                credentials.setOverrideLocale(false);
            }

            session = authenticationService.login(credentials).getSession();

            serverTokenStore.putSessionInfo(jwt.getTokenValue(),
                    new RestUserSessionInfo(session.getId(), locale));

        } catch (LoginException e) {
            return Either.left(new MakingCubaUserSessionException(e, login, ipAddress));
        }

        log.debug("New session created for token '{}'", tokenMasker.maskToken(jwt.getTokenValue()));

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

    protected AuthenticationException mapOnSpringException(MakingCubaUserSessionException exp) {

        var cause = exp.getCause();
        if (cause instanceof AccountLockedException) {
            log.info("Blocked user login attempt: login={}, ip={}", exp.getLogin(), exp.getIpAddress());
            throw new LockedException("User temporarily blocked");
        }

        if (cause instanceof RestApiAccessDeniedException) {
            log.info("User is not allowed to use the REST API {}", exp.getLogin());
            throw new BadCredentialsException("User is not allowed to use the REST API");
        }

        if (cause instanceof LoginException) {
            log.info("REST API authentication failed: {}", exp.getLogin());
            throw new BadCredentialsException("Bad credentials");
        }

        throw exp;
    }

    private String extractLogin(Jwt jwt) {
        return jwt.getClaim(keyCloakResourceServerConfig.getLoginClaim());
    }

    @Nullable
    public Locale extractLocaleFromRequestHeader(HttpServletRequest request) {
        Locale locale = null;
        if (!Strings.isNullOrEmpty(request.getHeader(HttpHeaders.ACCEPT_LANGUAGE))) {
            Locale requestLocale = request.getLocale();

            Map<String, Locale> availableLocales = globalConfig.getAvailableLocales();
            if (availableLocales.containsValue(requestLocale)) {
                locale = requestLocale;
            } else {
                log.debug("Locale {} passed in the Accept-Language header is not supported by the application. It was ignored.", requestLocale);
            }
        }
        return locale;
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

    @SuppressWarnings("unused")
    protected List<GrantedAuthority> getRoleUserAuthorities(Authentication authentication) {
        return new ArrayList<>();
    }
}
