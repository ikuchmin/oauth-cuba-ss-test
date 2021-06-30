package com.company.oauth.rest.auth;

import com.company.oauth.core.UsersRepository;
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
import com.haulmont.cuba.security.global.AccountLockedException;
import com.haulmont.cuba.security.global.LoginException;
import com.haulmont.cuba.security.global.UserSession;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.SerializationUtils;

import java.util.ArrayList;
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

    private Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter = new JwtAuthenticationConverter();

    private static final OAuth2Error DEFAULT_INVALID_TOKEN =
            invalidToken("An error occurred while attempting to decode the Jwt: Invalid token");


    public CubaUserJwtAuthenticationProvider(AuthenticationService authenticationService, Messages messages, UsersRepository usersRepository, TrustedClientService trustedClientService, RestAuthUtils restAuthUtils, RestApiConfig restApiConfig, GlobalConfig globalConfig, JwtDecoder jwtDecoder, ServerTokenStore serverTokenStore) {
        this.authenticationService = authenticationService;
        this.messages = messages;
        this.usersRepository = usersRepository;
        this.trustedClientService = trustedClientService;
        this.restAuthUtils = restAuthUtils;
        this.restApiConfig = restApiConfig;
        this.globalConfig = globalConfig;
        this.jwtDecoder = jwtDecoder;
        this.serverTokenStore = serverTokenStore;
    }

    /**
     * Decode and validate the
     * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer Token</a>.
     *
     * @param authentication the authentication request object.
     *
     * @return A successful authentication
     * @throws org.springframework.security.core.AuthenticationException if authentication failed for some reason
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        BearerTokenAuthenticationToken bearer = (BearerTokenAuthenticationToken) authentication;

        Jwt jwt;
        try {
            jwt = this.jwtDecoder.decode(bearer.getToken());
        } catch (JwtException failed) {
            OAuth2Error invalidToken = invalidToken(failed.getMessage());
            throw new OAuth2AuthenticationException(invalidToken, invalidToken.getDescription(), failed);
        }

        AbstractAuthenticationToken token = this.jwtAuthenticationConverter.convert(jwt);
        token.setDetails(bearer.getDetails());

        // CUBA.platform path

//        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
//        HttpServletRequest request = attributes.getRequest();

//        String ipAddress = request.getRemoteAddr();

        String login = ((Jwt)token.getPrincipal()).getClaim("preferred_username");

        //noinspection unchecked
//        Map<String, Object> details = (Map<String, Object>) authentication.getDetails();
        Map<String, Object> details = new HashMap<>();

        RestUserSessionInfo cubaSessionInfo = serverTokenStore.getSessionInfoByTokenValue(bearer.getToken());
        if (cubaSessionInfo != null) {
            processSession(cubaSessionInfo, bearer.getToken());
            // next operation did in processSession
//            AppContext.setSecurityContext(new SecurityContext(session));

            ExternalAuthenticationToken result = new ExternalAuthenticationToken(authentication.getPrincipal(),
                    getRoleUserAuthorities(authentication));
            details.put(SESSION_ID_DETAILS_ATTRIBUTE, cubaSessionInfo.getId().toString());
            result.setDetails(details);

            return result;
        }

        UserSession session;
        try {
            TrustedClientCredentials credentials = new TrustedClientCredentials(login, restApiConfig.getTrustedClientPassword(), Locale.ENGLISH);
//            credentials.setIpAddress(ipAddress);
            credentials.setClientType(ClientType.REST_API);
//            credentials.setClientInfo(makeClientInfo(request.getHeader(HttpHeaders.USER_AGENT)));
            credentials.setSecurityScope(restApiConfig.getSecurityScope());
            credentials.setParams(details);

            //if the locale value is explicitly passed in the Accept-Language header then set its value to the
            //credentials. Otherwise, the locale of the user should be used
//            Locale locale = restAuthUtils.extractLocaleFromRequestHeader(request);
//            if (locale != null) {
//                credentials.setLocale(locale);
//                credentials.setOverrideLocale(true);
//            } else {
//                credentials.setOverrideLocale(false);
//            }

                session = loginMiddleware(credentials).getSession();

                serverTokenStore.putSessionInfo(bearer.getToken(),
                        new RestUserSessionInfo(session.getId(), Locale.ENGLISH));
        } catch (AccountLockedException le) {
            log.info("Blocked user login attempt: login={}, ip={}", login);
            throw new LockedException("User temporarily blocked");
        } catch (RestApiAccessDeniedException ex) {
            log.info("User is not allowed to use the REST API {}", login);
            throw new BadCredentialsException("User is not allowed to use the REST API");
        } catch (LoginException e) {
            log.info("REST API authentication failed: {} {}", login);
            throw new BadCredentialsException("Bad credentials");
        }

        AppContext.setSecurityContext(new SecurityContext(session));

        ExternalAuthenticationToken result = new ExternalAuthenticationToken(authentication.getPrincipal(),
                getRoleUserAuthorities(authentication));
        details.put(SESSION_ID_DETAILS_ATTRIBUTE, session.getId().toString());
        result.setDetails(details);

        return token;
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

    protected String getInvalidCredentialsMessage(String login, Locale locale) {
        return messages.formatMessage(MSG_PACK, "LoginException.InvalidLoginOrPassword", locale, login);
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

    protected void processSession(RestUserSessionInfo sessionInfo, String tokenValue) {
        UUID sessionId = sessionInfo.getId();
//        if (sessionId == null) {
//            @SuppressWarnings("unchecked")
//            Map<String, String> userAuthenticationDetails =
//                    (Map<String, String>) authentication.getUserAuthentication().getDetails();
//            //sessionId parameter was put in the CubaUserAuthenticationProvider
//            String sessionIdStr = userAuthenticationDetails.get("sessionId");
//            if (! Strings.isNullOrEmpty(sessionIdStr)) {
//                sessionId = UUID.fromString(sessionIdStr);
//            }
//        }

        UserSession session = null;
        if (sessionId != null) {
            try {
                session = trustedClientService.findSession(restApiConfig.getTrustedClientPassword(), sessionId);
            } catch (LoginException e) {
                throw new RuntimeException("Unable to login with trusted client password");
            }
        }

//        if (session == null) {
//            @SuppressWarnings("unchecked")
//            Map<String, String> userAuthenticationDetails =
//                    (Map<String, String>) authentication.getUserAuthentication().getDetails();
//            String username = userAuthenticationDetails.get("username");
//
//            if (Strings.isNullOrEmpty(username)) {
//                throw new IllegalStateException("Empty username extracted from user authentication details");
//            }
//
//            Locale locale = sessionInfo != null ?
//                    sessionInfo.getLocale() : null;
//            TrustedClientCredentials credentials = createTrustedClientCredentials(username, locale);
//            try {
//                session = authenticationService.login(credentials).getSession();
//            } catch (LoginException e) {
//                throw new OAuth2Exception("Cannot login to the middleware", e);
//            }
//            log.debug("New session created for token '{}' since the original session has been expired", tokenMasker.maskToken(tokenValue));
//        }

        if (session != null) {
//            serverTokenStore.putSessionInfo(tokenValue, new RestUserSessionInfo(session));
            AppContext.setSecurityContext(new SecurityContext(session));
        }
    }
}
