package com.company.oauth.config;

import com.haulmont.cuba.core.config.Config;
import com.haulmont.cuba.core.config.Source;
import com.haulmont.cuba.core.config.SourceType;
import com.haulmont.cuba.core.config.defaults.DefaultBoolean;
import com.haulmont.cuba.core.config.defaults.DefaultString;

@Source(type = SourceType.APP)
public interface KeyCloakResourceServerConfig extends Config {

    @DefaultBoolean(false)
    Boolean getEnableMakingSession();

    @DefaultBoolean(false)
    Boolean getEnableUserRegistration();

    @DefaultString("preferred_username")
    String getLoginClaim();
}
