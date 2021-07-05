package com.company.oauth.config;

import com.haulmont.cuba.core.config.Config;
import com.haulmont.cuba.core.config.Source;
import com.haulmont.cuba.core.config.SourceType;
import com.haulmont.cuba.core.config.defaults.DefaultString;

@Source(type = SourceType.APP)
public interface KeyCloakClientRegistrationConfig extends Config {

    @DefaultString("keycloakRegistrationId")
    String getKeyCloakClientRegistrationId();
}
