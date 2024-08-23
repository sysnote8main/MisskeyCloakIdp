package com.sysnote8.misskeycloakidp.provider;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

public class MisskeyOAuthIdentityProviderConfig extends OAuth2IdentityProviderConfig {
    public MisskeyOAuthIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public MisskeyOAuthIdentityProviderConfig() {}

    public String getAllowedServers() {
        return this.getConfig().get("allowedServers");
    }

    public void setAllowedServers(String allowedServers) {
        this.getConfig().put("allowedServers", allowedServers);
    }

    public boolean hasAllowedServers() {
        String servers = getConfig().get("allowedServers");
        return servers != null && !servers.trim().isEmpty();
    }

    public Set<String> getAllowedServersAsSet() {
        if (hasAllowedServers()) {
            String servers = getConfig().get("allowedServers");
            return Arrays.stream(servers.split(",")).map(String::trim).collect(Collectors.toSet());
        }
        return Collections.emptySet();
    }
}
