package com.sysnote8.misskeycloakidp.provider.miauth;

import org.keycloak.models.IdentityProviderModel;

public class MiAuthIdentityProviderConfig extends IdentityProviderModel {
    public MiAuthIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public MiAuthIdentityProviderConfig() {
        super();
    }

    public String getApplicationName() {
        return this.getConfig().get("applicationName");
    }

    public void setApplicationName(String applicationName) {
        this.getConfig().put("applicationName", applicationName);
    }

    public String getApplicationIcon() {
        return this.getConfig().get("applicationIcon");
    }

    public void setApplicationIcon(String applicationIcon) {
        this.getConfig().put("applicationIcon", applicationIcon);
    }
}
