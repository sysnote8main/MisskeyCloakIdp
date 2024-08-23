package com.sysnote8.misskeycloakidp.provider;

import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;

public class MisskeyOAuthUserAttributeMapper extends AbstractJsonUserAttributeMapper {
    private static final String[] compatibleProviderList = new String[]{MisskeyOAuthIdentityProviderFactory.PROVIDER_ID};

    @Override
    public String[] getCompatibleProviders() {
        return compatibleProviderList;
    }

    @Override
    public String getId() {
        return "misske-oauth-user-attribute-mapper";
    }
}
