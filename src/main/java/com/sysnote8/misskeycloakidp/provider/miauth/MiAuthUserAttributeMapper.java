package com.sysnote8.misskeycloakidp.provider.miauth;

import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;

public class MiAuthUserAttributeMapper extends AbstractJsonUserAttributeMapper {
    private static final String[] compatibleProviderList = new String[]{MiAuthIdentityProviderFactory.PROVIDER_ID};

    @Override
    public String[] getCompatibleProviders() {
        return compatibleProviderList;
    }

    @Override
    public String getId() {
        return "misskey-miauth-user-attribute-mapper";
    }
}
