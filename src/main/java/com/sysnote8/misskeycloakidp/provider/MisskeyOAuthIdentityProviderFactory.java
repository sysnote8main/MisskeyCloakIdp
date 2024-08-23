package com.sysnote8.misskeycloakidp.provider;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

public class MisskeyOAuthIdentityProviderFactory extends AbstractIdentityProviderFactory<MisskeyOAuthIdentityProvider> implements SocialIdentityProviderFactory<MisskeyOAuthIdentityProvider> {
    public static final String PROVIDER_ID = "misskey-oauth";

    @Override
    public String getName() {
        return "Misskey(OAuth)";
    }

    @Override
    public MisskeyOAuthIdentityProvider create(KeycloakSession keycloakSession, IdentityProviderModel identityProviderModel) {
        return new MisskeyOAuthIdentityProvider(keycloakSession, new MisskeyOAuthIdentityProviderConfig(identityProviderModel));
    }

    @Override
    public IdentityProviderModel createConfig() {
        return new MisskeyOAuthIdentityProviderConfig();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name("allowedServers")
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("Instance hosts to allow federation")
                .helpText("Please use a comma to separate multiple server hosts")
                .add()
                .build();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
