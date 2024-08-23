package com.sysnote8.misskeycloakidp.provider.miauth;

import com.sysnote8.misskeycloakidp.provider.MisskeyOAuthIdentityProvider;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

public class MiAuthIdentityProviderFactory extends AbstractIdentityProviderFactory<MiAuthIdentityProvider> implements SocialIdentityProviderFactory<MiAuthIdentityProvider> {
    public static final String PROVIDER_ID = "misskey-miauth";

    @Override
    public String getName() {
        return "Misskey(MiAuth)";
    }

    @Override
    public MiAuthIdentityProvider create(KeycloakSession keycloakSession, IdentityProviderModel identityProviderModel) {
        return new MiAuthIdentityProvider(keycloakSession, new MiAuthIdentityProviderConfig(identityProviderModel));
    }

    @Override
    public IdentityProviderModel createConfig() {
        return new MiAuthIdentityProviderConfig();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        // TODO check this
        return ProviderConfigurationBuilder.create()
                .property()
                    .name("applicationName")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .label("Application Name")
                    .add()
                .property()
                    .name("applicationIcon")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .label("Application Icon")
                    .add()
                .build();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
