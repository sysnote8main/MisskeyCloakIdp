package com.sysnote8.misskeycloakidp.provider;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.ErrorPageException;
import org.keycloak.services.messages.Messages;

public class MisskeyOAuthIdentityProvider extends AbstractOAuth2IdentityProvider<MisskeyOAuthIdentityProviderConfig> implements SocialIdentityProvider<MisskeyOAuthIdentityProviderConfig> {
    private static final Logger logger = Logger.getLogger(MisskeyOAuthIdentityProvider.class);

    public static final String HOST = "misskey.systems";
    public static final String DEFAULT_BASE_URL = "https://" + HOST;
    public static final String AUTH_FRAGMENT = "/oauth/authorize";
    public static final String TOKEN_FRAGMENT = "/oauth/token";
    public static final String PROFILE_FRAGMENT = "/api/i";
    public static final String AUTH_URL = DEFAULT_BASE_URL + AUTH_FRAGMENT;
    public static final String TOKEN_URL = DEFAULT_BASE_URL + TOKEN_FRAGMENT;
    public static final String PROFILE_URL = DEFAULT_BASE_URL + PROFILE_FRAGMENT;
    public static final String DEFAULT_SCOPE = "read:account";

    public MisskeyOAuthIdentityProvider(KeycloakSession session, MisskeyOAuthIdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        config.setUserInfoUrl(PROFILE_URL);
        config.setPkceEnabled(true);
        config.setPkceMethod("S256");
    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    @Override
    protected String getProfileEndpointForValidation(EventBuilder event) {
        return PROFILE_URL;
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode node) {
        BrokeredIdentityContext user = new BrokeredIdentityContext(getJsonProperty(node, "id"), getConfig());
        user.setUsername(getJsonProperty(node, "username"));
//        user.setEmail(getJsonProperty(node, "email"));
        user.setIdp(this);

        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, node, getConfig().getAlias());

        return user;
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        logger.debug("doGetFederatedIdentity()");
        JsonNode profile;
        try {
            profile = SimpleHttp.doGet(PROFILE_URL, session).header("Authorization", "Bearer " + accessToken).asJson();
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not get user profile from misskey.", e);
        }

        if (getConfig().hasAllowedServers()) {
            if (!isAllowedServer(profile.get("host").textValue())) {
                throw new ErrorPageException(session, Response.Status.FORBIDDEN, Messages.INVALID_REQUESTER);
            }
        }
        return extractIdentityFromProfile(null, profile);
    }

    protected boolean isAllowedServer(String host) {
        if (host == null) host = HOST;
        return getConfig().getAllowedServersAsSet().contains(host);
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }
}
