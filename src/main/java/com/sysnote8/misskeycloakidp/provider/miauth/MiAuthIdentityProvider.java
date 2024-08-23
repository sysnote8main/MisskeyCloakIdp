package com.sysnote8.misskeycloakidp.provider.miauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.io.IOException;
import java.net.URI;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MiAuthIdentityProvider extends AbstractIdentityProvider<MiAuthIdentityProviderConfig> implements SocialIdentityProvider<MiAuthIdentityProviderConfig> {
    protected static final Logger logger = Logger.getLogger(MiAuthIdentityProvider.class);
    // Message Id
    public static final String IDENTITY_PROVIDER_MISSING_SESSION_ERROR = "identityProviderMissingSessionMessage";

    // Parameters
    public static final String MIAUTH_PARAMETER_NAME = "name";
    public static final String MIAUTH_PARAMETER_ICON = "icon";
    public static final String MIAUTH_PARAMETER_CALLBACK = "callback";
    public static final String MIAUTH_PARAMETER_PERMISSION = "permission";
    public static final String MIAUTH_PARAMETER_SESSION = "session";
    public static final String MIAUTH_PARAMETER_TOKEN = "token";

    // Settings
    public static final String HOST = "https://misskey.systems";
    public static final String AUTH_FRAGMENT = "/miauth/%s";
    public static final String TOKEN_FRAGMENT = "/api/miauth/%s/check";
    public static final String PROFILE_FRAGMENT = "/api/i";
    public static final String AUTH_URL = HOST + AUTH_FRAGMENT;
    public static final String TOKEN_URL = HOST + TOKEN_FRAGMENT;
    public static final String PROFILE_URL = HOST + PROFILE_FRAGMENT;
    public static final String DEFAULT_PERMISSION = "read:account";

    // Json Mapper
    protected static ObjectMapper mapper = new ObjectMapper();

    public MiAuthIdentityProvider(KeycloakSession session, MiAuthIdentityProviderConfig config) {
        super(session, config);
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new Endpoint(callback, realm, event, this);
    }

    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        return UriBuilder.fromUri(String.format(AUTH_URL, UUID.randomUUID()))
                .queryParam(MIAUTH_PARAMETER_NAME, getConfig().getApplicationName())
                .queryParam(MIAUTH_PARAMETER_ICON, getConfig().getApplicationIcon())
                .queryParam(MIAUTH_PARAMETER_CALLBACK, request.getRedirectUri())
                .queryParam(MIAUTH_PARAMETER_PERMISSION, DEFAULT_PERMISSION);
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        try {
            URI authorizationUrl = createAuthorizationUrl(request).build();

            return Response.seeOther(authorizationUrl).build();
        } catch (Exception e) {
            throw new IdentityBrokerException("Failed to create authentication request.", e);
        }
    }

    @Override
    public Response retrieveToken(KeycloakSession keycloakSession, FederatedIdentityModel federatedIdentityModel) {
        return Response.ok(federatedIdentityModel.getToken()).type(MediaType.APPLICATION_JSON).build();
    }

    @Override
    public MiAuthIdentityProviderConfig getConfig() {
        return super.getConfig();
    }

    // exchangeFromToken implements ExchangeTokenToIdentityProviderToken, ExchangeExternalToken
    // isIssuer
    // exchangeExternalComplete

    @Override
    public void authenticationFinished(AuthenticationSessionModel authSession, BrokeredIdentityContext context) {
        String token = (String) context.getContextData().get(FEDERATED_ACCESS_TOKEN);
        if (token != null) authSession.setUserSessionNote(FEDERATED_ACCESS_TOKEN, token);
    }

    protected String extractTokenFromResponse(String response, String tokenName) {
        if(response == null)
            return null;

        if (response.startsWith("{")) {
            try {
                JsonNode node = mapper.readTree(response);
                if(node.has(tokenName)){
                    String s = node.get(tokenName).textValue();
                    if(s == null || s.trim().isEmpty())
                        return null;
                    return s;
                } else {
                    return null;
                }
            } catch (IOException e) {
                throw new IdentityBrokerException("Could not extract token [" + tokenName + "] from response [" + response + "] due: " + e.getMessage(), e);
            }
        } else {
            Matcher matcher = Pattern.compile(tokenName + "=([^&]+)").matcher(response);

            if (matcher.find()) {
                return matcher.group(1);
            }
        }

        return null;
    }

    public String getJsonProperty(JsonNode jsonNode, String name) {
        if (jsonNode.has(name) && !jsonNode.get(name).isNull()) {
            String s = jsonNode.get(name).asText();
            if(s != null && !s.isEmpty())
                return s;
            else
                return null;
        }

        return null;
    }

    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        BrokeredIdentityContext user = new BrokeredIdentityContext(getJsonProperty(profile, "id"), getConfig());

        String username = getJsonProperty(profile, "username");
        user.setUsername(username);
        user.setEmail(getJsonProperty(profile, "email"));
        user.setIdp(this);

        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());

        return user;
    }

    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        try (SimpleHttp.Response response = SimpleHttp.doGet(PROFILE_URL, session)
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .asResponse()) {
            if (Response.Status.fromStatusCode(response.getStatus()).getFamily() != Response.Status.Family.SUCCESSFUL) {
                logger.warnf("Profile endpoint returned an error (%d): %s", response.getStatus(), response.asString());
                throw new IdentityBrokerException("Profile could not be retrieved from the misskey");
            }

            JsonNode profile = response.asJson();
            logger.tracef("Retrieved profile from misskey: %s", profile);
            BrokeredIdentityContext user = extractIdentityFromProfile(null, profile);

            if (user.getEmail() == null) {
                // TODO check this
                user.setEmail("");
            }

            return user;
        } catch (Exception e) {
            throw new IdentityBrokerException("Failed to retrieve profile from misskey", e);
        }
    }

    public BrokeredIdentityContext getFederatedIdentity(String response) {
        String accessToken = extractTokenFromResponse(response, MIAUTH_PARAMETER_TOKEN);

        if (accessToken == null) {
            throw new IdentityBrokerException("Access token is not found in server response: " + response);
        }

        BrokeredIdentityContext context = doGetFederatedIdentity(accessToken);
        context.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);
        return context;
    }

    protected static class Endpoint {
        protected final AuthenticationCallback callback;
        protected final RealmModel realm;
        protected final EventBuilder event;
        private final MiAuthIdentityProvider provider;

        protected final KeycloakSession session;

        protected final ClientConnection clientConnection;

        protected final HttpHeaders headers;

        protected final HttpRequest httpRequest;

        public Endpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event, MiAuthIdentityProvider provider) {
            this.callback = callback;
            this.realm = realm;
            this.event = event;
            this.provider = provider;
            this.session = provider.session;
            this.clientConnection = session.getContext().getConnection();
            this.httpRequest = session.getContext().getHttpRequest();
            this.headers = session.getContext().getRequestHeaders();
        }

        @GET
        public Response authResponse(@QueryParam(MiAuthIdentityProvider.MIAUTH_PARAMETER_SESSION) String sessionId) {
            MiAuthIdentityProviderConfig providerConfig = provider.getConfig();

            if (session == null) {
                logError("Redirection URL has no session parameter", providerConfig);
                return errorIdpLogin(IDENTITY_PROVIDER_MISSING_SESSION_ERROR);
            }

            try {
                SimpleHttp simpleHttp = generateTokenRequest(sessionId);
                String response;
                try (SimpleHttp.Response simpleResponse = simpleHttp.asResponse()) {
                    int status = simpleResponse.getStatus();
                    boolean success = status >= 200 && status < 400;
                    response = simpleResponse.asString();

                    if (!success) {
                        logger.errorf("Unexpected response from token endpoint %s. status=%s, response=%s",
                                simpleHttp.getUrl(), status, response);
                        return errorIdpLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                    }
                }

                BrokeredIdentityContext federatedIdentity = provider.getFederatedIdentity(response);
                if (providerConfig.isStoreToken()) {
                    if (federatedIdentity.getToken() == null) federatedIdentity.setToken(response);
                }

                federatedIdentity.setIdp(provider);
                // federatedIdentity.setAuthenticationSession(authSession);

                return callback.authenticated(federatedIdentity);
            } catch (WebApplicationException e) {
                return e.getResponse();
            } catch (IdentityBrokerException e) {
                if (e.getMessageCode() != null) {
                    return errorIdpLogin(e.getMessageCode());
                }
                logger.error("Failed to make identity provider oauth callback", e);
                return errorIdpLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            } catch (Exception e) {
                logger.error("Failed to make identity provider oauth callback", e);
                return errorIdpLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            }
        }

        public SimpleHttp generateTokenRequest(String sessionId) {
            String requestTargetUrl = String.format(TOKEN_URL, sessionId);
            return SimpleHttp.doPost(requestTargetUrl, session);
        }

        private void logError(String msg, MiAuthIdentityProviderConfig providerConfig) {
            String providerId = providerConfig.getProviderId();
            String redirectionUrl = session.getContext().getUri().getRequestUri().toString();

            logger.errorf("%s. providerId=%s, redirectionUrl=%s", msg, providerId, redirectionUrl);
        }

        private Response errorIdpLogin(String msg) {
            event.event(EventType.IDENTITY_PROVIDER_LOGIN);
            event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
            return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY, msg);
        }
    }
}
