package com.github.steveice10.mc.auth.service;

import com.github.steveice10.mc.auth.data.GameProfile;
import com.github.steveice10.mc.auth.exception.request.RequestException;
import com.github.steveice10.mc.auth.util.HTTP;
import com.github.steveice10.mc.auth.util.MSALTokenPersistence;
import com.microsoft.aad.msal4j.*;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;

public class MSALAuthenticationService extends AuthenticationService {
    private static final String DEFAULT_AUTHORITY = "https://login.microsoftonline.com/consumers/";
    private static final String XBOX_SIGNIN_SCOPE = "XboxLive.signin";
    private static final String XBOX_OFFLINE_SCOPE = XBOX_SIGNIN_SCOPE.concat(" offline_access");

    private final Set<String> scopes;
    private final PublicClientApplication app;
    private Consumer<DeviceCode> deviceCodeConsumer;

    /**
     * Creates a <code>MSALAuthenticationService</code>. Uses default authority and sign in scope (no offline access).
     */
    public MSALAuthenticationService(String clientId) throws IOException {
        this(clientId, DEFAULT_AUTHORITY);
    }

    /**
     * Creates a <code>MSALAuthenticationService</code>. Uses default authority.
     */
    public MSALAuthenticationService(String clientId, boolean offlineAccess) throws IOException {
        this(clientId, offlineAccess, DEFAULT_AUTHORITY);
    }

    /**
     * Creates a <code>MSALAuthenticationService</code>. Uses default sign in scope (no offline access).
     */
    public MSALAuthenticationService(String clientId, String authority) throws IOException {
        this(clientId, false, authority);
    }

    /**
     * Creates a <code>MSALAuthenticationService</code>.
     */
    public MSALAuthenticationService(String clientId, boolean offlineAccess, String authority) throws IOException {
        this(clientId, offlineAccess, authority, new MSALTokenPersistence());
    }

    /**
     * Creates a <code>MSALAuthenticationService</code> with custom {@link ITokenCacheAccessAspect}. If not provided, {@link MSALTokenPersistence} is used.
     *
     * @see <a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/msal-java-token-cache-serialization">Custom token cache serialization in MSAL for Java</a>
     */
    public MSALAuthenticationService(String clientId, boolean offlineAccess, String authority, ITokenCacheAccessAspect tokenCacheAccessAspect) throws IOException {
        super(URI.create(""));
        this.scopes = new HashSet<>(Arrays.asList((offlineAccess ? XBOX_OFFLINE_SCOPE : XBOX_SIGNIN_SCOPE).split(" ")));

        // Create MSAL client
        this.app = PublicClientApplication.builder(clientId)
                .authority(authority)
                .setTokenCacheAccessAspect(tokenCacheAccessAspect)
                .build();
    }

    /**
     * Sets the function to run when a <a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code">Device Code flow</a> is requested.
     * <p>
     * The provided <code>consumer</code> will be called when Azure is ready for the user to authenticate. Your consumer
     * should somehow get the user to authenticate with the provided URL and user code. How this is implemented is up to
     * you. MSAL automatically handles waiting for the user to authenticate.
     *
     * @param consumer To be called when Azure wants the user to sign in. This involves showing the user the URL to open and the code to enter.
     */
    public void setDeviceCodeConsumer(Consumer<DeviceCode> consumer) {
        this.deviceCodeConsumer = consumer;
    }

    /**
     * Authenticates the user using Device Code flow.
     */
    private IAuthenticationResult getAccessTokenWithDeviceCode() throws MalformedURLException, ExecutionException, InterruptedException {
        return getAccessToken(null, DeviceCodeFlowParameters.builder(scopes, this.deviceCodeConsumer).build()).get();
    }

    /**
     * Authenticates the user using credentials (username and password).
     */
    private IAuthenticationResult getAccessTokenWithCredentials(String username, String password) throws MalformedURLException, ExecutionException, InterruptedException {
        return getAccessToken(UserNamePasswordParameters.builder(scopes, username, password.toCharArray()).build(), null).get();
    }

    /**
     * Get an <code>IAccount</code> from the cache (if available) for re-authentication.
     *
     * @return An <code>IAccount</code> matching the username given to this <code>MSALAuthenticationService</code>
     */
    private IAccount getIAccount() {
        return app.getAccounts().join().stream()
                .filter(account -> account.username().equalsIgnoreCase(this.getUsername()))
                .findFirst().orElse(null);
    }

    /**
     * Wrapper for silent, credential, and device code flows. <strong>Either</strong> parameter can be null, but <strong>not</strong> both.
     * @param userPassParams Parameters to use for username/password authentication.
     * @param deviceCodeParams Parameters to use for device code authentication.
     */
    private CompletableFuture<IAuthenticationResult> getAccessToken(UserNamePasswordParameters userPassParams, DeviceCodeFlowParameters deviceCodeParams) throws MalformedURLException {
        IAccount account = getIAccount();

        if (account == null)
            return (deviceCodeParams != null) ? app.acquireToken(deviceCodeParams) : app.acquireToken(userPassParams);
        else return app.acquireTokenSilently(SilentParameters.builder(scopes, account).build());
    }

    /**
     * Finalizes the authentication process using Xbox API's.
     */
    private void getProfile() throws RequestException {
        MsaAuthenticationService.McProfileResponse response = HTTP.makeRequest(this.getProxy(),
                MsaAuthenticationService.MC_PROFILE_ENDPOINT,
                null,
                MsaAuthenticationService.McProfileResponse.class,
                Collections.singletonMap("Authorization", "Bearer " + this.accessToken));

        assert response != null;

        this.selectedProfile = new GameProfile(response.id, response.name);
        this.profiles = Collections.singletonList(this.selectedProfile);
        this.username = response.name;
    }

    @Override
    public void login() throws RequestException {
        try {
            // Get access token for users Microsoft account
            String microsoftAccessToken = (this.password != null && !this.password.isEmpty())
                    ? this.getAccessTokenWithCredentials(this.username, this.password).accessToken()
                    : this.getAccessTokenWithDeviceCode().accessToken();

            // Get an access token for the Minecraft session
            this.accessToken = MsaAuthenticationService.getLoginResponseFromToken(
                    "d=".concat(microsoftAccessToken), this.getProxy()).access_token;

            // Get the profile to complete the login process
            getProfile();

            this.loggedIn = true;
        } catch (MalformedURLException | ExecutionException | InterruptedException ex) {
            throw new RequestException(ex);
        }
    }
}
