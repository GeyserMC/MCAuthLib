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
    private String microsoftAccessToken;

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
     * Triggers the <a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code">Device Code flow</a> for Microsoft Account authentication.
     * <p>
     * The provided <code>consumer</code> will be called when Azure is ready for the user to authenticate. Your consumer
     * should somehow get the user to authenticate with the provided URL and user code. How this is implemented is up to
     * you. MSAL automatically handles waiting for the user to authenticate.
     *
     * @param consumer To be called when Azure wants the user to sign in. This involves showing the user the URL to open and the code to enter.
     */
    public void getDeviceCode(Consumer<DeviceCode> consumer) throws ExecutionException, InterruptedException, MalformedURLException {
        // Find account to re-authenticate from cache
        IAccount account = app.getAccounts().join().stream()
                .filter((a) -> a.username().equalsIgnoreCase(this.getUsername()))
                .findFirst().orElse(null);

        // Log in with either device code or silently with cached account
        CompletableFuture<IAuthenticationResult> accessTokenFuture = (account != null
                ? app.acquireTokenSilently(SilentParameters.builder(scopes, account).build())
                : app.acquireToken(DeviceCodeFlowParameters.builder(scopes, consumer).build()));

        // Wait for the access token
        this.microsoftAccessToken = accessTokenFuture.get().accessToken();
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
        // Get an access token for the Minecraft session
        this.accessToken = MsaAuthenticationService.getLoginResponseFromToken("d=".concat(this.microsoftAccessToken), this.getProxy()).access_token;

        // Get the profile to complete the login process
        getProfile();

        this.loggedIn = true;
    }
}
