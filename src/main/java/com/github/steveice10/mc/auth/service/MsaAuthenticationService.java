package com.github.steveice10.mc.auth.service;

import com.github.steveice10.mc.auth.data.GameProfile;
import com.github.steveice10.mc.auth.exception.request.InvalidCredentialsException;
import com.github.steveice10.mc.auth.exception.request.RequestException;
import com.github.steveice10.mc.auth.exception.request.ServiceUnavailableException;
import com.github.steveice10.mc.auth.exception.request.XboxRequestException;
import com.github.steveice10.mc.auth.util.HTTP;
import com.github.steveice10.mc.auth.util.MSALApplicationOptions;
import com.microsoft.aad.msal4j.*;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MsaAuthenticationService extends AuthenticationService {
    /**
     * This ID is Microsoft's official Xbox app ID. It will bypass the OAuth grant permission prompts, and also allows
     * child accounts to authenticate. These are not something developers are able to do in custom Azure applications.
     */
    public static final String MINECRAFT_CLIENT_ID = "00000000402b5328";

    private static final URI MS_LOGIN_ENDPOINT = URI.create(String.format("https://login.live.com/oauth20_authorize.srf?redirect_uri=https://login.live.com/oauth20_desktop.srf&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=code&locale=en&client_id=%s", MINECRAFT_CLIENT_ID));
    private static final URI MS_TOKEN_ENDPOINT = URI.create("https://login.live.com/oauth20_token.srf");
    private static final URI XBL_AUTH_ENDPOINT = URI.create("https://user.auth.xboxlive.com/user/authenticate");
    private static final URI XSTS_AUTH_ENDPOINT = URI.create("https://xsts.auth.xboxlive.com/xsts/authorize");
    private static final URI MC_LOGIN_ENDPOINT = URI.create("https://api.minecraftservices.com/authentication/login_with_xbox");
    private static final URI MC_PROFILE_ENDPOINT = URI.create("https://api.minecraftservices.com/minecraft/profile");
    private static final Pattern PPFT_PATTERN = Pattern.compile("sFTTag:[ ]?'.*value=\"(.*)\"/>'");
    private static final Pattern URL_POST_PATTERN = Pattern.compile("urlPost:[ ]?'(.+?(?='))");
    private static final Pattern CODE_PATTERN = Pattern.compile("[?|&]code=([\\w.-]+)");

    private final Set<String> scopes;
    private final PublicClientApplication app;

    private String clientId;
    private String refreshToken;
    private Consumer<DeviceCode> deviceCodeConsumer;

    public MsaAuthenticationService(String clientId) throws IOException {
        this(clientId, new MSALApplicationOptions.Builder().build());
    }

    public MsaAuthenticationService(String clientId, MSALApplicationOptions msalOptions) throws MalformedURLException {
        // Create the default MSAL client
        this(clientId, msalOptions.scopes, PublicClientApplication.builder(clientId)
                .authority(msalOptions.authority)
                .setTokenCacheAccessAspect(msalOptions.tokenPersistence)
                .build());
    }

    public MsaAuthenticationService(String clientId, Set<String> scopes, PublicClientApplication app) {
        super(URI.create(""));

        if (clientId == null || clientId.isEmpty())
            throw new IllegalArgumentException("clientId cannot be null or empty.");

        this.clientId = clientId;
        this.scopes = scopes;
        this.app = app;
    }

    /**
     * Gets the current refresh token for this session
     */
    public String getRefreshToken() {
        return this.refreshToken;
    }

    /**
     * Sets a new refresh token. Useful for re-authenticating from device code authorizations.
     * @param refreshToken The refresh token to set
     */
    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
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

    private McLoginResponse getLoginResponseFromCreds() throws RequestException {
        // TODO: Migrate alot of this to {@link HTTP}

        String cookie = "";
        String PPFT = "";
        String urlPost = "";

        try {
            HttpURLConnection connection = HTTP.createUrlConnection(this.getProxy(), MS_LOGIN_ENDPOINT);
            connection.setDoInput(true);
            try (InputStream in = connection.getResponseCode() == 200 ? connection.getInputStream() : connection.getErrorStream()) {
                cookie = connection.getHeaderField("set-cookie");
                String body = inputStreamToString(in);
                Matcher m = PPFT_PATTERN.matcher(body);
                if (m.find()) {
                    PPFT = m.group(1);
                } else {
                    throw new ServiceUnavailableException("Could not parse response of '" + MS_LOGIN_ENDPOINT + "'.");
                }

                m = URL_POST_PATTERN.matcher(body);
                if (m.find()) {
                    urlPost = m.group(1);
                } else {
                    throw new ServiceUnavailableException("Could not parse response of '" + MS_LOGIN_ENDPOINT + "'.");
                }
            }
        } catch (IOException e) {
            throw new ServiceUnavailableException("Could not make request to '" + MS_LOGIN_ENDPOINT + "'.", e);
        }

        if (cookie.isEmpty() || PPFT.isEmpty() || urlPost.isEmpty()) {
            throw new RequestException("Invalid response from '" + MS_LOGIN_ENDPOINT + "' missing one or more of cookie, PPFT or urlPost");
        }

        Map<String, String> map = new HashMap<>();

        map.put("login", this.username);
        map.put("loginfmt", this.username);
        map.put("passwd", this.password);
        map.put("PPFT", PPFT);

        String postData = HTTP.formMapToString(map);
        String code;

        try {
            byte[] bytes = postData.getBytes(StandardCharsets.UTF_8);

            HttpURLConnection connection = HTTP.createUrlConnection(this.getProxy(), URI.create(urlPost));
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
            connection.setRequestProperty("Content-Length", String.valueOf(bytes.length));
            connection.setRequestProperty("Cookie", cookie);

            connection.setDoInput(true);
            connection.setDoOutput(true);

            try(OutputStream out = connection.getOutputStream()) {
                out.write(bytes);
            }

            if (connection.getResponseCode() != 200 || connection.getURL().toString().equals(urlPost)) {
                // TODO: Get and parse the error from the site
                // See https://github.com/XboxReplay/xboxlive-auth/blob/master/src/core/live/index.ts#L115
                throw new InvalidCredentialsException("Invalid username and/or password");
            }

            Matcher m = CODE_PATTERN.matcher(URLDecoder.decode(connection.getURL().toString(), StandardCharsets.UTF_8.name()));
            if (m.find()) {
                code = m.group(1);
            } else {
                throw new ServiceUnavailableException("Could not parse response of '" + urlPost + "'.");
            }
        } catch (IOException e) {
            throw new ServiceUnavailableException("Could not make request to '" + urlPost + "'.", e);
        }

        MsTokenRequest request = new MsTokenRequest(clientId, code);
        MsTokenResponse response = HTTP.makeRequestForm(this.getProxy(), MS_TOKEN_ENDPOINT, request.toMap(), MsTokenResponse.class);
        assert response != null;
        this.refreshToken = response.refresh_token;
        return this.getLoginResponseFromToken(response.access_token);
    }

    private String inputStreamToString(InputStream inputStream) throws IOException {
        StringBuilder textBuilder = new StringBuilder();
        try (Reader reader = new BufferedReader(new InputStreamReader(inputStream, Charset.forName(StandardCharsets.UTF_8.name())))) {
            int c = 0;
            while ((c = reader.read()) != -1) {
                textBuilder.append((char) c);
            }
        }

        return textBuilder.toString();
    }

    /**
     * Refreshes the access token and refresh token for further use
     *
     * @return The response containing the refresh token, so the user can store it for later use.
     */
    public MsTokenResponse refreshToken() throws RequestException {
        if (this.refreshToken == null || this.refreshToken.isEmpty())
            throw new InvalidCredentialsException("Invalid refresh token.");

        MsTokenResponse response = HTTP.makeRequestForm(this.getProxy(), MS_TOKEN_ENDPOINT, new MsRefreshRequest(clientId, refreshToken).toMap(), MsTokenResponse.class);

        assert response != null;
        accessToken = response.access_token;
        refreshToken = response.refresh_token;

        return response;
    }

    /**
     * Get an <code>IAccount</code> from the cache (if available) for re-authentication.
     *
     * @return An <code>IAccount</code> matching the username given to this <code>MSALAuthenticationService</code>
     */
    private IAccount getIAccount() {
        return this.app.getAccounts().join().stream()
                .filter(account -> account.username().equalsIgnoreCase(this.getUsername()))
                .findFirst().orElse(null);
    }

    /**
     * Get an access token from MSAL using Device Code flow authentication.
     */
    private CompletableFuture<IAuthenticationResult> getMsalAccessToken() throws MalformedURLException {
        if (this.deviceCodeConsumer == null)
            throw new IllegalStateException("Device code consumer is not set.");

        IAccount account = this.getIAccount();
        if (account == null)
            return this.app.acquireToken(DeviceCodeFlowParameters.builder(this.scopes, this.deviceCodeConsumer).build());
        else return this.app.acquireTokenSilently(SilentParameters.builder(this.scopes, account).build());
    }

    /**
     * Attempt to sign in using an existing refresh token set by {@link #setRefreshToken(String)}
     */
    private McLoginResponse getLoginResponseFromRefreshToken() throws RequestException {
        return this.getLoginResponseFromToken("d=".concat(this.refreshToken().access_token));
    }

    /**
     * Get a Minecraft login response from the given
     * Microsoft access token
     *
     * @param accessToken the access token
     * @return The Minecraft login response
     */
    private McLoginResponse getLoginResponseFromToken(String accessToken) throws RequestException {
        XblAuthRequest xblRequest = new XblAuthRequest(accessToken);
        XblAuthResponse response = HTTP.makeRequest(this.getProxy(), XBL_AUTH_ENDPOINT, xblRequest, XblAuthResponse.class);

        XstsAuthRequest xstsRequest = new XstsAuthRequest(response.Token);
        response = HTTP.makeRequest(this.getProxy(), XSTS_AUTH_ENDPOINT, xstsRequest, XblAuthResponse.class);

        if (response.XErr != 0) {
            if (response.XErr == 2148916233L) {
                throw new XboxRequestException("Microsoft account does not have an Xbox Live account attached!");
            } else if (response.XErr == 2148916235L) {
                throw new XboxRequestException("Xbox Live is not available in your country!");
            } else if (response.XErr == 2148916238L) {
                throw new XboxRequestException("This account is a child account! Please add it to a family in order to log in.");
            } else {
                throw new XboxRequestException("Error occurred while authenticating to Xbox Live! Error ID: " + response.XErr);
            }
        }

        McLoginRequest mcRequest = new McLoginRequest(response.DisplayClaims.xui[0].uhs, response.Token);
        return HTTP.makeRequest(this.getProxy(), MC_LOGIN_ENDPOINT, mcRequest, McLoginResponse.class);
    }

    /**
     * Finalizes the authentication process using Xbox API's.
     */
    private void getProfile() throws RequestException {
        McProfileResponse response = HTTP.makeRequest(this.getProxy(),
                MC_PROFILE_ENDPOINT,
                null,
                McProfileResponse.class,
                Collections.singletonMap("Authorization", "Bearer ".concat(this.accessToken)));

        assert response != null;
        this.selectedProfile = new GameProfile(response.id, response.name);
        this.profiles = Collections.singletonList(this.selectedProfile);
        this.username = response.name;
    }

    @Override
    public void login() throws RequestException {
        try {
            boolean password = this.password != null && !this.password.isEmpty();
            boolean refresh = this.refreshToken != null && !this.refreshToken.isEmpty();

            // Complain if the username is not set
            if (this.username == null || this.username.isEmpty())
                throw new InvalidCredentialsException("Invalid username.");

            // Fix client ID if a password is set
            if (password)
                this.clientId = MINECRAFT_CLIENT_ID;

            McLoginResponse response = refresh ? this.getLoginResponseFromRefreshToken()
                    : password ? this.getLoginResponseFromCreds()
                    : this.getLoginResponseFromToken("d=".concat(this.getMsalAccessToken().get().accessToken()));

            if (response == null)
                throw new RequestException("Invalid response received.");
            this.accessToken = response.access_token;

            // Get the profile to complete the login process
            this.getProfile();

            this.loggedIn = true;
        } catch (MalformedURLException | ExecutionException | InterruptedException ex) {
            throw new RequestException(ex);
        }
    }

    @Override
    public void logout() throws RequestException {
        super.logout();
        this.clientId = null;
    }

    @Override
    public String toString() {
        return "MsaAuthenticationService{" +
                "clientId='" + this.clientId + '\'' +
                ", accessToken='" + this.accessToken + '\'' +
                ", loggedIn=" + this.loggedIn +
                ", username='" + this.username + '\'' +
                ", password='" + this.password + '\'' +
                ", selectedProfile=" + this.selectedProfile +
                ", properties=" + this.properties +
                ", profiles=" + this.profiles +
                '}';
    }

    private static class MsTokenRequest {
        private String client_id;
        private String code;
        private String grant_type;
        private String redirect_uri;
        private String scope;

        protected MsTokenRequest(String clientId, String code) {
            this.client_id = clientId;
            this.code = code;
            this.grant_type = "authorization_code";
            this.redirect_uri = "https://login.live.com/oauth20_desktop.srf";
            this.scope = "service::user.auth.xboxlive.com::MBI_SSL";
        }

        public Map<String, String> toMap() {
            Map<String, String> map = new HashMap<>();

            map.put("client_id", client_id);
            map.put("code", code);
            map.put("grant_type", grant_type);
            map.put("redirect_uri", redirect_uri);
            map.put("scope", scope);

            return map;
        }
    }

    private static class MsRefreshRequest {
        private String client_id;
        private String refresh_token;
        private String grant_type;

        protected MsRefreshRequest(String clientId, String refreshToken) {
            this.client_id = clientId;
            this.refresh_token = refreshToken;
            this.grant_type = "refresh_token";
        }

        public Map<String, String> toMap() {
            Map<String, String> map = new HashMap<>();

            map.put("client_id", client_id);
            map.put("refresh_token", refresh_token);
            map.put("grant_type", grant_type);

            return map;
        }
    }

    private static class XblAuthRequest {
        private String RelyingParty;
        private String TokenType;
        private Properties Properties;

        protected XblAuthRequest(String accessToken) {
            this.RelyingParty = "http://auth.xboxlive.com";
            this.TokenType = "JWT";
            this.Properties = new Properties(accessToken);
        }

        private static class Properties {
            private String AuthMethod;
            private String SiteName;
            private String RpsTicket;

            protected Properties(String accessToken) {
                this.AuthMethod = "RPS";
                this.SiteName = "user.auth.xboxlive.com";
                this.RpsTicket = accessToken;
            }
        }
    }

    private static class XstsAuthRequest {
        private String RelyingParty;
        private String TokenType;
        private Properties Properties;

        protected XstsAuthRequest(String token) {
            this.RelyingParty = "rp://api.minecraftservices.com/";
            this.TokenType = "JWT";
            this.Properties = new Properties(token);
        }

        private static class Properties {
            private String[] UserTokens;
            private String SandboxId;

            protected Properties(String token) {
                this.UserTokens = new String[] { token };
                this.SandboxId = "RETAIL";
            }
        }
    }

    private static class McLoginRequest {
        private String identityToken;

        protected McLoginRequest(String uhs, String identityToken) {
            this.identityToken = "XBL3.0 x=" + uhs + ";" + identityToken;
        }
    }

    // Public so users can access the refresh_token for offline access
    public static class MsTokenResponse {
        public String token_type;
        public String scope;
        public int expires_in;
        public String access_token;
        public String refresh_token;
    }

    private static class XblAuthResponse {
        /* Only appear in error responses */
        public String Identity;
        public long XErr;
        public String Message;
        public String Redirect;

        public String IssueInstant;
        public String NotAfter;
        public String Token;
        public DisplayClaims DisplayClaims;

        private static class DisplayClaims {
            public Xui[] xui;
        }

        private static class Xui {
            public String uhs;
        }
    }

    public static class McLoginResponse {
        public String username;
        public String[] roles;
        public String access_token;
        public String token_type;
        public int expires_in;
    }

    public static class McProfileResponse {
        public UUID id;
        public String name;
        public Skin[] skins;
        //public String capes; // Not sure on the datatype or response

        private static class Skin {
            public UUID id;
            public String state;
            public URI url;
            public String variant;
            public String alias;
        }
    }
}
