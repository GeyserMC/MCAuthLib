package com.github.steveice10.mc.auth.service;

import com.github.steveice10.mc.auth.exception.request.InvalidCredentialsException;
import com.github.steveice10.mc.auth.exception.request.RequestException;
import com.github.steveice10.mc.auth.util.HTTP;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

public class MsaAuthenticationService extends AuthenticationService {
    private static final URI MS_CODE_ENDPOINT = URI.create("https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode");
    private static final URI MS_TOKEN_ENDPOINT = URI.create("https://login.microsoftonline.com/consumers/oauth2/v2.0/token");
    private static final URI XBL_AUTH_ENDPOINT = URI.create("https://user.auth.xboxlive.com/user/authenticate");
    private static final URI XSTS_AUTH_ENDPOINT = URI.create("https://xsts.auth.xboxlive.com/xsts/authorize");
    private static final URI MC_LOGIN_ENDPOINT = URI.create("https://api.minecraftservices.com/authentication/login_with_xbox");

    private static final URI EMPTY_URI = URI.create("");

    private String deviceCode;

    public MsaAuthenticationService(String clientId) {
        this(clientId, null);
    }

    public MsaAuthenticationService(String clientId, String deviceCode) {
        super(clientId, EMPTY_URI);

        this.deviceCode = deviceCode;
    }

    public MsCodeResponse getAuthCode() throws RequestException {
        if(this.clientToken == null) {
            throw new InvalidCredentialsException("Invalid client token.");
        }
        MsCodeRequest request = new MsCodeRequest(this.clientToken);
        return HTTP.makeRequestForm(this.getProxy(), MS_CODE_ENDPOINT, request.toMap(), MsCodeResponse.class);
    }

    public McLoginResponse getLoginResponseFromCode() throws RequestException {
        if(this.deviceCode == null) {
            throw new InvalidCredentialsException("Invalid device code.");
        }
        MsTokenRequest request = new MsTokenRequest(this.clientToken, this.deviceCode);
        MsTokenResponse response = HTTP.makeRequestForm(this.getProxy(), MS_TOKEN_ENDPOINT, request.toMap(), MsTokenResponse.class);

        return getLoginResponseFromToken(response.access_token);
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

        McLoginRequest mcRequest = new McLoginRequest(response.DisplayClaims.xui[0].uhs, response.Token);
        return HTTP.makeRequest(this.getProxy(), MC_LOGIN_ENDPOINT, mcRequest, McLoginResponse.class);
    }

    @Override
    public void login() throws RequestException {
        boolean token = this.clientToken != null && !this.clientToken.isEmpty();
        boolean device = this.deviceCode != null && !this.deviceCode.isEmpty();
        boolean password = this.password != null && !this.password.isEmpty();
        if(!token && !password) {
            throw new InvalidCredentialsException("Invalid password, device code or access token.");
        }
        if(password && (this.username == null || this.username.isEmpty())) {
            throw new InvalidCredentialsException("Invalid username.");
        }
        if(password) {
            // TODO: Password-based auth to generate token
        }
        if(!device) {
            this.deviceCode = getAuthCode().device_code;
        }
        McLoginResponse response = getLoginResponseFromCode();
        if(response == null) {
            throw new RequestException("Invalid response received.");
        }
        this.username = response.username;
        this.accessToken = response.access_token;
        this.loggedIn = true;
    }

    @Override
    public void logout() throws RequestException {
        super.logout();
        this.clientToken = null;
    }

    @Override
    public String toString() {
        return "MsaAuthenticationService{" +
                "deviceCode='" + this.deviceCode + '\'' +
                ", clientToken='" + this.clientToken + '\'' +
                ", accessToken='" + this.accessToken + '\'' +
                ", loggedIn=" + this.loggedIn +
                ", username='" + this.username + '\'' +
                ", password='" + this.password + '\'' +
                ", selectedProfile=" + this.selectedProfile +
                ", properties=" + this.properties +
                ", profiles=" + this.profiles +
                '}';
    }

    private static class MsCodeRequest {
        private String client_id;
        private String scope;

        protected MsCodeRequest(String clientId) {
            this.client_id = clientId;
            this.scope = "XboxLive.signin";
        }

        public Map<String, String> toMap() {
            Map<String, String> map = new HashMap<>();

            map.put("client_id", client_id);
            map.put("scope", scope);

            return map;
        }
    }

    private static class MsTokenRequest {
        private String grant_type;
        private String client_id;
        private String device_code;

        protected MsTokenRequest(String clientId, String deviceCode) {
            this.grant_type = "urn:ietf:params:oauth:grant-type:device_code";
            this.client_id = clientId;
            this.device_code = deviceCode;
        }

        public Map<String, String> toMap() {
            Map<String, String> map = new HashMap<>();

            map.put("grant_type", grant_type);
            map.put("client_id", client_id);
            map.put("device_code", device_code);

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
                this.RpsTicket = "d=" + accessToken;
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

    public static class MsCodeResponse {
        public String user_code;
        public String device_code;
        public URI verification_uri;
        public int expires_in;
        public int interval;
        public String message;
    }

    private static class MsTokenResponse {
        public String token_type;
        public String scope;
        public int expires_in;
        public String access_token;
        public String id_token;
        public String refresh_token;
    }

    private static class XblAuthResponse {
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

    private static class McLoginResponse {
        public String username;
        public String[] roles;
        public String access_token;
        public String token_type;
        public int expires_in;
    }
}
