package com.github.steveice10.mc.auth.service;

import com.github.steveice10.mc.auth.exception.request.RequestException;
import com.github.steveice10.mc.auth.util.HTTP;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

public class MsaAuthenticationService extends Service {
    private String clientId;

    private static final URI MS_CODE_ENDPOINT = URI.create("https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode");
    private static final URI MS_TOKEN_ENDPOINT = URI.create("https://login.microsoftonline.com/consumers/oauth2/v2.0/token");
    private static final URI XBL_AUTH_ENDPOINT = URI.create("https://user.auth.xboxlive.com/user/authenticate");
    private static final URI XSTS_AUTH_ENDPOINT = URI.create("https://xsts.auth.xboxlive.com/xsts/authorize");
    private static final URI MC_LOGIN_ENDPOINT = URI.create("https://api.minecraftservices.com/authentication/login_with_xbox");

    public MsaAuthenticationService(String clientId) {
        super(URI.create(""));

        this.clientId = clientId;
    }

    public MsCodeResponse getAuthCode() throws RequestException {
        MsCodeRequest request = new MsCodeRequest(this.clientId);
        MsCodeResponse response = HTTP.makeRequestForm(this.getProxy(), MS_CODE_ENDPOINT, request.toMap(), MsCodeResponse.class);

        return response;
    }

    public String getSessionTokenFromCode(String deviceCode) throws RequestException {
        MsTokenRequest request = new MsTokenRequest(this.clientId, deviceCode);
        MsTokenResponse response = HTTP.makeRequestForm(this.getProxy(), MS_TOKEN_ENDPOINT, request.toMap(), MsTokenResponse.class);

        return getSessionTokenFromToken(response.access_token);
    }

    /**
     * Get a Minecraft session token from a
     * given Microsoft account token
     *
     * @param accessToken
     * @return A session token
     */
    private String getSessionTokenFromToken(String accessToken) throws RequestException {
        XblAuthRequest xblRequest = new XblAuthRequest(accessToken);
        XblAuthResponse response = HTTP.makeRequest(this.getProxy(), XBL_AUTH_ENDPOINT, xblRequest, XblAuthResponse.class);

        XstsAuthRequest xstsRequest = new XstsAuthRequest(response.Token);
        response = HTTP.makeRequest(this.getProxy(), XSTS_AUTH_ENDPOINT, xstsRequest, XblAuthResponse.class);

        McLoginRequest mcRequest = new McLoginRequest(response.DisplayClaims.xui[0].uhs, response.Token);
        McLoginResponse mcResponse = HTTP.makeRequest(this.getProxy(), MC_LOGIN_ENDPOINT, mcRequest, McLoginResponse.class);

        return mcResponse.access_token;
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
