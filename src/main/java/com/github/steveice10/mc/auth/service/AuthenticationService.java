package com.github.steveice10.mc.auth.service;

import com.github.steveice10.mc.auth.data.GameProfile;
import com.github.steveice10.mc.auth.exception.request.InvalidCredentialsException;
import com.github.steveice10.mc.auth.exception.request.RequestException;
import com.github.steveice10.mc.auth.util.HTTP;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

/**
 * Service used for authenticating users.
 */
public class AuthenticationService extends Service {
    private static final URI DEFAULT_BASE_URI = URI.create("https://authserver.mojang.com/");
    private static final String AUTHENTICATE_ENDPOINT = "authenticate";
    private static final String REFRESH_ENDPOINT = "refresh";
    private static final String INVALIDATE_ENDPOINT = "invalidate";

    private String clientToken;

    private String username;
    private String password;
    private String accessToken;

    private boolean loggedIn;
    private String id;
    private List<GameProfile.Property> properties = new ArrayList<>();
    private List<GameProfile> profiles = new ArrayList<>();
    private GameProfile selectedProfile;

    /**
     * Creates a new AuthenticationService instance.
     */
    public AuthenticationService() {
        this(UUID.randomUUID().toString());
    }

    /**
     * Creates a new AuthenticationService instance.
     *
     * @param clientToken Client token to use when making authentication requests.
     */
    public AuthenticationService(String clientToken) {
        super(DEFAULT_BASE_URI);

        if(clientToken == null) {
            throw new IllegalArgumentException("ClientToken cannot be null.");
        }

        this.clientToken = clientToken;
    }

    /**
     * Gets the client token of the service.
     *
     * @return The service's client token.
     */
    public String getClientToken() {
        return this.clientToken;
    }

    /**
     * Gets the username of the service.
     *
     * @return The service's username.
     */
    public String getUsername() {
        return this.id;
    }

    /**
     * Gets the password of the service.
     *
     * @return The user's ID.
     */
    public String getPassword() {
        return this.password;
    }

    /**
     * Gets the access token of the service.
     *
     * @return The user's access token.
     */
    public String getAccessToken() {
        return this.accessToken;
    }

    /**
     * Gets whether the service has been used to log in.
     *
     * @return Whether the service is logged in.
     */
    public boolean isLoggedIn() {
        return this.loggedIn;
    }

    /**
     * Gets the ID of the user logged in with the service.
     *
     * @return The user's ID.
     */
    public String getId() {
        return this.id;
    }

    /**
     * Gets the properties of the user logged in with the service.
     *
     * @return The user's properties.
     */
    public List<GameProfile.Property> getProperties() {
        return Collections.unmodifiableList(this.properties);
    }

    /**
     * Gets the available profiles of the user logged in with the service.
     *
     * @return The user's available profiles.
     */
    public List<GameProfile> getAvailableProfiles() {
        return Collections.unmodifiableList(this.profiles);
    }

    /**
     * Gets the selected profile of the user logged in with the service.
     *
     * @return The user's selected profile.
     */
    public GameProfile getSelectedProfile() {
        return this.selectedProfile;
    }

    /**
     * Sets the username of the service.
     *
     * @param username Username to set.
     */
    public void setUsername(String username) {
        if(this.loggedIn && this.selectedProfile != null) {
            throw new IllegalStateException("Cannot change username while user is logged in and profile is selected.");
        } else {
            this.username = username;
        }
    }

    /**
     * Sets the password of the service.
     *
     * @param password Password to set.
     */
    public void setPassword(String password) {
        if(this.loggedIn && this.selectedProfile != null) {
            throw new IllegalStateException("Cannot change password while user is logged in and profile is selected.");
        } else {
            this.password = password;
        }
    }

    /**
     * Sets the access token of the service.
     *
     * @param accessToken Access token to set.
     */
    public void setAccessToken(String accessToken) {
        if(this.loggedIn && this.selectedProfile != null) {
            throw new IllegalStateException("Cannot change access token while user is logged in and profile is selected.");
        } else {
            this.accessToken = accessToken;
        }
    }

    /**
     * Logs the service in.
     * The current access token will be used if set. Otherwise, password-based authentication will be used.
     *
     * @throws RequestException If an error occurs while making the request.
     */
    public void login() throws RequestException {
        if(this.username == null || this.username.equals("")) {
            throw new InvalidCredentialsException("Invalid username.");
        }

        boolean token = this.accessToken != null && !this.accessToken.equals("");
        boolean password = this.password != null && !this.password.equals("");
        if(!token && !password) {
            throw new InvalidCredentialsException("Invalid password or access token.");
        }

        AuthenticateRefreshResponse response;
        if(token) {
            RefreshRequest request = new RefreshRequest(this.clientToken, this.accessToken, null);
            response = HTTP.makeRequest(this.getProxy(), this.getEndpointUri(REFRESH_ENDPOINT), request, AuthenticateRefreshResponse.class);
        } else {
            AuthenticationRequest request = new AuthenticationRequest(this.username, this.password, this.clientToken);
            response = HTTP.makeRequest(this.getProxy(), this.getEndpointUri(AUTHENTICATE_ENDPOINT), request, AuthenticateRefreshResponse.class);
        }

        if(response == null) {
            throw new RequestException("Server returned invalid response.");
        } else if(!response.clientToken.equals(this.clientToken)) {
            throw new RequestException("Server responded with incorrect client token.");
        }

        if(response.user != null && response.user.id != null) {
            this.id = response.user.id;
        } else {
            this.id = this.username;
        }

        this.accessToken = response.accessToken;
        this.profiles = response.availableProfiles != null ? Arrays.asList(response.availableProfiles) : Collections.<GameProfile>emptyList();
        this.selectedProfile = response.selectedProfile;

        this.properties.clear();
        if(response.user != null && response.user.properties != null) {
            this.properties.addAll(response.user.properties);
        }

        this.loggedIn = true;
    }

    /**
     * Logs the service out.
     *
     * @throws RequestException If an error occurs while making the request.
     */
    public void logout() throws RequestException {
        if(!this.loggedIn) {
            throw new IllegalStateException("Cannot log out while not logged in.");
        }

        InvalidateRequest request = new InvalidateRequest(this.clientToken, this.accessToken);
        HTTP.makeRequest(this.getProxy(), this.getEndpointUri(INVALIDATE_ENDPOINT), request);

        this.accessToken = null;
        this.loggedIn = false;
        this.id = null;
        this.properties.clear();
        this.profiles.clear();
        this.selectedProfile = null;
    }

    /**
     * Selects a game profile.
     *
     * @param profile Profile to select.
     * @throws RequestException If an error occurs while making the request.
     */
    public void selectGameProfile(GameProfile profile) throws RequestException {
        if(!this.loggedIn) {
            throw new RequestException("Cannot change game profile while not logged in.");
        } else if(this.selectedProfile != null) {
            throw new RequestException("Cannot change game profile when it is already selected.");
        } else if(profile == null || !this.profiles.contains(profile)) {
            throw new IllegalArgumentException("Invalid profile '" + profile + "'.");
        }

        RefreshRequest request = new RefreshRequest(this.clientToken, this.accessToken, profile);
        AuthenticateRefreshResponse response = HTTP.makeRequest(this.getProxy(), this.getEndpointUri(REFRESH_ENDPOINT), request, AuthenticateRefreshResponse.class);
        if(response == null) {
            throw new RequestException("Server returned invalid response.");
        } else if(!response.clientToken.equals(this.clientToken)) {
            throw new RequestException("Server responded with incorrect client token.");
        }

        this.accessToken = response.accessToken;
        this.selectedProfile = response.selectedProfile;
    }

    @Override
    public String toString() {
        return "UserAuthentication{clientToken=" + this.clientToken + ", username=" + this.username + ", accessToken=" + this.accessToken + ", loggedIn=" + this.loggedIn + ", profiles=" + this.profiles + ", selectedProfile=" + this.selectedProfile + "}";
    }

    private static class Agent {
        private String name;
        private int version;

        protected Agent(String name, int version) {
            this.name = name;
            this.version = version;
        }
    }

    private static class User {
        public String id;
        public List<GameProfile.Property> properties;
    }

    private static class AuthenticationRequest {
        private Agent agent;
        private String username;
        private String password;
        private String clientToken;
        private boolean requestUser;

        protected AuthenticationRequest(String username, String password, String clientToken) {
            this.agent = new Agent("Minecraft", 1);
            this.username = username;
            this.password = password;
            this.clientToken = clientToken;
            this.requestUser = true;
        }
    }

    private static class RefreshRequest {
        private String clientToken;
        private String accessToken;
        private GameProfile selectedProfile;
        private boolean requestUser;

        protected RefreshRequest(String clientToken, String accessToken, GameProfile selectedProfile) {
            this.clientToken = clientToken;
            this.accessToken = accessToken;
            this.selectedProfile = selectedProfile;
            this.requestUser = true;
        }
    }

    private static class InvalidateRequest {
        private String clientToken;
        private String accessToken;

        protected InvalidateRequest(String clientToken, String accessToken) {
            this.clientToken = clientToken;
            this.accessToken = accessToken;
        }
    }

    private static class AuthenticateRefreshResponse {
        public String accessToken;
        public String clientToken;
        public GameProfile selectedProfile;
        public GameProfile[] availableProfiles;
        public User user;
    }
}
