package org.spacehq.mc.auth;

import org.spacehq.mc.auth.exception.authentication.AuthenticationException;
import org.spacehq.mc.auth.exception.authentication.InvalidCredentialsException;
import org.spacehq.mc.auth.util.RequestUtil;

import java.net.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Service used for authenticating users.
 */
public class AuthenticationService {
    private static final String BASE_URL = "https://authserver.mojang.com/";
    private static final String AUTHENTICATE_URL = BASE_URL + "authenticate";
    private static final String REFRESH_URL = BASE_URL + "refresh";

    private String clientToken;
    private Proxy proxy;

    private String username;
    private String password;
    private String accessToken;

    private boolean loggedIn;
    private String userId;
    private List<GameProfile.Property> properties = new ArrayList<GameProfile.Property>();
    private List<GameProfile> profiles = new ArrayList<GameProfile>();
    private GameProfile selectedProfile;

    /**
     * Creates a new AuthenticationService instance.
     *
     * @param clientToken Client token to use when making authentication requests.
     */
    public AuthenticationService(String clientToken) {
        this(clientToken, Proxy.NO_PROXY);
    }

    /**
     * Creates a new AuthenticationService instance.
     *
     * @param clientToken Client token to use when making authentication requests.
     * @param proxy       Proxy to use when making HTTP requests.
     */
    public AuthenticationService(String clientToken, Proxy proxy) {
        if(clientToken == null) {
            throw new IllegalArgumentException("ClientToken cannot be null.");
        }

        if(proxy == null) {
            throw new IllegalArgumentException("Proxy cannot be null.");
        }

        this.clientToken = clientToken;
        this.proxy = proxy;
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
        return this.userId;
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
     * Sets the username of the service.
     *
     * @param username Username to set.
     */
    public void setUsername(String username) {
        if(this.isLoggedIn() && this.selectedProfile != null) {
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
        if(this.isLoggedIn() && this.selectedProfile != null) {
            throw new IllegalStateException("Cannot set password while user is logged in and profile is selected.");
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
        if(this.isLoggedIn() && this.selectedProfile != null) {
            throw new IllegalStateException("Cannot change access token while user is logged in and profile is selected.");
        } else {
            this.accessToken = accessToken;
        }
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
    public String getUserId() {
        return this.userId;
    }

    /**
     * Gets the properties of the user logged in with the service.
     *
     * @return The user's properties.
     */
    public List<GameProfile.Property> getProperties() {
        return this.isLoggedIn() ? new ArrayList<GameProfile.Property>(this.properties) : Collections.<GameProfile.Property>emptyList();
    }

    /**
     * Gets the available profiles of the user logged in with the service.
     *
     * @return The user's available profiles.
     */
    public List<GameProfile> getAvailableProfiles() {
        return this.profiles;
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
     * Logs the service in.
     *
     * @throws AuthenticationException If an authentication error occurs.
     */
    public void login() throws AuthenticationException {
        if(this.username == null || this.username.equals("")) {
            throw new InvalidCredentialsException("Invalid username.");
        } else {
            if(this.accessToken != null && !this.accessToken.equals("")) {
                this.loginWithToken();
            } else {
                if(this.password == null || this.password.equals("")) {
                    throw new InvalidCredentialsException("Invalid password.");
                }

                this.loginWithPassword();
            }
        }
    }

    /**
     * Logs the session out.
     */
    public void logout() {
        this.loggedIn = false;
        this.userId = null;
        this.properties.clear();
        this.profiles.clear();
        this.selectedProfile = null;
    }

    /**
     * Selects a game profile.
     *
     * @param profile Profile to select.
     * @throws AuthenticationException If an authentication error occurs.
     */
    public void selectGameProfile(GameProfile profile) throws AuthenticationException {
        if(!this.loggedIn) {
            throw new AuthenticationException("Cannot change game profile while not logged in.");
        } else if(this.selectedProfile != null) {
            throw new AuthenticationException("Cannot change game profile when it is already selected. You must log out and back in.");
        } else if(profile != null && this.profiles.contains(profile)) {
            RefreshRequest request = new RefreshRequest(this.clientToken, this.accessToken, profile);
            RefreshResponse response = RequestUtil.makeRequest(this.proxy, REFRESH_URL, request, RefreshResponse.class);
            if(response.clientToken.equals(this.clientToken)) {
                this.accessToken = response.accessToken;
                this.selectedProfile = response.selectedProfile;
            } else {
                throw new AuthenticationException("Server requested we change our client token. Don't know how to handle this!");
            }
        } else {
            throw new IllegalArgumentException("Invalid profile '" + profile + "'.");
        }
    }

    @Override
    public String toString() {
        return "UserAuthentication{clientToken=" + this.clientToken + ", username=" + this.username + ", accessToken=" + this.accessToken + ", loggedIn=" + this.loggedIn + ", profiles=" + this.profiles + ", selectedProfile=" + this.selectedProfile + "}";
    }

    private void loginWithPassword() throws AuthenticationException {
        if(this.username == null || this.username.equals("")) {
            throw new InvalidCredentialsException("Invalid username.");
        } else if(this.password == null || this.password.equals("")) {
            throw new InvalidCredentialsException("Invalid password.");
        } else {
            AuthenticationRequest request = new AuthenticationRequest(this.username, this.password, this.clientToken);
            AuthenticationResponse response = RequestUtil.makeRequest(this.proxy, AUTHENTICATE_URL, request, AuthenticationResponse.class);
            if(!response.clientToken.equals(this.clientToken)) {
                throw new AuthenticationException("Server requested we change our client token. Don't know how to handle this!");
            } else {
                if(response.user != null && response.user.id != null) {
                    this.userId = response.user.id;
                } else {
                    this.userId = this.username;
                }

                this.loggedIn = true;
                this.accessToken = response.accessToken;
                this.profiles = response.availableProfiles != null ? Arrays.asList(response.availableProfiles) : Collections.<GameProfile>emptyList();
                this.selectedProfile = response.selectedProfile;
                this.properties.clear();
                if(response.user != null && response.user.properties != null) {
                    this.properties.addAll(response.user.properties);
                }
            }
        }
    }

    private void loginWithToken() throws AuthenticationException {
        if(this.userId == null || this.userId.equals("")) {
            if(this.username == null || this.username.equals("")) {
                throw new InvalidCredentialsException("Invalid uuid and username.");
            }

            this.userId = this.username;
        }

        if(this.accessToken == null || this.accessToken.equals("")) {
            throw new InvalidCredentialsException("Invalid access token.");
        } else {
            RefreshRequest request = new RefreshRequest(this.clientToken, this.accessToken, null);
            RefreshResponse response = RequestUtil.makeRequest(this.proxy, REFRESH_URL, request, RefreshResponse.class);
            if(response.clientToken.equals(this.clientToken)) {
                if(response.user != null && response.user.id != null) {
                    this.userId = response.user.id;
                } else {
                    this.userId = this.username;
                }

                this.loggedIn = true;
                this.accessToken = response.accessToken;
                this.profiles = Arrays.asList(response.availableProfiles);
                this.selectedProfile = response.selectedProfile;
                this.properties.clear();
                if(response.user != null && response.user.properties != null) {
                    this.properties.addAll(response.user.properties);
                }
            } else {
                throw new AuthenticationException("Server requested we change our client token. Don't know how to handle this!");
            }
        }
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

    private static class AuthenticationResponse extends RequestUtil.Response {
        public String accessToken;
        public String clientToken;
        public GameProfile selectedProfile;
        public GameProfile[] availableProfiles;
        public User user;
    }

    private static class RefreshResponse extends RequestUtil.Response {
        public String accessToken;
        public String clientToken;
        public GameProfile selectedProfile;
        public GameProfile[] availableProfiles;
        public User user;
    }
}
