package com.github.steveice10.mc.auth.util;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class MSALApplicationOptions {
    private static final String DEFAULT_AUTHORITY = "https://login.microsoftonline.com/consumers/";
    private static final String XBOX_SIGNIN_SCOPE = "XboxLive.signin";
    private static final String XBOX_OFFLINE_SCOPE = XBOX_SIGNIN_SCOPE.concat(" offline_access");

    public final String authority;
    public final boolean offlineAccess;
    public final Set<String> scopes;
    public final MSALTokenPersistence tokenPersistence;

    public MSALApplicationOptions(Builder builder) {
        this.authority = builder.authority;
        this.offlineAccess = builder.offlineAccess;
        this.scopes = builder.scopes;
        this.tokenPersistence = builder.tokenPersistence;
    }

    public static class Builder {
        private String authority = DEFAULT_AUTHORITY;
        private boolean offlineAccess = false;
        private Set<String> scopes = Collections.singleton(XBOX_SIGNIN_SCOPE);
        private MSALTokenPersistence tokenPersistence = new MSALTokenPersistence();
        private boolean scopesModified = false;

        public Builder() throws IOException {
        }

        public Builder authority(String authority) {
            this.authority = authority;
            return this;
        }

        public Builder offlineAccess(boolean offlineAccess) {
            this.offlineAccess = offlineAccess;
            return this;
        }

        public Builder scopes(Set<String> scopes) {
            this.scopes = scopes;
            this.scopesModified = true;
            return this;
        }

        public Builder persistence(MSALTokenPersistence persistence) {
            this.tokenPersistence = persistence;
            return this;
        }

        public MSALApplicationOptions build() {
            // If the scopes were not modified, we can use the default set of scopes
            if (!this.scopesModified)
                this.scopes = new HashSet<>(Arrays.asList((offlineAccess ? XBOX_OFFLINE_SCOPE : XBOX_SIGNIN_SCOPE).split(" ")));

            return new MSALApplicationOptions(this);
        }
    }
}
