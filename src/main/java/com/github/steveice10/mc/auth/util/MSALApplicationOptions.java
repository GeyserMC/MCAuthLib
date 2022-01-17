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
        // Default options
        private String authority = DEFAULT_AUTHORITY;
        private boolean offlineAccess = false;
        private Set<String> scopes = Collections.singleton(XBOX_SIGNIN_SCOPE);
        private MSALTokenPersistence tokenPersistence = new MSALTokenPersistence();
        /**
         * Indicates that the user has provided their own scopes and that we should disregard <code>offlineAccess</code>
         */
        private boolean scopesModified = false;

        public Builder() throws IOException {
        }

        /**
         * Set the authority to use for authentication.
         *
         * @see <a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/msal-client-application-configuration#authority">MSAL documentation - Authority</a>
         */
        public Builder authority(String authority) {
            this.authority = authority;
            return this;
        }

        /**
         * Set whether offline access scopes should be included in the authentication request. Internally, this will
         * modify the <code>scopes</code> field to include the offline access scope. This boolean is not directly used
         * by MSAL.
         */
        public Builder offlineAccess(boolean offlineAccess) {
            this.offlineAccess = offlineAccess;
            return this;
        }

        /**
         * Set the scopes to use for authentication. You should already know why you're using this method and have the
         * required scopes enabled in your Azure AD application. If not, ignore this method or simply use <code>offlineAccess</code>
         * instead.
         */
        public Builder scopes(Set<String> scopes) {
            this.scopes = scopes;

            // Indicate that the scopes were modified so that we don't use the default set of scopes
            this.scopesModified = true;

            return this;
        }

        /**
         * Set the token persistence to use for storing tokens. By default, this is a {@link MSALTokenPersistence} that
         * loads/saves tokens to/from a file. You can use this method to set a different persistence implementation,
         * such as a database. If you want to disable token persistence, just pass <code>null</code> as the argument.
         */
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
