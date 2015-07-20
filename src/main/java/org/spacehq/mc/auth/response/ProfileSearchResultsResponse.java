package org.spacehq.mc.auth.response;

import org.spacehq.mc.auth.GameProfile;

public class ProfileSearchResultsResponse extends Response {

    private GameProfile[] profiles;

    public GameProfile[] getProfiles() {
        return this.profiles;
    }

    public void setProfiles(GameProfile[] profiles) {
        this.profiles = profiles;
    }

}
