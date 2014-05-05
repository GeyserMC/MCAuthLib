package org.spacehq.mc.auth;

import org.spacehq.mc.auth.exception.AuthenticationException;
import org.spacehq.mc.auth.exception.ProfileNotFoundException;
import org.spacehq.mc.auth.response.ProfileSearchResultsResponse;
import org.spacehq.mc.auth.util.URLUtils;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public class GameProfileRepository {

	private static final String BASE_URL = "https://api.mojang.com/";
	private static final String SEARCH_URL = BASE_URL + "profiles/minecraft";
	private static final int MAX_FAIL_COUNT = 3;
	private static final int DELAY_BETWEEN_PAGES = 100;
	private static final int DELAY_BETWEEN_FAILURES = 750;
	private static final int PROFILES_PER_REQUEST = 100;

	public void findProfilesByNames(String[] names, ProfileLookupCallback callback) {
		Set<String> criteria = new HashSet<String>();
		for(String name : names) {
			if(name != null && !name.isEmpty()) {
				criteria.add(name.toLowerCase());
			}
		}

		for(Set<String> request : partition(criteria, PROFILES_PER_REQUEST)) {
			Exception error = null;
			int failCount = 0;
			boolean tryAgain = true;
			while(failCount < MAX_FAIL_COUNT && tryAgain) {
				tryAgain = false;
				try {
					ProfileSearchResultsResponse response = URLUtils.makeRequest(URLUtils.constantURL(SEARCH_URL), request, ProfileSearchResultsResponse.class);
					failCount = 0;
					error = null;
					Set<String> missing = new HashSet<String>(request);
					for(GameProfile profile : response.getProfiles()) {
						missing.remove(profile.getName().toLowerCase());
						callback.onProfileLookupSucceeded(profile);
					}

					for(String name : missing) {
						callback.onProfileLookupFailed(new GameProfile((UUID) null, name), new ProfileNotFoundException("Server could not find the requested profile."));
					}

					try {
						Thread.sleep(DELAY_BETWEEN_PAGES);
					} catch(InterruptedException ignored) {
					}
				} catch(AuthenticationException e) {
					error = e;
					failCount++;
					if(failCount >= MAX_FAIL_COUNT) {
						for(String name : request) {
							callback.onProfileLookupFailed(new GameProfile((UUID) null, name), error);
						}
					} else {
						try {
							Thread.sleep(DELAY_BETWEEN_FAILURES);
						} catch(InterruptedException ignored) {
						}

						tryAgain = true;
					}
				}
			}
		}
	}

	private static Set<Set<String>> partition(Set<String> set, int size) {
		List<String> list = new ArrayList<String>(set);
		Set<Set<String>> ret = new HashSet<Set<String>>();
		for(int i = 0; i < list.size(); i += size) {
			Set<String> s = new HashSet<String>();
			s.addAll(list.subList(i, Math.min(i + size, list.size())));
			ret.add(s);
		}

		return ret;
	}
}
