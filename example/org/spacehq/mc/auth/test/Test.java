package org.spacehq.mc.auth.test;

import org.spacehq.mc.auth.UserAuthentication;
import org.spacehq.mc.auth.exception.AuthenticationException;

import java.util.UUID;

public class Test {

	private static final String USERNAME = "Username";
	private static final String PASSWORD = "Password";
	private static final String ACCESS_TOKEN = null;

	public static void main(String[] args) {
		String clientToken = UUID.randomUUID().toString();
		UserAuthentication auth = new UserAuthentication(clientToken);
		auth.setUsername(USERNAME);
		if(ACCESS_TOKEN != null) {
			auth.setAccessToken(ACCESS_TOKEN);
		} else {
			auth.setPassword(PASSWORD);
		}

		try {
			auth.login();
			System.out.println("Access Token: " + auth.getAccessToken());
			System.out.println("Profiles: " + auth.getAvailableProfiles());
		} catch(AuthenticationException e) {
			System.err.println("Failed to login!");
			e.printStackTrace();
		}
	}

}
