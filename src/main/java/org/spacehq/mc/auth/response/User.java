package org.spacehq.mc.auth.response;

import org.spacehq.mc.auth.properties.PropertyMap;

public class User {

	private String id;
	private PropertyMap properties;

	public String getId() {
		return this.id;
	}

	public PropertyMap getProperties() {
		return this.properties;
	}

}
