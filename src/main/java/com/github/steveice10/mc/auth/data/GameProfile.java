package com.github.steveice10.mc.auth.data;

import com.github.steveice10.mc.auth.exception.property.ProfileTextureException;
import com.github.steveice10.mc.auth.exception.property.PropertyException;
import com.github.steveice10.mc.auth.exception.property.SignatureValidateException;
import com.github.steveice10.mc.auth.service.ServiceRoot;
import com.github.steveice10.mc.auth.util.Base64;
import com.github.steveice10.mc.auth.util.UUIDSerializer;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Information about a user profile.
 */
public class GameProfile {
    private static final Gson GSON;

    static {
        GSON = new GsonBuilder().registerTypeAdapter(UUID.class, new UUIDSerializer()).create();
    }

    private static boolean isWhitelistedDomain(String url) {
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid URL \"" + url + "\".");
        }

        String domain = uri.getHost();
        for(String whitelistedDomain : ServiceRoot.getWhitelistedDomains()) {
            if(domain.endsWith(whitelistedDomain)) {
                return true;
            }
        }

        return false;
    }

    private UUID id;
    private String name;

    private List<Property> properties;
    private Map<TextureType, Texture> textures;
    private boolean texturesVerified;

    /**
     * Creates a new GameProfile instance.
     *
     * @param id   ID of the profile.
     * @param name Name of the profile.
     */
    public GameProfile(String id, String name) {
        this(id == null || id.equals("") ? null : UUID.fromString(id), name);
    }

    /**
     * Creates a new GameProfile instance.
     *
     * @param id   ID of the profile.
     * @param name Name of the profile.
     */
    public GameProfile(UUID id, String name) {
        if(id == null && (name == null || name.equals(""))) {
            throw new IllegalArgumentException("Name and ID cannot both be blank");
        } else {
            this.id = id;
            this.name = name;
        }
    }

    /**
     * Gets whether the profile is complete.
     *
     * @return Whether the profile is complete.
     */
    public boolean isComplete() {
        return this.id != null && this.name != null && !this.name.equals("");
    }

    /**
     * Gets the ID of the profile.
     *
     * @return The profile's ID.
     */
    public UUID getId() {
        return this.id;
    }

    /**
     * Gets the ID of the profile as a String.
     *
     * @return The profile's ID as a string.
     */
    public String getIdAsString() {
        return this.id != null ? this.id.toString() : "";
    }

    /**
     * Gets the name of the profile.
     *
     * @return The profile's name.
     */
    public String getName() {
        return this.name;
    }

    /**
     * Gets an immutable list of properties contained in the profile.
     *
     * @return The profile's properties.
     */
    public List<Property> getProperties() {
        if(this.properties == null) {
            this.properties = new ArrayList<>();
        }

        return Collections.unmodifiableList(this.properties);
    }

    /**
     * Sets the properties of this profile.
     *
     * @param properties Properties belonging to this profile.
     */
    public void setProperties(List<Property> properties) {
        if(this.properties == null) {
            this.properties = new ArrayList<>();
        } else {
            this.properties.clear();
        }

        if(properties != null) {
            this.properties.addAll(properties);
        }

        // Invalidate cached decoded textures.
        this.textures = null;
        this.texturesVerified = false;
    }

    /**
     * Gets a property contained in the profile.
     *
     * @param name Name of the property.
     * @return The property with the specified name.
     */
    public Property getProperty(String name) {
        for(Property property : this.getProperties()) {
            if(property.getName().equals(name)) {
                return property;
            }
        }

        return null;
    }

    /**
     * Gets an immutable map of texture types to textures contained in the profile.
     *
     * @return The profile's textures.
     * @throws PropertyException If an error occurs decoding the profile's texture property.
     */
    public Map<TextureType, Texture> getTextures() throws PropertyException {
        return this.getTextures(true);
    }

    /**
     * Gets an immutable map of texture types to textures contained in the profile.
     *
     * @param requireSecure Whether to require the profile's texture payload to be securely signed.
     * @return The profile's textures.
     * @throws PropertyException If an error occurs decoding the profile's texture property.
     */
    public Map<TextureType, Texture> getTextures(boolean requireSecure) throws PropertyException {
        if(this.textures == null || (requireSecure && !this.texturesVerified)) {
            GameProfile.Property textures = this.getProperty("textures");
            if(textures != null) {
                if(requireSecure) {
                    if(!textures.hasSignature()) {
                        throw new ProfileTextureException("Signature is missing from textures payload.");
                    }

                    if(!textures.isSignatureValid(ServiceRoot.getSignatureKey())) {
                        throw new ProfileTextureException("Textures payload has been tampered with. (signature invalid)");
                    }
                }

                MinecraftTexturesPayload result;
                try {
                    String json = new String(Base64.decode(textures.getValue().getBytes(StandardCharsets.UTF_8)));
                    result = GSON.fromJson(json, MinecraftTexturesPayload.class);
                } catch(Exception e) {
                    throw new ProfileTextureException("Could not decode texture payload.", e);
                }

                if(result != null && result.textures != null) {
                    if(requireSecure) {
                        for(GameProfile.Texture texture : result.textures.values()) {
                            if (!isWhitelistedDomain(texture.getURL())) {
                                throw new ProfileTextureException("Textures payload has been tampered with. (non-whitelisted domain)");
                            }
                        }
                    }

                    this.textures = result.textures;
                } else {
                    this.textures = Collections.emptyMap();
                }

                this.texturesVerified = requireSecure;
            } else {
                return Collections.emptyMap();
            }
        }

        return Collections.unmodifiableMap(this.textures);
    }

    /**
     * Gets a texture contained in the profile.
     *
     * @param type Type of texture to get.
     * @return The texture of the specified type.
     * @throws PropertyException If an error occurs decoding the profile's texture property.
     */
    public Texture getTexture(TextureType type) throws PropertyException {
        return this.getTextures().get(type);
    }

    /**
     * Gets a texture contained in the profile.
     *
     * @param type Type of texture to get.
     * @param requireSecure Whether to require the profile's texture payload to be securely signed.
     * @return The texture of the specified type.
     * @throws PropertyException If an error occurs decoding the profile's texture property.
     */
    public Texture getTexture(TextureType type, boolean requireSecure) throws PropertyException {
        return this.getTextures(requireSecure).get(type);
    }

    @Override
    public boolean equals(Object o) {
        if(this == o) {
            return true;
        } else if(o != null && this.getClass() == o.getClass()) {
            GameProfile that = (GameProfile) o;
            return Objects.equals(this.id, that.id) && Objects.equals(this.name, that.name);
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        int result = this.id != null ? this.id.hashCode() : 0;
        result = 31 * result + (this.name != null ? this.name.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "GameProfile{id=" + this.id + ", name=" + this.name + ", properties=" + this.getProperties() + "}";
    }

    /**
     * A property belonging to a profile.
     */
    public static class Property {
        private String name;
        private String value;
        private String signature;

        /**
         * Creates a new Property instance.
         *
         * @param name  Name of the property.
         * @param value Value of the property.
         */
        public Property(String name, String value) {
            this(name, value, null);
        }

        /**
         * Creates a new Property instance.
         *
         * @param name      Name of the property.
         * @param value     Value of the property.
         * @param signature Signature used to verify the property.
         */
        public Property(String name, String value, String signature) {
            this.name = name;
            this.value = value;
            this.signature = signature;
        }

        /**
         * Gets the name of the property.
         *
         * @return The property's name.
         */
        public String getName() {
            return this.name;
        }

        /**
         * Gets the value of the property.
         *
         * @return The property's value.
         */
        public String getValue() {
            return this.value;
        }

        /**
         * Gets whether this property has a signature to verify it.
         *
         * @return Whether this property is signed.
         */
        public boolean hasSignature() {
            return this.signature != null;
        }

        /**
         * Gets the signature used to verify the property.
         *
         * @return The property's signature.
         */
        public String getSignature() {
            return this.signature;
        }

        /**
         * Gets whether this property's signature is valid.
         *
         * @param key Public key to validate the signature against.
         * @return Whether the signature is valid.
         * @throws SignatureValidateException If the signature could not be validated.
         */
        public boolean isSignatureValid(PublicKey key) throws SignatureValidateException {
            if(!this.hasSignature()) {
                return false;
            }

            try {
                Signature sig = Signature.getInstance("SHA1withRSA");
                sig.initVerify(key);
                sig.update(this.value.getBytes());
                return sig.verify(Base64.decode(this.signature.getBytes("UTF-8")));
            } catch(Exception e) {
                throw new SignatureValidateException("Could not validate property signature.", e);
            }
        }

        @Override
        public String toString() {
            return "Property{name=" + this.name + ", value=" + this.value + ", signature=" + this.signature + "}";
        }
    }

    /**
     * The type of a profile texture.
     */
    public enum TextureType {
        SKIN,
        CAPE,
        ELYTRA;
    }

    /**
     * The model used for a profile texture.
     */
    public enum TextureModel {
        NORMAL,
        SLIM;
    }

    /**
     * A texture contained within a profile.
     */
    public static class Texture {
        private String url;
        private Map<String, String> metadata;

        /**
         * Creates a new Texture instance.
         *
         * @param url      URL of the texture.
         * @param metadata Metadata of the texture.
         */
        public Texture(String url, Map<String, String> metadata) {
            this.url = url;
            this.metadata = new HashMap<>(metadata);
        }

        /**
         * Gets the URL of the texture.
         *
         * @return The texture's URL.
         */
        public String getURL() {
            return this.url;
        }

        /**
         * Gets a metadata string from the texture.
         *
         * @return The metadata value corresponding to the given key.
         */
        public String getMetadata(String key) {
            return this.metadata != null ? this.metadata.get(key) : null;
        }

        /**
         * Gets the model of the texture.
         *
         * @return The texture's model.
         */
        public TextureModel getModel() {
            String model = this.getMetadata("model");
            return model != null && model.equals("slim") ? TextureModel.SLIM : TextureModel.NORMAL;
        }

        /**
         * Gets the hash of the texture.
         *
         * @return The texture's hash.
         */
        public String getHash() {
            String url = this.url.endsWith("/") ? this.url.substring(0, this.url.length() - 1) : this.url;
            int slash = url.lastIndexOf("/");
            int dot = url.lastIndexOf(".");
            if(dot < slash) {
                dot = url.length();
            }

            return url.substring(slash + 1, dot != -1 ? dot : url.length());
        }

        @Override
        public String toString() {
            return "Texture{url=" + this.url + ", model=" + this.getModel() + ", hash=" + this.getHash() + "}";
        }
    }

    private static class MinecraftTexturesPayload {
        public long timestamp;
        public UUID profileId;
        public String profileName;
        public boolean isPublic;
        public Map<GameProfile.TextureType, GameProfile.Texture> textures;
    }
}
