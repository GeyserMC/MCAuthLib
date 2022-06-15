package com.github.steveice10.mc.auth.service;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.Proxy;
import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.github.steveice10.mc.auth.exception.request.RequestException;
import com.github.steveice10.mc.auth.util.Base64;
import com.github.steveice10.mc.auth.util.HTTP;

public class ServiceRoot {
    private static final URI DEFAULT_AUTH_URI = URI.create("https://authserver.mojang.com/");
    private static final URI DEFAULT_PROFILE_URI = URI.create("https://api.mojang.com/profiles/");
    private static final URI DEFAULT_SESSION_URI = URI.create("https://sessionserver.mojang.com/session/minecraft/");
    private static final String[] DEFAULT_WHITELISTED_DOMAINS = { ".minecraft.net", ".mojang.com" };
    private static final PublicKey DEFAULT_SIGNATURE_KEY;

    private static URI rootUri = null;
    private static URI authUri = DEFAULT_AUTH_URI;
    private static URI profileUri = DEFAULT_PROFILE_URI;
    private static URI sessionUri = DEFAULT_SESSION_URI;
    private static String[] whitelistedDomains = DEFAULT_WHITELISTED_DOMAINS;
    private static PublicKey signatureKey;
    private static Proxy proxy;

    static {
        try (InputStream in = SessionService.class.getResourceAsStream("/yggdrasil_session_pubkey.der")) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int length = -1;
            while ((length = in.read(buffer)) != -1)
                out.write(buffer, 0, length);
            out.close();
            DEFAULT_SIGNATURE_KEY = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(out.toByteArray()));
            signatureKey = DEFAULT_SIGNATURE_KEY;
        } catch (Exception e) {
            throw new ExceptionInInitializerError("Missing/invalid yggdrasil public key.");
        }
    }

    public static URI getAuthURI() { return authUri; }
    public static URI getProfileURI() { return profileUri; }
    public static URI getSessionURI() { return sessionUri; }
    public static boolean canMigrate() { return rootUri == null; }
    public static String[] getWhitelistedDomains() { return whitelistedDomains; }
    public static PublicKey getSignatureKey() { return signatureKey; }
    public static Proxy getProxy() { return proxy; }
    public static void setProxy(Proxy proxy) { ServiceRoot.proxy = proxy; }

    /**
     * Register Yggdrasil service root URI.
     *
     * @param rootUri             The root of unofficial Yggdrasil service. Leave space
     *                            if you want to turn back to the official one.
     * @throws RequestException   If an error occurs while making the request.
     */
    public static void registerYggdrasilServiceRoot(URI rootUri) throws RequestException {
        if (rootUri != null) {
            ServiceRoot.rootUri = rootUri;
            ServiceRoot.authUri = rootUri.resolve("authserver/");
            ServiceRoot.profileUri = rootUri.resolve("api/profiles/");
            ServiceRoot.sessionUri = rootUri.resolve("sessionserver/session/minecraft/");

            ServiceMetaData metaData = HTTP.makeRequest(getProxy(), rootUri, null, ServiceRoot.ServiceMetaData.class);
            List<String> domains = new ArrayList<>();
            domains.addAll(Arrays.asList(DEFAULT_WHITELISTED_DOMAINS));
            domains.addAll(Arrays.asList(metaData.skinDomains));
            ServiceRoot.whitelistedDomains = domains.toArray(new String[domains.size()]);
            
            String publickeyPem = metaData.signaturePublickey;
            publickeyPem = publickeyPem.replace("-----BEGIN PUBLIC KEY-----\n","");
            publickeyPem = publickeyPem.replace("-----END PUBLIC KEY-----","");
            byte[] encoded = Base64.decode(publickeyPem.getBytes());
            try {
                signatureKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encoded));
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
            }
        } else {
            ServiceRoot.rootUri = rootUri;
            ServiceRoot.authUri = DEFAULT_AUTH_URI;
            ServiceRoot.profileUri = DEFAULT_PROFILE_URI;
            ServiceRoot.sessionUri = DEFAULT_SESSION_URI;
            ServiceRoot.whitelistedDomains = DEFAULT_WHITELISTED_DOMAINS;
            ServiceRoot.signatureKey = DEFAULT_SIGNATURE_KEY;
        }
    }

    public static class ServiceMetaData {
        public Object meta;
        public String[] skinDomains;
        public String signaturePublickey;
    }
}
