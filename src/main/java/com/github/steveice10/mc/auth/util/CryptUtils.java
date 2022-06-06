package com.github.steveice10.mc.auth.util;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class CryptUtils {

    private static byte[] stripHeaderFooter(String key, String header, String footer) {
        int headerIndex = key.indexOf(header);
        if (headerIndex != -1) {
            headerIndex += header.length();
            int footerIndex = key.indexOf(footer, headerIndex);
            key = key.substring(headerIndex, footerIndex + 1);
        }

        return Base64.getMimeDecoder().decode(key);
    }

    public static PrivateKey stringToPemRsaPrivateKey(String key) throws GeneralSecurityException {
        byte[] stripped = stripHeaderFooter(key, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----");
        return byteToPrivateKey(stripped);
    }

    public static PublicKey stringToRsaPublicKey(String key) throws GeneralSecurityException {
        byte[] stripped = stripHeaderFooter(key, "-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----");
        return byteToPublicKey(stripped);
    }

    private static PrivateKey byteToPrivateKey(byte[] encodedKey) throws GeneralSecurityException {
        EncodedKeySpec spec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePrivate(spec);
    }

    public static PublicKey byteToPublicKey(byte[] encodedKey) throws GeneralSecurityException {
        EncodedKeySpec spec = new X509EncodedKeySpec(encodedKey);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(spec);
    }

    private CryptUtils() {
    }
}
