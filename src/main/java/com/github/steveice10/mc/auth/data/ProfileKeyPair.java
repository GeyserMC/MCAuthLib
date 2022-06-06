package com.github.steveice10.mc.auth.data;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;

public class ProfileKeyPair {
    private final PrivateKey privateKey;
    private final Instant publicKeyExpiresAt;
    private final PublicKey publicKey;
    private final byte[] publicKeySignature;
    private final Instant refreshedAfter;

    public ProfileKeyPair(PrivateKey privateKey, Instant publicKeyExpiresAt, PublicKey publicKey, byte[] publicKeySignature, Instant refreshedAfter) {
        this.privateKey = privateKey;
        this.publicKeyExpiresAt = publicKeyExpiresAt;
        this.publicKey = publicKey;
        this.publicKeySignature = publicKeySignature;
        this.refreshedAfter = refreshedAfter;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public Instant getPublicKeyExpiresAt() {
        return publicKeyExpiresAt;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public byte[] getPublicKeySignature() {
        return publicKeySignature;
    }

    public Instant getRefreshedAfter() {
        return refreshedAfter;
    }
}
