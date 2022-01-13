package com.github.steveice10.mc.auth.util;

import com.microsoft.aad.msal4j.ITokenCacheAccessAspect;
import com.microsoft.aad.msal4j.ITokenCacheAccessContext;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class MSALTokenPersistence implements ITokenCacheAccessAspect {
    private static final String DEFAULT_FILENAME = "msal_serialized_cache.json";
    private final Path filepath;
    private String msalTokenData;

    /**
     * @see <a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/msal-java-token-cache-serialization">Custom token cache serialization in MSAL for Java</a>
     */
    public MSALTokenPersistence() throws IOException {
        this(DEFAULT_FILENAME);
    }

    /**
     * @see <a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/msal-java-token-cache-serialization">Custom token cache serialization in MSAL for Java</a>
     */
    public MSALTokenPersistence(String filename) throws IOException {
        this.filepath = Paths.get(filename);
        this.msalTokenData = (Files.exists(this.filepath)) ? new String(Files.readAllBytes(this.filepath)) : "";
    }

    @Override
    public void beforeCacheAccess(ITokenCacheAccessContext context) {
        context.tokenCache().deserialize(this.msalTokenData);
    }

    @Override
    public void afterCacheAccess(ITokenCacheAccessContext context) {
        this.msalTokenData = context.tokenCache().serialize();

        try {
            // Create file if it doesn't exist
            if (!Files.exists(this.filepath))
                Files.createFile(this.filepath);

            Files.write(this.filepath, this.msalTokenData.getBytes());
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }
}
