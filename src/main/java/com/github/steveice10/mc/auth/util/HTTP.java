package com.github.steveice10.mc.auth.util;

import com.github.steveice10.mc.auth.exception.request.InvalidCredentialsException;
import com.github.steveice10.mc.auth.exception.request.RequestException;
import com.github.steveice10.mc.auth.exception.request.ServiceUnavailableException;
import com.github.steveice10.mc.auth.exception.request.UserMigratedException;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * Utilities for making HTTP requests.
 */
public class HTTP {
    private static final Gson GSON;

    static {
        GSON = new GsonBuilder().registerTypeAdapter(UUID.class, new UUIDSerializer()).create();
    }

    private HTTP() {
    }

    /**
     * Makes an HTTP request.
     *
     * @param proxy Proxy to use when making the request.
     * @param uri   URI to make the request to.
     * @param input Input to provide in the request.
     * @throws IllegalArgumentException If the given proxy or URI is null.
     * @throws RequestException If an error occurs while making the request.
     */
    public static void makeRequest(Proxy proxy, URI uri, Object input) throws RequestException {
        makeRequest(proxy, uri, input, null);
    }

    /**
     * Makes an HTTP request.
     *
     * @param proxy        Proxy to use when making the request.
     * @param uri          URI to make the request to.
     * @param input        Input to provide in the request.
     * @param responseType Class to provide the response as.
     * @param <T>          Type to provide the response as.
     * @return The response of the request.
     * @throws IllegalArgumentException If the given proxy or URI is null.
     * @throws RequestException If an error occurs while making the request.
     */
    public static <T> T makeRequest(Proxy proxy, URI uri, Object input, Class<T> responseType) throws RequestException {
        if(proxy == null) {
            throw new IllegalArgumentException("Proxy cannot be null.");
        } else if(uri == null) {
            throw new IllegalArgumentException("URI cannot be null.");
        }

        JsonElement response;
        try {
            response = input == null ? performGetRequest(proxy, uri) : performPostRequest(proxy, uri, GSON.toJson(input), "application/json");
        } catch(IOException e) {
            throw new ServiceUnavailableException("Could not make request to '" + uri + "'.", e);
        }

        if(response != null) {
            checkForError(response);

            if(responseType != null) {
                return GSON.fromJson(response, responseType);
            }
        }

        return null;
    }

    private static void checkForError(JsonElement response) throws RequestException {
        if(response.isJsonObject()) {
            JsonObject object = response.getAsJsonObject();
            if(object.has("error")) {
                String error = object.get("error").getAsString();
                String cause = object.has("cause") ? object.get("cause").getAsString() : "";
                String errorMessage = object.has("errorMessage") ? object.get("errorMessage").getAsString() : "";
                if(!error.equals("")) {
                    if(error.equals("ForbiddenOperationException")) {
                        if(cause != null && cause.equals("UserMigratedException")) {
                            throw new UserMigratedException(errorMessage);
                        } else {
                            throw new InvalidCredentialsException(errorMessage);
                        }
                    } else {
                        throw new RequestException(errorMessage);
                    }
                }
            }
        }
    }

    private static JsonElement performGetRequest(Proxy proxy, URI uri) throws IOException {
        HttpURLConnection connection = createUrlConnection(proxy, uri);
        connection.setDoInput(true);

        return processResponse(connection);
    }

    private static JsonElement performPostRequest(Proxy proxy, URI uri, String post, String type) throws IOException {
        byte[] bytes = post.getBytes(StandardCharsets.UTF_8);

        HttpURLConnection connection = createUrlConnection(proxy, uri);
        connection.setRequestProperty("Content-Type", type + "; charset=utf-8");
        connection.setRequestProperty("Content-Length", String.valueOf(bytes.length));
        connection.setDoInput(true);
        connection.setDoOutput(true);

        try(OutputStream out = connection.getOutputStream()) {
            out.write(bytes);
        }

        return processResponse(connection);
    }

    private static HttpURLConnection createUrlConnection(Proxy proxy, URI uri) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) uri.toURL().openConnection(proxy);
        connection.setConnectTimeout(15000);
        connection.setReadTimeout(15000);
        connection.setUseCaches(false);
        return connection;
    }

    private static JsonElement processResponse(HttpURLConnection connection) throws IOException {
        try(InputStream in = connection.getResponseCode() == 200 ? connection.getInputStream() : connection.getErrorStream()) {
            return in != null ? GSON.fromJson(new InputStreamReader(in), JsonElement.class) : null;
        }
    }
}
