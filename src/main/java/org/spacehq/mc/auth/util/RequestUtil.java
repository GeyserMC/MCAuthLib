package org.spacehq.mc.auth.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.spacehq.mc.auth.exception.authentication.AuthenticationException;
import org.spacehq.mc.auth.exception.authentication.AuthenticationUnavailableException;
import org.spacehq.mc.auth.exception.authentication.InvalidCredentialsException;
import org.spacehq.mc.auth.exception.authentication.UserMigratedException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.util.UUID;

/**
 * Utilities for making HTTP requests.
 */
public class RequestUtil {
    private static final Gson GSON;

    static {
        GSON = new GsonBuilder().registerTypeAdapter(UUID.class, new UUIDSerializer()).create();
    }

    private RequestUtil() {
    }

    /**
     * Makes an HTTP request.
     *
     * @param proxy Proxy to use when making the request.
     * @param url   URL to make the request to.
     * @param input Input to provide in the request.
     * @param clazz Class to provide the response as.
     * @return The response of the request.
     * @throws AuthenticationException If an authentication error occurs.
     */
    public static <T> T makeRequest(Proxy proxy, String url, Object input, Class<T> clazz) throws AuthenticationException {
        T result = null;
        try {
            String jsonString = input == null ? performGetRequest(proxy, url) : performPostRequest(proxy, url, GSON.toJson(input), "application/json");
            result = GSON.fromJson(jsonString, clazz);
        } catch(Exception e) {
            throw new AuthenticationUnavailableException("Could not make request to auth server.", e);
        }

        if(result instanceof Response) {
            Response response = (Response) result;
            if(response.getError() != null && !response.getError().equals("")) {
                if(response.getCause() != null && response.getCause().equals("UserMigratedException")) {
                    throw new UserMigratedException(response.getErrorMessage());
                } else if(response.getError().equals("ForbiddenOperationException")) {
                    throw new InvalidCredentialsException(response.getErrorMessage());
                } else {
                    throw new AuthenticationException(response.getErrorMessage());
                }
            }
        }

        return result;
    }

    private static HttpURLConnection createUrlConnection(Proxy proxy, String url) throws IOException {
        if(proxy == null) {
            throw new IllegalArgumentException("Proxy cannot be null.");
        }

        if(url == null) {
            throw new IllegalArgumentException("URL cannot be null.");
        }

        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection(proxy);
        connection.setConnectTimeout(15000);
        connection.setReadTimeout(15000);
        connection.setUseCaches(false);
        return connection;
    }

    private static String performGetRequest(Proxy proxy, String url) throws IOException {
        if(proxy == null) {
            throw new IllegalArgumentException("Proxy cannot be null.");
        }

        if(url == null) {
            throw new IllegalArgumentException("URL cannot be null.");
        }

        HttpURLConnection connection = createUrlConnection(proxy, url);
        connection.setDoInput(true);

        InputStream in = null;
        try {
            int responseCode = connection.getResponseCode();
            if(responseCode == 200) {
                in = connection.getInputStream();
            } else {
                in = connection.getErrorStream();
            }

            if(in != null) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(in));
                StringBuilder result = new StringBuilder();
                String line = null;
                while((line = reader.readLine()) != null) {
                    result.append(line).append("\n");
                }

                return result.toString();
            } else {
                return "";
            }
        } finally {
            if(in != null) {
                try {
                    in.close();
                } catch(IOException e) {
                }
            }
        }
    }

    private static String performPostRequest(Proxy proxy, String url, String post, String type) throws IOException {
        if(proxy == null) {
            throw new IllegalArgumentException("Proxy cannot be null.");
        }

        if(url == null) {
            throw new IllegalArgumentException("URL cannot be null.");
        }

        if(post == null) {
            throw new IllegalArgumentException("Post cannot be null.");
        }

        if(type == null) {
            throw new IllegalArgumentException("Type cannot be null.");
        }

        byte[] bytes = post.getBytes("UTF-8");

        HttpURLConnection connection = createUrlConnection(proxy, url);
        connection.setRequestProperty("Content-Type", type + "; charset=utf-8");
        connection.setRequestProperty("Content-Length", String.valueOf(bytes.length));
        connection.setDoInput(true);
        connection.setDoOutput(true);

        OutputStream out = null;
        try {
            out = connection.getOutputStream();
            out.write(bytes);
        } finally {
            if(out != null) {
                try {
                    out.close();
                } catch(IOException e) {
                }
            }
        }

        InputStream in = null;
        try {
            int responseCode = connection.getResponseCode();
            if(responseCode == 200) {
                in = connection.getInputStream();
            } else {
                in = connection.getErrorStream();
            }

            if(in != null) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(in));
                StringBuilder result = new StringBuilder();
                String line = null;
                while((line = reader.readLine()) != null) {
                    result.append(line).append("\n");
                }

                return result.toString();
            } else {
                return "";
            }
        } finally {
            if(in != null) {
                try {
                    in.close();
                } catch(IOException e) {
                }
            }
        }
    }

    /**
     * Basic response containing error details, if available.
     */
    public static class Response {
        private String error;
        private String errorMessage;
        private String cause;

        /**
         * Gets the error contained in this response.
         *
         * @return The response's error.
         */
        public String getError() {
            return this.error;
        }

        /**
         * Gets the cause of the error contained in this response.
         *
         * @return The response's error cause.
         */
        public String getCause() {
            return this.cause;
        }

        /**
         * Gets the error message contained in this response.
         *
         * @return The response's error message.
         */
        public String getErrorMessage() {
            return this.errorMessage;
        }
    }
}
