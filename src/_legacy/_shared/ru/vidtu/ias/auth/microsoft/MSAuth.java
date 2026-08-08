/*
 * In-Game Account Switcher with Ely.by OAuth2 patch (Public Client Flow).
 */

package ru.vidtu.ias.auth.microsoft;

import com.google.errorprone.annotations.CheckReturnValue;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import ru.vidtu.ias.IAS;
import ru.vidtu.ias.auth.microsoft.fields.DeviceAuth;
import ru.vidtu.ias.auth.microsoft.fields.MCProfile;
import ru.vidtu.ias.auth.microsoft.fields.MSTokens;
import ru.vidtu.ias.auth.microsoft.fields.XHashedToken;
import ru.vidtu.ias.utils.GSONUtils;
import ru.vidtu.ias.utils.exceptions.FriendlyException;

import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

/**
 * MSAuth rewritten to perform Ely.by OAuth2 Authentication (No Client Secret required).
 */
public final class MSAuth {
    // Твой зарегистрированный публичный Client ID на Ely.by
    public static final String ELY_CLIENT_ID = "ely-account-switcher";

    @NotNull
    private static final HttpClient CLIENT = HttpClient.newBuilder()
            .connectTimeout(IAS.TIMEOUT)
            .version(HttpClient.Version.HTTP_2)
            .followRedirects(HttpClient.Redirect.NEVER)
            .executor(IAS.executor())
            .build();

    @Contract(value = "-> fail", pure = true)
    private MSAuth() {
        throw new AssertionError("No instances.");
    }

    /**
     * Exchanges Ely.by OAuth2 Authorization Code for access & refresh tokens (Public Client style).
     */
    @CheckReturnValue
    @NotNull
    public static CompletableFuture<MSTokens> msacToMsaMsr(@NotNull String code, @NotNull String redirect) {
        String payload = "client_id=" + ELY_CLIENT_ID +
                "&grant_type=authorization_code" +
                "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8) +
                "&redirect_uri=" + URLEncoder.encode(redirect, StandardCharsets.UTF_8);

        return CLIENT.sendAsync(HttpRequest.newBuilder()
                .uri(URI.create("https://ely.by/oauth2/v1/token"))
                .header("User-Agent", IAS.USER_AGENT)
                .header("Accept", "application/json")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .timeout(IAS.TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build(), HttpResponse.BodyHandlers.ofString()).thenApplyAsync(response -> {
            try {
                int status = response.statusCode();
                if (status != HttpURLConnection.HTTP_OK) {
                    throw new IllegalArgumentException("Invalid status code from Ely.by: " + status + ", body: " + response.body());
                }
                JsonObject json = GSONUtils.GSON.fromJson(response.body(), JsonObject.class);
                Objects.requireNonNull(json, "Response is null");

                JsonObject dummy = new JsonObject();
                dummy.addProperty("access_token", GSONUtils.getStringOrThrow(json, "access_token"));
                dummy.addProperty("refresh_token", GSONUtils.getStringOrThrow(json, "refresh_token"));
                return MSTokens.fromJson(dummy);
            } catch (Throwable t) {
                throw new RuntimeException("Unable to exchange Ely.by OAuth2 code.", t);
            }
        }, IAS.executor());
    }

    /**
     * Refreshes Ely.by OAuth2 Token (Public Client style).
     */
    @CheckReturnValue
    @NotNull
    public static CompletableFuture<MSTokens> msrToMsaMsr(@NotNull String refresh) {
        String payload = "client_id=" + ELY_CLIENT_ID +
                "&grant_type=refresh_token" +
                "&refresh_token=" + URLEncoder.encode(refresh, StandardCharsets.UTF_8);

        return CLIENT.sendAsync(HttpRequest.newBuilder()
                .uri(URI.create("https://ely.by/oauth2/v1/token"))
                .header("User-Agent", IAS.USER_AGENT)
                .header("Accept", "application/json")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .timeout(IAS.TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build(), HttpResponse.BodyHandlers.ofString()).thenApplyAsync(response -> {
            try {
                int status = response.statusCode();
                if (status != HttpURLConnection.HTTP_OK) {
                    throw new FriendlyException("Ely.by session expired.", "ias.error.session");
                }
                JsonObject json = GSONUtils.GSON.fromJson(response.body(), JsonObject.class);
                Objects.requireNonNull(json, "Response is null");

                JsonObject dummy = new JsonObject();
                dummy.addProperty("access_token", GSONUtils.getStringOrThrow(json, "access_token"));
                dummy.addProperty("refresh_token", GSONUtils.getStringOrThrow(json, "refresh_token"));
                return MSTokens.fromJson(dummy);
            } catch (Throwable t) {
                throw new RuntimeException("Unable to refresh Ely.by OAuth2 token.", t);
            }
        }, IAS.executor());
    }

    /**
     * Obtains user details from Ely.by and maps them to Minecraft Profile.
     */
    @CheckReturnValue
    @NotNull
    public static CompletableFuture<MCProfile> mcaToMcp(@NotNull String access) {
        return CLIENT.sendAsync(HttpRequest.newBuilder()
                .uri(URI.create("https://ely.by/api/oauth2/v1/userinfo"))
                .header("User-Agent", IAS.USER_AGENT)
                .header("Authorization", "Bearer " + access)
                .timeout(IAS.TIMEOUT)
                .GET()
                .build(), HttpResponse.BodyHandlers.ofString()).thenComposeAsync(response -> {
            try {
                int status = response.statusCode();
                if (status != HttpURLConnection.HTTP_OK) {
                    throw new IllegalArgumentException("Invalid userinfo status: " + status);
                }
                JsonObject json = GSONUtils.GSON.fromJson(response.body(), JsonObject.class);
                Objects.requireNonNull(json, "Response is null");
                String username = GSONUtils.getStringOrThrow(json, "username");

                return CLIENT.sendAsync(HttpRequest.newBuilder()
                        .uri(URI.create("https://authserver.ely.by/api/users/profiles/minecraft/" + URLEncoder.encode(username, StandardCharsets.UTF_8)))
                        .header("User-Agent", IAS.USER_AGENT)
                        .timeout(IAS.TIMEOUT)
                        .GET()
                        .build(), HttpResponse.BodyHandlers.ofString());
            } catch (Throwable t) {
                throw new RuntimeException("Failed fetching userinfo from Ely.by.", t);
            }
        }, IAS.executor()).thenApplyAsync(response -> {
            try {
                int status = response.statusCode();
                if (status != HttpURLConnection.HTTP_OK) {
                    throw new IllegalArgumentException("Invalid profile status: " + status);
                }
                JsonObject json = GSONUtils.GSON.fromJson(response.body(), JsonObject.class);
                Objects.requireNonNull(json, "Response is null");
                return MCProfile.fromJson(json);
            } catch (Throwable t) {
                throw new RuntimeException("Failed resolving profile from Ely.by.", t);
            }
        }, IAS.executor());
    }

    // --- XBOX AUTH PASS-THROUGH BYPASSES ---

    @CheckReturnValue
    @NotNull
    public static CompletableFuture<XHashedToken> msaToXbl(@NotNull String authToken) {
        try {
            JsonObject xuiObj = new JsonObject();
            xuiObj.addProperty("uhs", "dummy");
            JsonArray xui = new JsonArray();
            xui.add(xuiObj);
            JsonObject displayClaims = new JsonObject();
            displayClaims.add("xui", xui);
            JsonObject dummy = new JsonObject();
            dummy.addProperty("Token", authToken);
            dummy.add("DisplayClaims", displayClaims);
            return CompletableFuture.completedFuture(XHashedToken.fromJson(dummy));
        } catch (Throwable t) {
            return CompletableFuture.failedFuture(t);
        }
    }

    @CheckReturnValue
    @NotNull
    public static CompletableFuture<XHashedToken> xblToXsts(@NotNull String xbl, @Nullable String hash) {
        return msaToXbl(xbl);
    }

    @CheckReturnValue
    @NotNull
    public static CompletableFuture<String> xstsToMca(@NotNull String xsts, @NotNull String hash) {
        return CompletableFuture.completedFuture(xsts);
    }

    @CheckReturnValue
    @NotNull
    public static CompletableFuture<MCProfile> nameToMcp(@NotNull String name) {
        return CLIENT.sendAsync(HttpRequest.newBuilder()
                .uri(URI.create("https://authserver.ely.by/api/users/profiles/minecraft/" + URLEncoder.encode(name, StandardCharsets.UTF_8)))
                .header("User-Agent", IAS.USER_AGENT)
                .timeout(IAS.TIMEOUT)
                .GET()
                .build(), HttpResponse.BodyHandlers.ofString()).thenApplyAsync(response -> {
            try {
                int status = response.statusCode();
                if (status != HttpURLConnection.HTTP_OK) {
                    throw new IllegalArgumentException("Invalid profile status: " + status);
                }
                JsonObject json = GSONUtils.GSON.fromJson(response.body(), JsonObject.class);
                Objects.requireNonNull(json, "Response is null");
                return MCProfile.fromJson(json);
            } catch (Throwable t) {
                throw new RuntimeException("Unable to resolve Ely.by profile by name: " + name, t);
            }
        }, IAS.executor());
    }

    // --- DISABLED CLIENT FLOWS ---

    @CheckReturnValue
    @NotNull
    public static CompletableFuture<DeviceAuth> requestDac() {
        return CompletableFuture.failedFuture(new UnsupportedOperationException("Device Code flow is not supported by Ely.by."));
    }

    @CheckReturnValue
    @NotNull
    public static MSTokens dacToMsaMsr(@NotNull String code) {
        throw new UnsupportedOperationException("Device Code flow is not supported by Ely.by.");
    }
}
