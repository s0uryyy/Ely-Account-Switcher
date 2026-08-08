/*
 * In-Game Account Switcher with Ely.by hijack patch.
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
 * Hijacked MSAuth redirecting to Ely.by.
 */
public final class MSAuth {
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
     * Authenticates with Ely.by authserver.
     */
    @CheckReturnValue
    @NotNull
    public static CompletableFuture<ElyTokens> authenticateElyBy(@NotNull String login, @NotNull String password,
                                                                 @Nullable String totp, @NotNull String clientToken) {
        JsonObject agent = new JsonObject();
        agent.addProperty("name", "Minecraft");
        agent.addProperty("version", 1);

        JsonObject request = new JsonObject();
        request.add("agent", agent);
        request.addProperty("username", login);
        request.addProperty("password", (totp == null || totp.isBlank()) ? password : password + ":" + totp);
        request.addProperty("clientToken", clientToken);
        request.addProperty("requestUser", false);
        String payload = GSONUtils.GSON.toJson(request);

        return CLIENT.sendAsync(HttpRequest.newBuilder()
                .uri(URI.create("https://authserver.ely.by/auth/authenticate"))
                .header("User-Agent", IAS.USER_AGENT)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .timeout(IAS.TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build(), HttpResponse.BodyHandlers.ofString()).thenApplyAsync(response -> {
            try {
                int status = response.statusCode();
                if (status == 401 || status == 403) {
                    JsonObject json = GSONUtils.GSON.fromJson(response.body(), JsonObject.class);
                    String error = GSONUtils.getStringOrThrow(json, "errorMessage");
                    throw new FriendlyException("Ely.by: " + error, "ias.error.credentials");
                }
                if (status != 200) {
                    throw new IllegalArgumentException("Invalid status code: " + status);
                }
                JsonObject json = GSONUtils.GSON.fromJson(response.body(), JsonObject.class);
                Objects.requireNonNull(json, "Response is null");

                String access = GSONUtils.getStringOrThrow(json, "accessToken");
                String client = GSONUtils.getStringOrThrow(json, "clientToken");
                JsonObject profileObj = json.getAsJsonObject("selectedProfile");
                MCProfile profile = MCProfile.fromJson(profileObj);

                return new ElyTokens(access, access + ":" + client, profile);
            } catch (Throwable t) {
                throw new RuntimeException("Ely.by authentication failed.", t);
            }
        }, IAS.executor());
    }

    /**
     * Refreshes Ely.by session using stored old accessToken and clientToken.
     */
    @CheckReturnValue
    @NotNull
    public static CompletableFuture<MSTokens> msrToMsaMsr(@NotNull String refresh) {
        String[] parts = refresh.split(":");
        if (parts.length < 2) {
            return CompletableFuture.failedFuture(new IllegalArgumentException("Malformed Ely.by refresh token"));
        }
        String oldAccess = parts[0];
        String clientToken = parts[1];

        JsonObject request = new JsonObject();
        request.addProperty("accessToken", oldAccess);
        request.addProperty("clientToken", clientToken);
        request.addProperty("requestUser", false);
        String payload = GSONUtils.GSON.toJson(request);

        return CLIENT.sendAsync(HttpRequest.newBuilder()
                .uri(URI.create("https://authserver.ely.by/auth/refresh"))
                .header("User-Agent", IAS.USER_AGENT)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .timeout(IAS.TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build(), HttpResponse.BodyHandlers.ofString()).thenApplyAsync(response -> {
            try {
                int status = response.statusCode();
                if (status != 200) {
                    throw new FriendlyException("Ely.by session expired.", "ias.error.session");
                }
                JsonObject json = GSONUtils.GSON.fromJson(response.body(), JsonObject.class);
                Objects.requireNonNull(json, "Response is null");

                String newAccess = GSONUtils.getStringOrThrow(json, "accessToken");
                String newClient = GSONUtils.getStringOrThrow(json, "clientToken");

                // Mock MSTokens JSON representation
                JsonObject dummy = new JsonObject();
                dummy.addProperty("access_token", newAccess);
                dummy.addProperty("refresh_token", newAccess + ":" + newClient);
                return MSTokens.fromJson(dummy);
            } catch (Throwable t) {
                throw new RuntimeException("Ely.by token refresh failed.", t);
            }
        }, IAS.executor());
    }

    /**
     * Validates Ely.by accessToken and decodes MCProfile from JWT locally.
     */
    @CheckReturnValue
    @NotNull
    public static CompletableFuture<MCProfile> mcaToMcp(@NotNull String access) {
        JsonObject request = new JsonObject();
        request.addProperty("accessToken", access);
        String payload = GSONUtils.GSON.toJson(request);

        return CLIENT.sendAsync(HttpRequest.newBuilder()
                .uri(URI.create("https://authserver.ely.by/auth/validate"))
                .header("User-Agent", IAS.USER_AGENT)
                .header("Content-Type", "application/json")
                .timeout(IAS.TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build(), HttpResponse.BodyHandlers.ofString()).thenApplyAsync(response -> {
            int status = response.statusCode();
            if (status != 204 && status != 200) {
                throw new FriendlyException("Ely.by token is invalid.", "ias.error.session");
            }

            // Decode Ely.by JWT payload to construct profile details
            try {
                String[] parts = access.split("\\.");
                if (parts.length < 2) throw new IllegalArgumentException("Invalid JWT format");
                String payloadJson = new String(java.util.Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
                JsonObject jwt = GSONUtils.GSON.fromJson(payloadJson, JsonObject.class);
                String uuid = GSONUtils.getStringOrThrow(jwt, "sub");
                String name = GSONUtils.getStringOrThrow(jwt, "name");

                JsonObject profileObj = new JsonObject();
                profileObj.addProperty("id", uuid.replace("-", ""));
                profileObj.addProperty("name", name);
                return MCProfile.fromJson(profileObj);
            } catch (Throwable t) {
                throw new RuntimeException("Failed parsing Ely.by profile JWT payload.", t);
            }
        }, IAS.executor());
    }

    // --- PASS-THROUGH STUBS TO BYPASS XBOX AUTH ---

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
                if (status != 200) {
                    throw new IllegalArgumentException("Invalid status: " + status);
                }
                JsonObject json = GSONUtils.GSON.fromJson(response.body(), JsonObject.class);
                Objects.requireNonNull(json, "Response is null");
                return MCProfile.fromJson(json);
            } catch (Throwable t) {
                throw new RuntimeException("Unable to resolve profile name: " + name, t);
            }
        }, IAS.executor());
    }

    // --- UNSUPPORTED LEGACY OAUTH STUBS ---

    @CheckReturnValue
    @NotNull
    public static CompletableFuture<DeviceAuth> requestDac() {
        return CompletableFuture.failedFuture(new UnsupportedOperationException("Unsupported"));
    }

    @CheckReturnValue
    @NotNull
    public static MSTokens dacToMsaMsr(@NotNull String code) {
        throw new UnsupportedOperationException("Unsupported");
    }

    @CheckReturnValue
    @NotNull
    public static CompletableFuture<MSTokens> msacToMsaMsr(@NotNull String code, @NotNull String redirect) {
        return CompletableFuture.failedFuture(new UnsupportedOperationException("Unsupported"));
    }

    public static final class ElyTokens {
        private final String access;
        private final String refresh;
        private final MCProfile profile;

        public ElyTokens(String access, String refresh, MCProfile profile) {
            this.access = access;
            this.refresh = refresh;
            this.profile = profile;
        }

        public String access() { return access; }
        public String refresh() { return refresh; }
        public MCProfile profile() { return profile; }
    }
}
