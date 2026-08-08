/*
 * In-Game Account Switcher with Ely.by OAuth2 patch (Public Client Flow with PKCE).
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
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

/**
 * MSAuth rewritten to perform Ely.by OAuth2 Authentication with PKCE.
 */
public final class MSAuth {
    public static final String ELY_CLIENT_ID = "ely-account-switcher";
    
    // PKCE code verifier storage (thread-safe)
    private static volatile String currentCodeVerifier;

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
     * Generates PKCE code_verifier (random 43-128 character string).
     * Must be called BEFORE generating authorization URL.
     */
    @NotNull
    public static String generateCodeVerifier() {
        SecureRandom sr = new SecureRandom();
        byte[] code = new byte[32];
        sr.nextBytes(code);
        currentCodeVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(code);
        return currentCodeVerifier;
    }

    /**
     * Generates PKCE code_challenge from code_verifier using SHA-256.
     */
    @NotNull
    public static String generateCodeChallenge(@NotNull String verifier) {
        try {
            byte[] bytes = verifier.getBytes(StandardCharsets.US_ASCII);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(bytes);
            byte[] digest = md.digest();
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate PKCE code challenge", e);
        }
    }

    /**
     * Builds Ely.by OAuth2 authorization URL with PKCE.
     * Call this to get the URL to open in browser.
     * 
     * @param redirectUri Must match the URI registered in Ely.by app settings
     * @return Full authorization URL
     */
    @NotNull
    public static String getAuthorizationUrl(@NotNull String redirectUri) {
        String verifier = generateCodeVerifier();
        String challenge = generateCodeChallenge(verifier);
        
        return "https://account.ely.by/oauth2/v1?" +
                "client_id=" + URLEncoder.encode(ELY_CLIENT_ID, StandardCharsets.UTF_8) +
                "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8) +
                "&response_type=code" +
                "&scope=" + URLEncoder.encode("account_info minecraft_server_session", StandardCharsets.UTF_8) +
                "&code_challenge=" + URLEncoder.encode(challenge, StandardCharsets.UTF_8) +
                "&code_challenge_method=S256";
    }

    /**
     * Exchanges Ely.by OAuth2 Authorization Code for access & refresh tokens.
     * Requires PKCE code_verifier generated earlier.
     */
    @CheckReturnValue
    @NotNull
    public static CompletableFuture<MSTokens> msacToMsaMsr(@NotNull String code, @NotNull String redirect) {
        if (currentCodeVerifier == null) {
            return CompletableFuture.failedFuture(
                new IllegalStateException("PKCE code_verifier is missing. Did you call generateCodeVerifier()?")
            );
        }

        String payload = "client_id=" + URLEncoder.encode(ELY_CLIENT_ID, StandardCharsets.UTF_8) +
                "&grant_type=authorization_code" +
                "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8) +
                "&redirect_uri=" + URLEncoder.encode(redirect, StandardCharsets.UTF_8) +
                "&code_verifier=" + URLEncoder.encode(currentCodeVerifier, StandardCharsets.UTF_8);

        return CLIENT.sendAsync(HttpRequest.newBuilder()
                .uri(URI.create("https://account.ely.by/api/oauth2/v1/token"))
                .header("User-Agent", IAS.USER_AGENT)
                .header("Accept", "application/json")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .timeout(IAS.TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build(), HttpResponse.BodyHandlers.ofString()).thenApplyAsync(response -> {
            try {
                int status = response.statusCode();
                String body = response.body();
                
                if (status != HttpURLConnection.HTTP_OK) {
                    IAS.LOGGER.error("[Ely.by] Token exchange failed. Status: {}, Body: {}", status, body);
                    throw new FriendlyException("Failed to login with Ely.by", "ias.error.elyby.token");
                }
                
                JsonObject json = GSONUtils.GSON.fromJson(body, JsonObject.class);
                Objects.requireNonNull(json, "Ely.by token response is null");

                // Map Ely.by response to MSTokens format
                JsonObject mapped = new JsonObject();
                mapped.addProperty("access_token", GSONUtils.getStringOrThrow(json, "access_token"));
                mapped.addProperty("refresh_token", GSONUtils.getStringOrThrow(json, "refresh_token"));
                
                // Clear code_verifier after successful exchange
                currentCodeVerifier = null;
                
                return MSTokens.fromJson(mapped);
            } catch (Throwable t) {
                IAS.LOGGER.error("[Ely.by] Failed to parse token response", t);
                throw new RuntimeException("Unable to exchange Ely.by OAuth2 code.", t);
            }
        }, IAS.executor());
    }

    /**
     * Refreshes Ely.by OAuth2 Token.
     */
    @CheckReturnValue
    @NotNull
    public static CompletableFuture<MSTokens> msrToMsaMsr(@NotNull String refresh) {
        String payload = "client_id=" + URLEncoder.encode(ELY_CLIENT_ID, StandardCharsets.UTF_8) +
                "&grant_type=refresh_token" +
                "&refresh_token=" + URLEncoder.encode(refresh, StandardCharsets.UTF_8);

        return CLIENT.sendAsync(HttpRequest.newBuilder()
                .uri(URI.create("https://account.ely.by/api/oauth2/v1/token"))
                .header("User-Agent", IAS.USER_AGENT)
                .header("Accept", "application/json")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .timeout(IAS.TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build(), HttpResponse.BodyHandlers.ofString()).thenApplyAsync(response -> {
            try {
                int status = response.statusCode();
                String body = response.body();
                
                if (status != HttpURLConnection.HTTP_OK) {
                    IAS.LOGGER.warn("[Ely.by] Token refresh failed. Status: {}", status);
                    throw new FriendlyException("Ely.by session expired.", "ias.error.session");
                }
                
                JsonObject json = GSONUtils.GSON.fromJson(body, JsonObject.class);
                Objects.requireNonNull(json, "Ely.by refresh response is null");

                JsonObject mapped = new JsonObject();
                mapped.addProperty("access_token", GSONUtils.getStringOrThrow(json, "access_token"));
                mapped.addProperty("refresh_token", GSONUtils.getStringOrThrow(json, "refresh_token"));
                
                return MSTokens.fromJson(mapped);
            } catch (Throwable t) {
                IAS.LOGGER.error("[Ely.by] Failed to refresh token", t);
                throw new RuntimeException("Unable to refresh Ely.by OAuth2 token.", t);
            }
        }, IAS.executor());
    }

    /**
     * Fetches Minecraft profile from Ely.by using access token.
     */
    @CheckReturnValue
    @NotNull
    public static CompletableFuture<MCProfile> mcaToMcp(@NotNull String access) {
        return CLIENT.sendAsync(HttpRequest.newBuilder()
                .uri(URI.create("https://account.ely.by/api/account/v1/info"))
                .header("User-Agent", IAS.USER_AGENT)
                .header("Authorization", "Bearer " + access)
                .timeout(IAS.TIMEOUT)
                .GET()
                .build(), HttpResponse.BodyHandlers.ofString()).thenApplyAsync(response -> {
            try {
                int status = response.statusCode();
                String body = response.body();
                
                if (status != HttpURLConnection.HTTP_OK) {
                    IAS.LOGGER.error("[Ely.by] Failed to fetch account info. Status: {}, Body: {}", status, body);
                    throw new FriendlyException("Failed to get Ely.by profile", "ias.error.elyby.profile");
                }
                
                JsonObject json = GSONUtils.GSON.fromJson(body, JsonObject.class);
                Objects.requireNonNull(json, "Ely.by account info is null");
                
                // Ely.by returns: { "uuid": "...", "username": "...", ... }
                String uuid = GSONUtils.getStringOrThrow(json, "uuid");
                String username = GSONUtils.getStringOrThrow(json, "username");
                
                // Map to MCProfile format
                JsonObject profile = new JsonObject();
                profile.addProperty("id", uuid.replace("-", "")); // Remove dashes from UUID
                profile.addProperty("name", username);
                
                IAS.LOGGER.info("[Ely.by] Logged in as: {} ({})", username, uuid);
                
                return MCProfile.fromJson(profile);
            } catch (Throwable t) {
                IAS.LOGGER.error("[Ely.by] Failed to parse account info", t);
                throw new RuntimeException("Failed fetching profile from Ely.by.", t);
            }
        }, IAS.executor());
    }

    // --- XBOX AUTH BYPASS (Not used for Ely.by) ---

    @CheckReturnValue
    @NotNull
    public static CompletableFuture<XHashedToken> msaToXbl(@NotNull String authToken) {
        try {
            // Create dummy XBL token (Ely.by doesn't use Xbox Live)
            JsonObject xuiObj = new JsonObject();
            xuiObj.addProperty("uhs", "ely-bypass");
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
        return msaToXbl(xbl); // Pass-through
    }

    @CheckReturnValue
    @NotNull
    public static CompletableFuture<String> xstsToMca(@NotNull String xsts, @NotNull String hash) {
        return CompletableFuture.completedFuture(xsts); // Pass-through
    }

    /**
     * Resolves Minecraft profile by username from Ely.by.
     */
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
                String body = response.body();
                
                if (status == HttpURLConnection.HTTP_NO_CONTENT || status == HttpURLConnection.HTTP_NOT_FOUND) {
                    throw new FriendlyException("Ely.by profile not found: " + name, "ias.error.elyby.notfound");
                }
                
                if (status != HttpURLConnection.HTTP_OK) {
                    IAS.LOGGER.error("[Ely.by] Failed to resolve profile. Status: {}, Body: {}", status, body);
                    throw new IllegalArgumentException("Invalid profile status: " + status);
                }
                
                JsonObject json = GSONUtils.GSON.fromJson(body, JsonObject.class);
                Objects.requireNonNull(json, "Ely.by profile response is null");
                
                return MCProfile.fromJson(json);
            } catch (Throwable t) {
                IAS.LOGGER.error("[Ely.by] Failed to resolve profile by name: {}", name, t);
                throw new RuntimeException("Unable to resolve Ely.by profile by name: " + name, t);
            }
        }, IAS.executor());
    }

    // --- DISABLED FLOWS ---

    @CheckReturnValue
    @NotNull
    public static CompletableFuture<DeviceAuth> requestDac() {
        return CompletableFuture.failedFuture(
            new UnsupportedOperationException("Device Code flow is not supported by Ely.by.")
        );
    }

    @CheckReturnValue
    @NotNull
    public static MSTokens dacToMsaMsr(@NotNull String code) {
        throw new UnsupportedOperationException("Device Code flow is not supported by Ely.by.");
    }
}
