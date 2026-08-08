/*
 * In-Game Account Switcher with Ely.by OAuth2 patch.
 */

package ru.vidtu.ias.auth.microsoft;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpServer;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.vidtu.ias.IAS;
import ru.vidtu.ias.account.MicrosoftAccount;
import ru.vidtu.ias.auth.handlers.CreateHandler;
import ru.vidtu.ias.config.IASConfig;
import ru.vidtu.ias.crypt.Crypt;
import ru.vidtu.ias.utils.Holder;
import ru.vidtu.ias.utils.IUtils;
import ru.vidtu.ias.utils.exceptions.FriendlyException;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * HTTP server listening for Ely.by redirect callback.
 */
public final class MSAuthServer implements Runnable, Closeable {
    @NotNull
    private static final String ELY_AUTH_URL = "https://ely.by/oauth2/v1/authorize" +
            "?client_id=" + MSAuth.ELY_CLIENT_ID +
            "&response_type=code" +
            "&scope=minecraft" +
            "&redirect_uri=http://localhost:%%port%%/ias" +
            "&state=%%state%%";

    @NotNull
    private static final String REDIRECT_URI = "http://localhost:%s/ias";

    @NotNull
    private static final String END_URI = "http://localhost:%s/end";

    @NotNull
    private static final String STATE_CHARACTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_";

    @NotNull
    private static final Pattern DATA_EXTRACT_PATTERN = Pattern.compile("^code=([^&]*)&state=([^&]*)$");

    @NotNull
    private static final Pattern CODE_OBFUSCATE_PATTERN = Pattern.compile("code=[^&]*", Pattern.CASE_INSENSITIVE);

    @NotNull
    public static final Logger LOGGER = LoggerFactory.getLogger("IAS/MSAuthServer");

    @NotNull
    private final String doneMessage;
    @NotNull
    private final Crypt crypt;
    @NotNull
    private final CreateHandler handler;
    @NotNull
    private final HttpServer server;
    @NotNull
    private final String state;
    private int port;
    private boolean once;

    public MSAuthServer(@NotNull String doneMessage, @NotNull Crypt crypt, @NotNull CreateHandler handler) {
        try {
            this.doneMessage = doneMessage;
            this.crypt = crypt;
            this.handler = handler;
            this.server = HttpServer.create();

            SecureRandom random = SecureRandom.getInstanceStrong();
            int length = random.nextInt(96, 128);
            StringBuilder builder = new StringBuilder(length);
            for (int i = 0; i < length; i++) {
                builder.appendCodePoint(STATE_CHARACTERS.codePointAt(random.nextInt(STATE_CHARACTERS.length())));
            }
            this.state = builder.toString();
        } catch (Throwable t) {
            throw new RuntimeException("Unable to create HTTP server for Ely.by OAuth.", t);
        }
    }

    @Override
    public void run() {
        try {
            if (this.handler.cancelled()) return;

            LOGGER.info("IAS: Booting up local Ely.by Callback Server...");
            this.handler.stage(MicrosoftAccount.SERVER);

            this.server.createContext("/", ex -> {
                try {
                    if (this.once) {
                        ex.close();
                        return;
                    }

                    if (!ex.getRemoteAddress().getAddress().isLoopbackAddress()) {
                        ex.close();
                        return;
                    }

                    this.once = true;
                    URI uri = ex.getRequestURI();

                    byte[] data;
                    try (InputStream in = MSAuthServer.class.getResourceAsStream("/ias_auth.html")) {
                        Objects.requireNonNull(in, "Auth page is null.");
                        String page = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                        page = page
                                .replace("%%ias_icon%%", IASConfig.unexpectedPigs ? "🐷👍" : "✅")
                                .replace("%%ias_message%%", this.doneMessage);
                        data = page.getBytes(StandardCharsets.UTF_8);
                    }

                    Headers headers = ex.getResponseHeaders();
                    headers.add("Content-Type", "text/html; charset=UTF-8");
                    headers.add("Content-Length", Integer.toString(data.length));
                    headers.add("Server", IAS.USER_AGENT);
                    headers.add("Location", END_URI.formatted(this.port));
                    ex.sendResponseHeaders(302, data.length);

                    try (OutputStream out = ex.getResponseBody()) {
                        out.write(data);
                    }
                    ex.close();

                    this.auth(uri);
                    IAS.executor().schedule(this::close, 10L, TimeUnit.SECONDS);
                } catch (Throwable t) {
                    try { ex.close(); } catch (Throwable ignored) {}
                    try { this.close(); } catch (Throwable ignored) {}
                    this.handler.error(new RuntimeException("Unexpected exception on Ely.by callback: " + ex, t));
                }
            });

            this.server.createContext("/end", ex -> {
                try {
                    if (!ex.getRemoteAddress().getAddress().isLoopbackAddress()) {
                        ex.close();
                        return;
                    }

                    byte[] data;
                    try (InputStream in = MSAuthServer.class.getResourceAsStream("/ias_auth.html")) {
                        Objects.requireNonNull(in, "Auth page is null.");
                        String page = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                        page = page
                                .replace("%%ias_icon%%", IASConfig.unexpectedPigs ? "🐷👍" : "✅")
                                .replace("%%ias_message%%", this.doneMessage);
                        data = page.getBytes(StandardCharsets.UTF_8);
                    }

                    Headers headers = ex.getResponseHeaders();
                    headers.add("Content-Type", "text/html; charset=UTF-8");
                    headers.add("Content-Length", Integer.toString(data.length));
                    headers.add("Server", IAS.USER_AGENT);
                    ex.sendResponseHeaders(200, data.length);

                    try (OutputStream out = ex.getResponseBody()) {
                        out.write(data);
                    }
                    ex.close();
                    IAS.executor().schedule(this::close, 10L, TimeUnit.SECONDS);
                } catch (Throwable t) {
                    try { ex.close(); } catch (Throwable ignored) {}
                    try { this.close(); } catch (Throwable ignored) {}
                    this.handler.error(new RuntimeException("Unexpected exception on '/end': " + ex, t));
                }
            });

            if (this.handler.cancelled()) return;

            this.bindToSupportedPort();
            this.server.start();
            LOGGER.info("IAS: Ely.by Callback Server started on port " + this.port);
        } catch (Throwable t) {
            try { this.close(); } catch (Throwable ignored) {}
            throw new RuntimeException("Unable to start Ely.by callback server.", t);
        }
    }

    private void bindToSupportedPort() {
        List<RuntimeException> thrown = new LinkedList<>();
        for (int port : IUtils.tryBindPorts()) {
            try {
                this.server.bind(new InetSocketAddress(port), 0);
                this.port = port;
                return;
            } catch (Throwable t) {
                thrown.add(new RuntimeException("Unable to bind to port: " + port, t));
            }
        }
        RuntimeException holder = new RuntimeException("Unable to bind callback server to any port.");
        thrown.forEach(holder::addSuppressed);
        throw holder;
    }

    @Contract(pure = true)
    @NotNull
    public String authUrl() {
        return ELY_AUTH_URL
                .replace("%%port%%", Integer.toString(this.port))
                .replace("%%state%%", this.state);
    }

    private void auth(@NotNull URI uri) {
        try {
            if (this.handler.cancelled()) return;
            this.handler.stage(MicrosoftAccount.PROCESSING);

            String query = uri.getQuery();
            Holder<String> access = new Holder<>();
            Holder<byte[]> data = new Holder<>();

            CompletableFuture.supplyAsync(() -> {
                if (this.handler.cancelled()) return null;

                if (query == null) {
                    throw new FriendlyException("Null query.", "ias.error.query");
                }
                if (query.toLowerCase(Locale.ROOT).contains("access_denied")) {
                    throw new FriendlyException("Invalid query (access denied)", "ias.error.cancel");
                }

                Matcher matcher = DATA_EXTRACT_PATTERN.matcher(query);
                if (!matcher.matches()) {
                    throw new IllegalStateException("Invalid query received.");
                }

                String state = matcher.group(2);
                if (!this.state.equals(state)) {
                    throw new IllegalStateException("Expected state mismatched.");
                }

                return matcher.group(1);
            }, IAS.executor()).thenComposeAsync(code -> {
                if (code == null || this.handler.cancelled()) return CompletableFuture.completedFuture(null);
                this.handler.stage(MicrosoftAccount.MSAC_TO_MSA_MSR);
                return MSAuth.msacToMsaMsr(code, REDIRECT_URI.formatted(this.port));
            }, IAS.executor()).thenComposeAsync(ms -> {
                if (ms == null || this.handler.cancelled()) return CompletableFuture.completedFuture(null);
                access.set(ms.access());
                this.handler.stage(MicrosoftAccount.MCA_TO_MCP);
                return MSAuth.mcaToMcp(ms.access());
            }, IAS.executor()).thenApplyAsync(profile -> {
                if (profile == null || this.handler.cancelled()) return null;
                this.handler.stage(MicrosoftAccount.ENCRYPTING);

                byte[] unencrypted;
                try (ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
                     DataOutputStream out = new DataOutputStream(byteOut)) {
                    out.writeUTF(access.get());
                    out.writeUTF(this.state); // Dummy value to preserve format structure
                    unencrypted = byteOut.toByteArray();
                } catch (Throwable t) {
                    throw new RuntimeException(t);
                }

                try (ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
                     DataOutputStream out = new DataOutputStream(byteOut)) {
                    byte[] encrypted = this.crypt.encrypt(unencrypted);
                    out.writeUTF(this.crypt.type());
                    out.write(encrypted);
                    data.set(byteOut.toByteArray());
                } catch (Throwable t) {
                    throw new RuntimeException(t);
                }

                return profile;
            }, IAS.executor()).thenAcceptAsync(profile -> {
                if (profile == null || this.handler.cancelled()) return;
                this.handler.stage(MicrosoftAccount.FINALIZING);

                MicrosoftAccount account = new MicrosoftAccount(this.crypt.insecure(), profile.uuid(), profile.name(), data.get());
                this.handler.success(account);
            }, IAS.executor()).exceptionallyAsync(t -> {
                this.handler.error(new RuntimeException("Unable to log in via Ely.by.", t));
                return null;
            }, IAS.executor());
        } catch (Throwable t) {
            this.handler.error(new RuntimeException("Failed to finalize Ely.by Auth.", t));
        }
    }

    @Override
    public void close() {
        this.server.stop(0);
        LOGGER.info("IAS: Ely.by Callback Server stopped.");
    }
}
