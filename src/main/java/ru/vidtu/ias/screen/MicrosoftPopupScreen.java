/*
 * In-Game Account Switcher with Ely.by OAuth2 patch.
 */

package ru.vidtu.ias.screen;

import net.minecraft.ChatFormatting;
import net.minecraft.client.KeyboardHandler;
//? if >=26.1 {
import net.minecraft.client.gui.GuiGraphicsExtractor;
//?} else
/*import net.minecraft.client.gui.GuiGraphics;*/
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.MultiLineLabel;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.resources.language.I18n;
import net.minecraft.network.chat.CommonComponents;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.Style;
import net.minecraft.util.FormattedCharSequence;
import org.joml.Matrix3x2fStack;
import org.lwjgl.glfw.GLFW;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.vidtu.ias.IAS;
import ru.vidtu.ias.account.Account;
import ru.vidtu.ias.account.MicrosoftAccount;
import ru.vidtu.ias.auth.handlers.CreateHandler;
import ru.vidtu.ias.auth.microsoft.MSAuthServer;
import ru.vidtu.ias.config.IASConfig;
import ru.vidtu.ias.crypt.Crypt;
import ru.vidtu.ias.crypt.PasswordCrypt;
import ru.vidtu.ias.platform.IStonecutter;
import ru.vidtu.ias.utils.exceptions.FriendlyException;

import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Pop-up screen that launches local HTTP server and opens Ely.by login page.
 */
final class MicrosoftPopupScreen extends Screen implements CreateHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger("IAS/MicrosoftPopupScreen");

    private final Screen parent;
    private final Object lock = new Object();
    private final Consumer<Account> handler;
    private Crypt crypt;
    private MSAuthServer server;

    private Component stage = Component.translatable(MicrosoftAccount.INITIALIZING).withStyle(ChatFormatting.YELLOW);
    private MultiLineLabel label;

    private PopupBox password;
    private MultiLineLabel cryptPasswordTip;
    private float error = Float.NaN;
    private MultiLineLabel errorNote;

    MicrosoftPopupScreen(Screen parent, Consumer<Account> handler, Crypt crypt) {
        super(Component.literal("Ely.by Login"));
        this.parent = parent;
        this.handler = handler;
        this.crypt = crypt;
    }

    @Override
    public boolean cancelled() {
        assert this.minecraft != null;
        return this != this.currentScreen();
    }

    @Override
    protected void init() {
        assert this.minecraft != null;
        synchronized (this.lock) {
            this.label = null;
        }

        if (this.parent != null) {
            //? if >=1.21.11 {
            this.parent.init(this.width, this.height);
            //?} else
            /*this.parent.init(this.minecraft, this.width, this.height);*/
        }

        this.addRenderableWidget(new PopupButton(this.width / 2 - 75, this.height / 2 + 74 - 22, 150, 20,
                CommonComponents.GUI_BACK, btn -> this.onClose(), Supplier::get));

        if (this.crypt == null) {
            this.password = new PopupBox(this.font, this.width / 2 - 100, this.height / 2 - 10 + 5, 178, 20, this.password, Component.translatable("ias.password"), () -> {
                if (this.password == null || this.crypt != null) return;
                String value = this.password.getValue();
                if (value.isBlank()) return;

                this.crypt = new PasswordCrypt(value);
                this.password = null;
                this.cryptPasswordTip = null;

                //? if >=1.21.11 {
                this.init(this.width, this.height);
                //?} else
                /*this.init(this.minecraft, this.width, this.height);*/
            }, true);
            this.password.setHint(Component.translatable("ias.password.hint").withStyle(ChatFormatting.DARK_GRAY));
            //? if >=1.21.10 {
            this.password.addFormatter((s, i) -> IASConfig.passwordEchoing ? FormattedCharSequence.forward("*".repeat(s.length()), Style.EMPTY) : FormattedCharSequence.EMPTY);
            //?} else
            /*this.password.setFormatter((s, i) -> IASConfig.passwordEchoing ? FormattedCharSequence.forward("*".repeat(s.length()), Style.EMPTY) : FormattedCharSequence.EMPTY);*/
            this.password.setMaxLength(32);
            this.addRenderableWidget(this.password);

            Button enterPassword = new PopupButton(this.width / 2 - 100 + 180, this.height / 2 - 10 + 5, 20, 20, Component.literal(">>"), btn -> {
                if (this.password == null || this.crypt != null) return;
                String value = this.password.getValue();
                if (value.isBlank()) return;

                this.crypt = new PasswordCrypt(value);
                this.password = null;
                this.cryptPasswordTip = null;

                //? if >=1.21.11 {
                this.init(this.width, this.height);
                //?} else
                /*this.init(this.minecraft, this.width, this.height);*/
            }, Supplier::get);
            enterPassword.active = !this.password.getValue().isBlank();
            this.addRenderableWidget(enterPassword);
            this.password.setResponder(value -> enterPassword.active = !value.isBlank());

            this.cryptPasswordTip = MultiLineLabel.create(this.font, Component.translatable("ias.password.tip"), 320);
        }

        IAS.executor().execute(this::server);
    }

    private void server() {
        try {
            assert this.minecraft != null;
            if (this.crypt == null || this.server != null) return;

            // Use translation "ias.login.done" or fallback
            String doneMessage = I18n.get("ias.login.done");
            if (doneMessage.equals("ias.login.done")) {
                doneMessage = "Success! You can now close this tab and return to Minecraft.";
            }

            this.server = new MSAuthServer(doneMessage, this.crypt, this);

            CompletableFuture.runAsync(() -> this.server.run(), IAS.executor()).thenRunAsync(() -> {
                LOGGER.info("IAS: Opening Ely.by browser OAuth2 auth URL...");
                this.stage(MicrosoftAccount.BROWSER);

                String url = this.server.authUrl();
                IStonecutter.openUrl(url);
                this.minecraft.keyboardHandler.setClipboard(url);
            }, this.minecraft).exceptionally(t -> {
                this.error(new RuntimeException("Failed launching browser callback server", t));
                return null;
            });
        } catch (Throwable t) {
            this.error(new RuntimeException("Unable to setup login server.", t));
        }
    }

    @Override
    public void onClose() {
        assert this.minecraft != null;
        //$set_screen 'this.minecraft' 'this.parent'
        this.minecraft.gui.setScreen(this.parent);
    }

    @Override
    public void removed() {
        assert this.minecraft != null;
        KeyboardHandler keyboard = this.minecraft.keyboardHandler;
        String clipboard = keyboard.getClipboard();

        if (clipboard.toLowerCase(Locale.ROOT).contains(IAS.CLIENT_ID.toLowerCase(Locale.ROOT))) {
            keyboard.setClipboard(" ");
        }

        IAS.executor().execute(() -> {
            if (this.server != null) {
                this.server.close();
                this.server = null;
            }
        });
    }

    @SuppressWarnings("NonPrivateFieldAccessedInSynchronizedContext")
    @Override
    //? if >=26.1 {
    public void extractRenderState(GuiGraphicsExtractor graphics, int mouseX, int mouseY, float delta) {
    //?} else
    /*public void render(GuiGraphics graphics, int mouseX, int mouseY, float delta) {*/
        assert this.minecraft != null;
        Matrix3x2fStack pose = graphics.pose();

        //? if >=26.1 {
        super.extractRenderState(graphics, mouseX, mouseY, delta);
        //?} else
        /*super.render(graphics, mouseX, mouseY, delta);*/

        pose.pushMatrix();
        pose.scale(2.0F, 2.0F);
        //? if >=26.1 {
        graphics.centeredText(this.font, Component.literal("Ely.by Login"), this.width / 4, this.height / 4 - 74 / 2, 0xFF_FF_FF_FF);
        //?} else
        /*graphics.drawCenteredString(this.font, Component.literal("Ely.by Login"), this.width / 4, this.height / 4 - 74 / 2, 0xFF_FF_FF_FF);*/
        pose.popMatrix();

        if (this.crypt == null && this.password != null && this.cryptPasswordTip != null) {
            //? if >=26.1 {
            graphics.centeredText(this.font, this.password.getMessage(), this.width / 2, this.height / 2 - 10 - 5, 0xFF_FF_FF_FF);
            //?} else
            /*graphics.drawCenteredString(this.font, this.password.getMessage(), this.width / 2, this.height / 2 - 10 - 5, 0xFF_FF_FF_FF);*/
            pose.pushMatrix();
            pose.scale(0.5F, 0.5F);
            IStonecutter.renderMultilineLabelCentered(this.cryptPasswordTip, graphics, this.width, this.height + 40);
            pose.popMatrix();
        } else {
            synchronized (this.lock) {
                if (this.label == null) {
                    Component component = Objects.requireNonNullElse(this.stage, Component.empty());
                    this.label = MultiLineLabel.create(this.font, component, 240);
                    this.minecraft.getNarrator().saySystemQueued(component);
                }
                IStonecutter.renderMultilineLabelCentered(this.label, graphics, this.width / 2, (this.height - this.label.getLineCount() * 9) / 2 - 4);
            }

            if (Float.isFinite(this.error)) {
                if (this.errorNote == null) {
                    this.errorNote = MultiLineLabel.create(this.font, Component.translatable("ias.error.note").withStyle(ChatFormatting.AQUA), 245);
                }

                float opacityFloat;
                int opacityMask;
                if (this.error < 1.0F) {
                    this.error = Math.min(this.error + delta * 0.1F, 1.0F);
                    opacityFloat = (this.error * this.error * this.error * this.error);
                    int opacity = Math.max(9, (int) (opacityFloat * 255.0F));
                    opacityMask = opacity << 24;
                } else {
                    opacityFloat = 1.0F;
                    opacityMask = -16777216;
                }

                int w = this.errorNote.getWidth() / 4 + 2;
                int h = (this.errorNote.getLineCount() * 9) / 2 + 1;
                int cx = this.width / 2;
                int sy = this.height / 2 + 87;
                graphics.fill(cx - w, sy, cx + w, sy + h, 0x101010 | opacityMask);
                graphics.fill(cx - w + 1, sy - 1, cx + w - 1, sy, 0x101010 | opacityMask);
                graphics.fill(cx - w + 1, sy + h, cx + w - 1, sy + h + 1, 0x101010 | opacityMask);

                pose.pushMatrix();
                pose.scale(0.5F, 0.5F);
                //? if >= 1.21.11 {
                var renderer = graphics.textRenderer();
                renderer.defaultParameters(renderer.defaultParameters().withOpacity(opacityFloat));
                this.errorNote.visitLines(net.minecraft.client.gui.TextAlignment.CENTER, this.width, this.height + 174, 9, renderer);
                //?} elif >= 1.21.10 {
                /*this.errorNote.render(graphics, MultiLineLabel.Align.CENTER, this.width, this.height + 174, 9, false, 0xFF_FF_FF | opacityMask);
                *///?} else
                /*this.errorNote.renderCentered(graphics, this.width, this.height + 174, 9, 0xFF_FF_FF | opacityMask);*/
                pose.popMatrix();
            }
        }
    }

    @Override
    //? if >=26.1 {
    public void extractBackground(GuiGraphicsExtractor graphics, int mouseX, int mouseY, float delta) {
    //?} else
    /*public void renderBackground(GuiGraphics graphics, int mouseX, int mouseY, float delta) {*/
        assert this.minecraft != null;

        if (this.parent != null) {
            //? if >=26.1 {
            this.parent.extractRenderStateWithTooltipAndSubtitles(graphics, 0, 0, delta);
            //?} elif >=1.21.10 {
            /*this.parent.renderWithTooltipAndSubtitles(graphics, 0, 0, delta);
            *///?} else
            /*this.parent.renderWithTooltip(graphics, 0, 0, delta);*/
            graphics.nextStratum();
            graphics.fill(0, 0, this.width, this.height, 0x80_00_00_00);
        } else {
            //? if >=26.1 {
            super.extractBackground(graphics, mouseX, mouseY, delta);
            //?} else
            /*super.renderBackground(graphics, mouseX, mouseY, delta);*/
        }

        int centerX = this.width / 2;
        int centerY = this.height / 2;
        graphics.fill(centerX - 125, centerY - 75, centerX + 125, centerY + 75, 0xF8_20_20_30);
        graphics.fill(centerX - 124, centerY - 76, centerX + 124, centerY - 75, 0xF8_20_20_30);
        graphics.fill(centerX - 124, centerY + 75, centerX + 124, centerY + 76, 0xF8_20_20_30);
    }

    @Override
    public void stage(String stage, Object... args) {
        assert this.minecraft != null;
        if (this != this.currentScreen()) return;

        Component component;
        if (MicrosoftAccount.BROWSER.equals(stage)) {
            component = Component.literal("Opening browser to authorize Ely.by...").withStyle(ChatFormatting.GREEN);
        } else {
            component = Component.translatable(stage, args).withStyle(ChatFormatting.YELLOW);
        }

        synchronized (this.lock) {
            this.stage = component;
            this.label = null;
        }
    }

    @Override
    public void success(MicrosoftAccount account) {
        assert this.minecraft != null;
        if (this != this.currentScreen()) return;

        this.stage(MicrosoftAccount.FINALIZING);

        this.minecraft.execute(() -> {
            if (this != this.currentScreen()) return;
            this.handler.accept(account);
        });
    }

    @Override
    public void error(Throwable error) {
        assert this.minecraft != null;
        LOGGER.error("IAS: Ely.by callback error.", error);
        if (this != this.currentScreen()) return;

        FriendlyException probable = FriendlyException.friendlyInChain(error);
        String key = probable != null ? probable.key() : "ias.error";
        Component component = Component.translatable(key).withStyle(ChatFormatting.RED);
        synchronized (this.lock) {
            this.stage = component;
            this.label = null;
            this.error = 0.0F;
        }
    }

    private Screen currentScreen() {
        //? if >=26.2 {
        return this.minecraft.gui.screen();
        //?} else {
        /*return this.minecraft.screen;
        *///?}
    }
}
