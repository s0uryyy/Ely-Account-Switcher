/*
 * In-Game Account Switcher with Ely.by hijack patch.
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
import ru.vidtu.ias.auth.microsoft.MSAuth;
import ru.vidtu.ias.config.IASConfig;
import ru.vidtu.ias.crypt.Crypt;
import ru.vidtu.ias.crypt.PasswordCrypt;
import ru.vidtu.ias.platform.IStonecutter;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Ely.by account insertion popup mimicking MicrosoftAccount.
 */
final class MicrosoftPopupScreen extends Screen implements CreateHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger("IAS/MicrosoftPopupScreen");

    private final Screen parent;
    private final Object lock = new Object();
    private final Consumer<Account> handler;
    private Crypt crypt;

    private Component stage = Component.literal("Ely.by Login").withStyle(ChatFormatting.YELLOW);
    private MultiLineLabel label;

    private PopupBox password; // Master key
    private MultiLineLabel cryptPasswordTip;

    // Ely.by UI elements
    private PopupBox elyEmail;
    private PopupBox elyPassword;
    private PopupBox elyTotp;
    private Button elySubmit;

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

        // Back button
        this.addRenderableWidget(new PopupButton(this.width / 2 - 75, this.height / 2 + 74 - 22, 150, 20,
                CommonComponents.GUI_BACK, btn -> this.onClose(), Supplier::get));

        if (this.crypt == null) {
            // Prompt Master password
            this.password = new PopupBox(this.font, this.width / 2 - 100, this.height / 2 - 10 + 5, 178, 20, this.password, Component.translatable("ias.password"), () -> {
                if (this.password == null || this.crypt != null) return;
                String value = this.password.getValue();
                if (value.isBlank()) return;

                this.crypt = new PasswordCrypt(value);
                this.password = null;
                this.cryptPasswordTip = null;

                // Re-init
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

                // Re-init
                //? if >=1.21.11 {
                this.init(this.width, this.height);
                //?} else
                /*this.init(this.minecraft, this.width, this.height);*/
            }, Supplier::get);
            enterPassword.active = !this.password.getValue().isBlank();
            this.addRenderableWidget(enterPassword);
            this.password.setResponder(value -> enterPassword.active = !value.isBlank());

            this.cryptPasswordTip = MultiLineLabel.create(this.font, Component.translatable("ias.password.tip"), 320);
        } else {
            // Master crypt exists: render Ely.by login form instead of MS browser / client code!
            this.elyEmail = new PopupBox(this.font, this.width / 2 - 100, this.height / 2 - 50, 200, 20, this.elyEmail, Component.literal("Email / Nickname"), () -> {}, false);
            this.elyEmail.setHint(Component.literal("Email / Nickname").withStyle(ChatFormatting.DARK_GRAY));
            this.elyEmail.setMaxLength(128);
            this.addRenderableWidget(this.elyEmail);

            this.elyPassword = new PopupBox(this.font, this.width / 2 - 100, this.height / 2 - 20, 200, 20, this.elyPassword, Component.literal("Ely.by Password"), () -> {}, true);
            this.elyPassword.setHint(Component.literal("Ely.by Password").withStyle(ChatFormatting.DARK_GRAY));
            this.elyPassword.setMaxLength(128);
            //? if >=1.21.10 {
            this.elyPassword.addFormatter((s, i) -> FormattedCharSequence.forward("*".repeat(s.length()), Style.EMPTY));
            //?} else
            /*this.elyPassword.setFormatter((s, i) -> FormattedCharSequence.forward("*".repeat(s.length()), Style.EMPTY));*/
            this.addRenderableWidget(this.elyPassword);

            this.elyTotp = new PopupBox(this.font, this.width / 2 - 100, this.height / 2 + 10, 200, 20, this.elyTotp, Component.literal("2FA Code (Optional)"), () -> {}, false);
            this.elyTotp.setHint(Component.literal("2FA Code (Optional)").withStyle(ChatFormatting.DARK_GRAY));
            this.elyTotp.setMaxLength(6);
            this.addRenderableWidget(this.elyTotp);

            this.elySubmit = new PopupButton(this.width / 2 - 100, this.height / 2 + 40, 200, 20, Component.literal("Sign In"), btn -> this.submitElyBy(), Supplier::get);
            this.addRenderableWidget(this.elySubmit);
            this.stage("Login with Ely.by Account");
        }
    }

    private void submitElyBy() {
        String email = this.elyEmail.getValue();
        String pass = this.elyPassword.getValue();
        String totp = this.elyTotp.getValue();
        if (email.isBlank() || pass.isBlank()) return;

        this.stage(MicrosoftAccount.PROCESSING);
        this.elySubmit.active = false;

        String clientToken = UUID.randomUUID().toString();

        MSAuth.authenticateElyBy(email, pass, totp, clientToken).thenAcceptAsync(tokens -> {
            try {
                this.stage(MicrosoftAccount.ENCRYPTING);

                byte[] unencrypted;
                try (ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
                     DataOutputStream out = new DataOutputStream(byteOut)) {
                    out.writeUTF(tokens.access());
                    out.writeUTF(tokens.refresh()); // accessToken:clientToken string saved as refresh
                    unencrypted = byteOut.toByteArray();
                }

                byte[] encryptedData;
                try (ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
                     DataOutputStream out = new DataOutputStream(byteOut)) {
                    byte[] encrypted = this.crypt.encrypt(unencrypted);
                    out.writeUTF(this.crypt.type());
                    out.write(encrypted);
                    encryptedData = byteOut.toByteArray();
                }

                MicrosoftAccount account = new MicrosoftAccount(this.crypt.insecure(), tokens.profile().uuid(), tokens.profile().name(), encryptedData);
                this.success(account);
            } catch (Throwable t) {
                this.error(new RuntimeException("Unable to encrypt Ely.by credentials", t));
            }
        }, IAS.executor()).exceptionally(t -> {
            this.error(t);
            this.minecraft.execute(() -> this.elySubmit.active = true);
            return null;
        });
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
        graphics.centeredText(this.font, this.title, this.width / 4, this.height / 4 - 74 / 2, 0xFF_FF_FF_FF);
        //?} else
        /*graphics.drawCenteredString(this.font, this.title, this.width / 4, this.height / 4 - 74 / 2, 0xFF_FF_FF_FF);*/
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

        Component component = Component.translatable(stage, args).withStyle(ChatFormatting.YELLOW);
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
        LOGGER.error("IAS: Ely.by auth error.", error);
        if (this != this.currentScreen()) return;

        String key = "ias.error";
        Component component = Component.literal(error.getMessage() != null ? error.getMessage() : "Error: Check credentials").withStyle(ChatFormatting.RED);
        synchronized (this.lock) {
            this.stage = component;
            this.label = null;
            this.error = 0.0F;
        }
    }

    @Override
    public String toString() {
        return "MicrosoftPopupScreen{elyByPatched=true}";
    }

    private Screen currentScreen() {
        //? if >=26.2 {
        return this.minecraft.gui.screen();
        //?} else {
        /*return this.minecraft.screen;
        *///?}
    }
}
