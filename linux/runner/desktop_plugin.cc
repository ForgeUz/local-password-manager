// File: linux/runner/desktop_plugin.cc
// Intent: v5 E10 — native Linux tray + global hotkey bindings.
//   Channel vault_crypto/linux_tray:   setupTray / updateState (binary state)
//   Channel vault_crypto/linux_hotkey: registerHotkey (X11 XGrabKey OR Wayland xdg-desktop-portal)
// The tray shows ONLY binary lock state (locked/unlocked icon + tooltip), never
// vault contents. Tray click focuses the window; right-click menu: Lock/Quit.
// Hotkey (Ctrl+Alt+Space) triggers the "hotkeyPressed" Dart callback.
// Wayland detection: WAYLAND_DISPLAY env var (more reliable than XOpenDisplay).
// Wayland fallback uses org.freedesktop.portal.GlobalShortcuts via raw GDBus.
// Dependencies: GTK3, ayatana-appindicator3, X11 (x11, xtst), gio-2.0.

#include <flutter_linux/flutter_linux.h>
#include <gtk/gtk.h>
#include <libayatana-appindicator/app-indicator.h>
#include <X11/Xlib.h>
#include <X11/keysym.h>
#include <gio/gio.h>

#include <cstring>
#include <optional>

// Channel names (must match lib/src/desktop/native_linux.dart + native_clipboard.dart).
static const char kTrayChannel[] = "vault_crypto/linux_tray";
static const char kHotkeyChannel[] = "vault_crypto/linux_hotkey";
static const char kClipboardChannel[] = "vault_crypto/clipboard";
static const char kTrayActivated[] = "trayActivated";
static const char kTrayLock[] = "trayLock";
static const char kTrayQuit[] = "trayQuit";
static const char kHotkeyPressed[] = "hotkeyPressed";

// Module-level state.
static FlMethodChannel* g_tray_channel = nullptr;
static FlMethodChannel* g_hotkey_channel = nullptr;
static FlMethodChannel* g_clipboard_channel = nullptr;
static AppIndicator* g_indicator = nullptr;

// Wayland portal state
static GDBusConnection* g_dbus_conn = nullptr;
static gchar* g_session_handle = nullptr;

// --- Tray callbacks (emit to Dart side) ---

static void tray_activated_cb(GtkMenuItem* /*item*/, gpointer /*user_data*/) {
  if (g_tray_channel) {
    fl_method_channel_invoke_method(g_tray_channel, kTrayActivated, nullptr,
                                    nullptr, nullptr, nullptr);
  }
}

static void tray_lock_cb(GtkMenuItem* /*item*/, gpointer /*user_data*/) {
  if (g_tray_channel) {
    fl_method_channel_invoke_method(g_tray_channel, kTrayLock, nullptr, nullptr,
                                    nullptr, nullptr);
  }
}

static void tray_quit_cb(GtkMenuItem* /*item*/, gpointer /*user_data*/) {
  if (g_tray_channel) {
    fl_method_channel_invoke_method(g_tray_channel, kTrayQuit, nullptr, nullptr,
                                    nullptr, nullptr);
  }
}

// --- Tray setup: appindicator with Lock/Quit menu, click-to-focus ---

static void desktop_tray_setup() {
  if (g_indicator) return;
  g_indicator = app_indicator_new("vault-crypto", "vault-crypto-locked",
                                  APP_INDICATOR_CATEGORY_APPLICATION_STATUS);
  app_indicator_set_status(g_indicator, APP_INDICATOR_STATUS_ACTIVE);
  app_indicator_set_title(g_indicator, "Vault (locked)");

  GtkMenu* menu = GTK_MENU(gtk_menu_new());
  GtkWidget* open_item = gtk_menu_item_new_with_label("Open");
  g_signal_connect(open_item, "activate", G_CALLBACK(tray_activated_cb), nullptr);
  gtk_menu_shell_append(GTK_MENU_SHELL(menu), open_item);
  GtkWidget* lock_item = gtk_menu_item_new_with_label("Lock");
  g_signal_connect(lock_item, "activate", G_CALLBACK(tray_lock_cb), nullptr);
  gtk_menu_shell_append(GTK_MENU_SHELL(menu), lock_item);

  GtkWidget* quit_item = gtk_menu_item_new_with_label("Quit");
  g_signal_connect(quit_item, "activate", G_CALLBACK(tray_quit_cb), nullptr);
  gtk_menu_shell_append(GTK_MENU_SHELL(menu), quit_item);
  gtk_widget_show_all(GTK_WIDGET(menu));

  app_indicator_set_menu(g_indicator, menu);
}

static void desktop_tray_update_state(const gchar* icon, const gchar* tooltip) {
  if (!g_indicator) return;
  const gchar* themed = (g_strcmp0(icon, "unlocked") == 0)
                            ? "vault-crypto-unlocked"
                            : "vault-crypto-locked";
  app_indicator_set_icon_full(g_indicator, themed, "Vault state");
  app_indicator_set_title(g_indicator, tooltip);
}

// --- Hotkey thread (X11 XGrabKey: Ctrl+Alt+Space) ---
// Changed from Ctrl+Shift to Ctrl+Alt to avoid conflict with
// German keyboard layout switching (Strg+Shift).
// Mod1Mask = Alt, Mod2Mask = NumLock, LockMask = CapsLock.

static gpointer hotkey_thread(gpointer /*user_data*/) {
  Display* dpy = XOpenDisplay(nullptr);
  if (!dpy) {
    g_warning("[hotkey] X11: cannot open display");
    return nullptr;
  }

  g_print("[hotkey] X11: registering Ctrl+Alt+Space via XGrabKey\n");

  KeyCode code = XKeysymToKeycode(dpy, XK_space);

  // Grab Ctrl+Alt+Space across NumLock/CapsLock states so the hotkey
  // fires regardless of toggled modifiers.
  unsigned int mods[] = {
    ControlMask | Mod1Mask,                              // base
    ControlMask | Mod1Mask | Mod2Mask,                   // + NumLock
    ControlMask | Mod1Mask | LockMask,                   // + CapsLock
    ControlMask | Mod1Mask | Mod2Mask | LockMask,        // + both
  };
  for (unsigned int m : mods) {
    XGrabKey(dpy, code, m, DefaultRootWindow(dpy), True,
             GrabModeAsync, GrabModeAsync);
  }
  XSync(dpy, False);

  XEvent ev;
  for (;;) {
    XNextEvent(dpy, &ev);
    if (ev.type == KeyPress && ev.xkey.keycode == code) {
      g_print("[hotkey] X11: Ctrl+Alt+Space pressed -> invoking Dart\n");
      if (g_hotkey_channel) {
        fl_method_channel_invoke_method(g_hotkey_channel, kHotkeyPressed,
                                        nullptr, nullptr, nullptr, nullptr);
      }
    }
  }
}

// --- Wayland Hotkey Fallback (xdg-desktop-portal GlobalShortcuts via GDBus) ---
// Trigger changed to <Control><Alt>space to avoid layout-switch conflict.

static void on_create_session_response(GDBusConnection *connection, const gchar *sender_name,
                                       const gchar *object_path, const gchar *interface_name,
                                       const gchar *signal_name, GVariant *parameters, gpointer user_data);
static void on_bind_shortcuts_response(GDBusConnection *connection, const gchar *sender_name,
                                       const gchar *object_path, const gchar *interface_name,
                                       const gchar *signal_name, GVariant *parameters, gpointer user_data);
static void on_shortcut_activated(GDBusConnection *connection, const gchar *sender_name,
                                  const gchar *object_path, const gchar *interface_name,
                                  const gchar *signal_name, GVariant *parameters, gpointer user_data);

static void setup_wayland_hotkey() {
    GError *error = nullptr;
    g_dbus_conn = g_bus_get_sync(G_BUS_TYPE_SESSION, nullptr, &error);
    if (!g_dbus_conn) {
        g_warning("[hotkey] Wayland: failed to get session bus: %s", error->message);
        g_error_free(error);
        return;
    }

    g_print("[hotkey] Wayland: creating portal session\n");

    GVariantBuilder opts;
    g_variant_builder_init(&opts, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_add(&opts, "{sv}", "handle_token", g_variant_new_string("vault_req"));

    GVariant *res = g_dbus_connection_call_sync(g_dbus_conn,
        "org.freedesktop.portal.Desktop",
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.GlobalShortcuts",
        "CreateSession",
        g_variant_new("(a{sv})", &opts),
        G_VARIANT_TYPE("(o)"),
        G_DBUS_CALL_FLAGS_NONE, -1, nullptr, &error);

    if (!res) {
        g_warning("[hotkey] Wayland: CreateSession failed: %s", error->message);
        g_error_free(error);
        return;
    }

    const gchar *request_path = nullptr;
    g_variant_get(res, "(&o)", &request_path);
    gchar *req_path_dup = g_strdup(request_path);
    g_variant_unref(res);

    g_print("[hotkey] Wayland: session request at %s\n", req_path_dup);

    g_dbus_connection_signal_subscribe(g_dbus_conn,
        "org.freedesktop.portal.Desktop",
        "org.freedesktop.portal.Request",
        "Response",
        req_path_dup,
        nullptr,
        G_DBUS_SIGNAL_FLAGS_NONE,
        on_create_session_response,
        req_path_dup, g_free);
}

static void on_create_session_response(GDBusConnection *connection, const gchar *sender_name,
                                       const gchar *object_path, const gchar *interface_name,
                                       const gchar *signal_name, GVariant *parameters, gpointer user_data) {
    guint response;
    GVariant *results;
    g_variant_get(parameters, "(u@a{sv})", &response, &results);

    if (response != 0) {
        g_warning("[hotkey] Wayland: CreateSession denied (response=%u)", response);
        g_variant_unref(results);
        return;
    }

    GVariant *session_handle_var = g_variant_lookup_value(results, "session_handle", G_VARIANT_TYPE_OBJECT_PATH);
    if (!session_handle_var) {
        g_warning("[hotkey] Wayland: session_handle missing in Response");
        g_variant_unref(results);
        return;
    }

    g_session_handle = g_variant_dup_string(session_handle_var, nullptr);
    g_variant_unref(session_handle_var);
    g_variant_unref(results);

    g_print("[hotkey] Wayland: session created at %s\n", g_session_handle);

    // BindShortcuts — trigger is Ctrl+Alt+Space (avoids layout-switch conflict)
    GVariantBuilder shortcuts;
    g_variant_builder_init(&shortcuts, G_VARIANT_TYPE("aa{sv}"));
    g_variant_builder_open(&shortcuts, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&shortcuts, "{sv}", "id", g_variant_new_string("vault_hotkey"));
    g_variant_builder_add(&shortcuts, "{sv}", "description", g_variant_new_string("Vault Crypto Unlock"));
    g_variant_builder_add(&shortcuts, "{sv}", "trigger", g_variant_new_string("<Control><Alt>space"));
    g_variant_builder_close(&shortcuts);

    GVariantBuilder opts;
    g_variant_builder_init(&opts, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_add(&opts, "{sv}", "handle_token", g_variant_new_string("vault_bind_req"));

    GError *error = nullptr;
    GVariant *res = g_dbus_connection_call_sync(connection,
        "org.freedesktop.portal.Desktop",
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.GlobalShortcuts",
        "BindShortcuts",
        g_variant_new("(oaa{sv}a{sv})", g_session_handle, &shortcuts, &opts),
        G_VARIANT_TYPE("(o)"),
        G_DBUS_CALL_FLAGS_NONE, -1, nullptr, &error);

    if (!res) {
        g_warning("[hotkey] Wayland: BindShortcuts failed: %s", error->message);
        g_error_free(error);
        return;
    }

    const gchar *bind_req_path = nullptr;
    g_variant_get(res, "(&o)", &bind_req_path);
    gchar *bind_req_path_dup = g_strdup(bind_req_path);
    g_variant_unref(res);

    g_dbus_connection_signal_subscribe(connection,
        "org.freedesktop.portal.Desktop",
        "org.freedesktop.portal.Request",
        "Response",
        bind_req_path_dup,
        nullptr,
        G_DBUS_SIGNAL_FLAGS_NONE,
        on_bind_shortcuts_response,
        bind_req_path_dup, g_free);
}

static void on_bind_shortcuts_response(GDBusConnection *connection, const gchar *sender_name,
                                       const gchar *object_path, const gchar *interface_name,
                                       const gchar *signal_name, GVariant *parameters, gpointer user_data) {
    guint response;
    GVariant *results;
    g_variant_get(parameters, "(u@a{sv})", &response, &results);

    if (response != 0) {
        g_warning("[hotkey] Wayland: BindShortcuts denied (response=%u)", response);
        g_variant_unref(results);
        return;
    }
    g_variant_unref(results);

    g_print("[hotkey] Wayland: Ctrl+Alt+Space bound via xdg-desktop-portal\n");

    g_dbus_connection_signal_subscribe(connection,
        "org.freedesktop.portal.Desktop",
        "org.freedesktop.portal.GlobalShortcuts",
        "Activated",
        g_session_handle,
        nullptr,
        G_DBUS_SIGNAL_FLAGS_NONE,
        on_shortcut_activated,
        nullptr, nullptr);
}

static void on_shortcut_activated(GDBusConnection *connection, const gchar *sender_name,
                                  const gchar *object_path, const gchar *interface_name,
                                  const gchar *signal_name, GVariant *parameters, gpointer user_data) {
    const gchar *shortcut_id;
    guint64 timestamp;
    GVariant *options;

    g_variant_get(parameters, "(&st@a{sv})", &shortcut_id, &timestamp, &options);

    if (g_strcmp0(shortcut_id, "vault_hotkey") == 0) {
        g_print("[hotkey] Wayland: Ctrl+Alt+Space activated -> invoking Dart\n");
        if (g_hotkey_channel) {
            fl_method_channel_invoke_method(g_hotkey_channel, kHotkeyPressed,
                                            nullptr, nullptr, nullptr, nullptr);
        }
    }
    g_variant_unref(options);
}

// --- Hotkey registration entry point ---
// Detects Wayland via WAYLAND_DISPLAY env var (more reliable than XOpenDisplay,
// which succeeds via XWayland even on Wayland sessions).

static void desktop_hotkey_register() {
  g_print("[hotkey] registerHotkey called from Dart\n");

  const gchar *wayland_display = g_getenv("WAYLAND_DISPLAY");
  if (wayland_display != NULL && wayland_display[0] != '\0') {
    g_print("[hotkey] Wayland detected (WAYLAND_DISPLAY=%s)\n", wayland_display);
    setup_wayland_hotkey();
  } else {
    g_print("[hotkey] X11 detected\n");
    GThread* t = g_thread_new("hotkey-x11", hotkey_thread, nullptr);
    (void)t;
  }
}

// --- Clipboard (v5: sensitive MIME type) ---

static void clipboard_get_func(GtkClipboard* /*clipboard*/, GtkSelectionData* data,
                               guint /*info*/, gpointer user_data) {
  const gchar* text = static_cast<const gchar*>(user_data);
  gtk_selection_data_set(data, GDK_SELECTION_TYPE_STRING, 8,
                         (const guint8*)text, strlen(text));
}

static void clipboard_clear_func(GtkClipboard* /*clipboard*/, gpointer /*user_data*/) {}

static void desktop_clipboard_copy(const gchar* text, gboolean sensitive) {
  GtkClipboard* clip = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
  if (sensitive) {
    GtkTargetEntry targets[] = {
        {(gchar*)"text/plain;charset=utf-8", 0, 0},
        {(gchar*)"text/plain;charset=utf-8;sensitive=true", 0, 1},
    };
    gtk_clipboard_set_with_data(clip, targets, 2, clipboard_get_func,
                                clipboard_clear_func, (gpointer)text);
  } else {
    gtk_clipboard_set_text(clip, text, -1);
  }
}

// --- Method channel handler ---

static void desktop_plugin_method_call(FlMethodChannel* channel,
                                       FlMethodCall* call, gpointer /*user_data*/) {
  const gchar* method = fl_method_call_get_name(call);
  if (g_strcmp0(method, "setupTray") == 0) {
    desktop_tray_setup();
    fl_method_call_respond_success(call, nullptr, nullptr);
  } else if (g_strcmp0(method, "updateState") == 0) {
    FlValue* args = fl_method_call_get_args(call);
    FlValue* icon_value = fl_value_lookup_string(args, "icon");
    FlValue* tooltip_value = fl_value_lookup_string(args, "tooltip");
    const gchar* icon = icon_value != nullptr ? fl_value_get_string(icon_value)
                                              : "locked";
    const gchar* tooltip = tooltip_value != nullptr
                               ? fl_value_get_string(tooltip_value)
                               : "";
    desktop_tray_update_state(icon, tooltip);
    fl_method_call_respond_success(call, nullptr, nullptr);
  } else if (g_strcmp0(method, "registerHotkey") == 0) {
    g_print("[hotkey] MethodChannel: registerHotkey received\n");
    desktop_hotkey_register();
    fl_method_call_respond_success(call, nullptr, nullptr);
  } else if (g_strcmp0(method, "copy") == 0) {
    FlValue* args = fl_method_call_get_args(call);
    FlValue* text_value = fl_value_lookup_string(args, "text");
    FlValue* sensitive_value = fl_value_lookup_string(args, "sensitive");
    const gchar* text = text_value != nullptr ? fl_value_get_string(text_value) : "";
    gboolean sensitive = sensitive_value != nullptr &&
                         g_strcmp0(fl_value_get_string(sensitive_value), "true") == 0;
    desktop_clipboard_copy(text, sensitive);
    fl_method_call_respond_success(call, nullptr, nullptr);
  } else if (g_strcmp0(method, "clear") == 0) {
    GtkClipboard* clip = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_clear(clip);
    fl_method_call_respond_success(call, nullptr, nullptr);
  } else {
    fl_method_call_respond_error(call, "Unimplemented", method, nullptr, nullptr);
  }
}

// Public entry point: attach the channels to the FlView's binary messenger.
gboolean desktop_plugin_register(FlView* view) {
  FlEngine* engine = fl_view_get_engine(view);
  if (!engine) return FALSE;
  g_autoptr(FlBinaryMessenger) messenger =
      fl_engine_get_binary_messenger(engine);
  g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();

  g_tray_channel =
      fl_method_channel_new(messenger, kTrayChannel, FL_METHOD_CODEC(codec));
  fl_method_channel_set_method_call_handler(g_tray_channel,
                                            desktop_plugin_method_call, nullptr,
                                            nullptr);

  g_hotkey_channel =
      fl_method_channel_new(messenger, kHotkeyChannel, FL_METHOD_CODEC(codec));
  fl_method_channel_set_method_call_handler(g_hotkey_channel,
                                            desktop_plugin_method_call, nullptr,
                                            nullptr);

  g_clipboard_channel =
      fl_method_channel_new(messenger, kClipboardChannel, FL_METHOD_CODEC(codec));
  fl_method_channel_set_method_call_handler(g_clipboard_channel,
                                            desktop_plugin_method_call, nullptr,
                                            nullptr);

  return TRUE;
}