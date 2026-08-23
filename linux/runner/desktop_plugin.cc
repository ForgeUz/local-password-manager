#include <flutter_linux/flutter_linux.h>
#include <gtk/gtk.h>
#include <libayatana-appindicator/app-indicator.h>
#include <X11/Xlib.h>
#include <X11/keysym.h>

#include <cstring>
#include <optional>

// Intent: v5 E10 — native Linux tray + global hotkey bindings.
//   Channel vault_crypto/linux_tray:   setupTray / updateState (binary state)
//   Channel vault_crypto/linux_hotkey: registerHotkey (X11 XGrabKey)
// The tray shows ONLY binary lock state (locked/unlocked icon + tooltip), never
// vault contents. Tray click focuses the window; right-click menu: Lock/Quit.
// Hotkey (Ctrl+Shift+Space) triggers the "hotkeyPressed" Dart callback.
// Wayland-first is the documented limitation; X11 grab is the working path.
// Dependencies: GTK3, ayatana-appindicator3, X11 (x11, xtst).

// Channel names (must match lib/src/desktop/native_linux.dart).
static constexpr char kTrayChannel[] = "vault_crypto/linux_tray";
static constexpr char kHotkeyChannel[] = "vault_crypto/linux_hotkey";
static constexpr char kTrayActivated[] = "trayActivated";
static constexpr char kTrayLock[] = "trayLock";
static constexpr char kTrayQuit[] = "trayQuit";
static constexpr char kHotkeyPressed[] = "hotkeyPressed";

// Module-level state.
static FlMethodChannel* g_tray_channel = nullptr;
static FlMethodChannel* g_hotkey_channel = nullptr;
static AppIndicator* g_indicator = nullptr;

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
  // Click-to-focus (binary unlock/activate): click on "Open" emits
  // trayActivated to Dart, which focuses + opens the vault window.
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

// icon: "locked" | "unlocked" (binary state only — never vault contents).
static void desktop_tray_update_state(const gchar* icon, const gchar* tooltip) {
  if (!g_indicator) return;
  const gchar* themed = (g_strcmp0(icon, "unlocked") == 0)
                            ? "vault-crypto-unlocked"
                            : "vault-crypto-locked";
  app_indicator_set_icon_full(g_indicator, themed, "Vault state");
  app_indicator_set_title(g_indicator, tooltip);
}

// --- Hotkey thread (X11 XGrabKey: Ctrl+Shift+Space) ---

static gpointer hotkey_thread(gpointer /*user_data*/) {
  Display* dpy = XOpenDisplay(nullptr);
  if (!dpy) {
    g_warning("hotkey: cannot open X display (limitation on Wayland)");
    return nullptr;
  }
  KeyCode code = XKeysymToKeycode(dpy, XK_space);
  XGrabKey(dpy, code, ControlMask | ShiftMask, DefaultRootWindow(dpy), True,
           GrabModeAsync, GrabModeAsync);
  XSync(dpy, False);

  XEvent ev;
  for (;;) {
    XNextEvent(dpy, &ev);
    if (ev.type == KeyPress && ev.xkey.keycode == code) {
      if (g_hotkey_channel) {
        fl_method_channel_invoke_method(g_hotkey_channel, kHotkeyPressed,
                                        nullptr, nullptr, nullptr, nullptr);
      }
    }
  }
}

static void desktop_hotkey_register() {
  GThread* t = g_thread_new("hotkey-x11", hotkey_thread, nullptr);
  (void)t;
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
    desktop_hotkey_register();
    fl_method_call_respond_success(call, nullptr, nullptr);
  } else {
    fl_method_call_respond_error(call, "Unimplemented", method, nullptr, nullptr);
  }
}

// Public entry point: attach the two channels to the FlView's binary messenger.
gboolean desktop_plugin_register(FlView* view) {
  FlEngine* engine = fl_view_get_engine(view);
  if (!engine) return FALSE;
  g_autoptr(FlBinaryMessenger) messenger =
      fl_engine_get_binary_messenger(engine);
  // Dart's MethodChannel uses StandardMethodCodec by default (binary). The C++
  // side MUST match, or every incoming call fails to decode ("Message is not
  // valid UTF8") and the response handle is never cleared.
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

  return TRUE;
}