/*
 * Password Vault for Cardputer Zero
 *
 * Updated version:
 * - LVGL UI
 * - Linux filesystem
 * - Real authenticated encryption via libsodium:
 *     - Argon2id for key derivation (password -> key)
 *     - XSalsa20-Poly1305 (crypto_secretbox) for AEAD
 * - No Arduino / SD / ArduinoJson / mbedTLS
 *
 * NOTE: Layout tuned for the Cardputer Zero's 320x170 (1.9") panel.
 *
 * BUILD NOTE: link against libsodium, e.g. add `-lsodium` to your
 * linker flags (or `find_package(sodium REQUIRED)` / pkg-config
 * `libsodium` in CMake). Call `sodium_init()` once before any other
 * sodium_* / crypto_* call - this is done at the top of main() below.
 *
 * FILE FORMAT CHANGE: the on-disk vault file format has changed from
 * the old raw XOR blob to:
 *
 *   [ MAGIC (4 bytes) ][ salt (crypto_pwhash_SALTBYTES) ]
 *   [ nonce (crypto_secretbox_NONCEBYTES) ][ ciphertext+MAC ]
 
 */

#include "asset_manager.h"
#include "theme.h"
#include "linux_input.h"

#include <lvgl.h>
#include <sodium.h>

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdint>

#if USE_DESKTOP
#include "desktop_simulator_frame.h"
#endif

#if !USE_DESKTOP
#if APP_USE_DRM
#include "src/drivers/display/drm/lv_linux_drm.h"
#else
#include "src/drivers/display/fb/lv_linux_fbdev.h"
#endif
#endif

#ifndef APP_FRAMEBUFFER_DEVICE
#define APP_FRAMEBUFFER_DEVICE "/dev/fb0"
#endif

#ifndef APP_DRM_DEVICE
#define APP_DRM_DEVICE "/dev/dri/card0"
#endif

#ifndef APP_DRM_CONNECTOR_ID
#define APP_DRM_CONNECTOR_ID -1
#endif

// ------------------------------------------------------------
// Screen geometry (Cardputer Zero: 1.9" ST7789v3, 320x170)
// ------------------------------------------------------------

#ifndef APP_SCREEN_W
#define APP_SCREEN_W 320
#endif

#ifndef APP_SCREEN_H
#define APP_SCREEN_H 170
#endif

// Compact sizing constants used throughout the tight 170px layout.
static constexpr int PAD_TINY = 2;
static constexpr int PAD_SMALL = 3;
static constexpr int ROW_H = 22;      // buttons / list rows
static constexpr int BOTTOM_BAR_H = 26;
static constexpr int FIELD_W = APP_SCREEN_W - 12;
static constexpr int INPUT_H = 20;    // one-line text inputs (Add screen)

// ------------------------------------------------------------
// Color palette: white background, vivid buttons.
// ------------------------------------------------------------

static lv_color_t color_bg_white()   { return lv_color_hex(0xFFFFFF); }
static lv_color_t color_text_dark()  { return lv_color_hex(0x1A1A1A); }
static lv_color_t color_yellow()     { return lv_color_hex(0xFFD400); }
static lv_color_t color_cherry()     { return lv_color_hex(0xD7263D); }
static lv_color_t color_sky()        { return lv_color_hex(0x4FC3F7); }

// ------------------------------------------------------------
// Simple Password Vault
// ------------------------------------------------------------

struct VaultEntry
{
    std::string title;
    std::string username;
    std::string password;
};

static std::vector<VaultEntry> vault;
static std::string masterPassword;

static lv_obj_t *main_screen = nullptr;
static lv_obj_t *content = nullptr;

static lv_obj_t *password_box = nullptr;
static lv_obj_t *status_label = nullptr;

static lv_obj_t *title_input = nullptr;
static lv_obj_t *username_input = nullptr;
static lv_obj_t *entry_password_input = nullptr;

static int selected_entry = 0;

// ------------------------------------------------------------
// File path
// ------------------------------------------------------------

static std::string vault_path()
{
    const char *home = std::getenv("HOME");

    if (home && *home)
    {
        return std::string(home) + "/.password-vault/data.bin";
    }

    return "./data.bin";
}

// ------------------------------------------------------------
// Authenticated encryption (libsodium)
//

//
// On-disk layout written by save_vault():
//
//   MAGIC (4 bytes, "PVS1")
//   salt  (crypto_pwhash_SALTBYTES)
//   nonce (crypto_secretbox_NONCEBYTES)
//   ciphertext (plaintext size + crypto_secretbox_MACBYTES)
//
// A fresh random salt AND a fresh random nonce are generated on
// every single save, so:
//  - two vaults (or two backups of the same vault) never reveal
//    anything by comparing bytes, even with the same password.
//  - the derived key is never reused across nonces, which is a
//    hard requirement for crypto_secretbox's security.
// ------------------------------------------------------------

static constexpr char VAULT_MAGIC[4] = {'P', 'V', 'S', '1'};

// Interactive limits: fast enough for a login prompt on a small
// embedded device, still far more expensive than the old 32-bit
// FNV seed. Bump to crypto_pwhash_OPSLIMIT_MODERATE /
// MEMLIMIT_MODERATE if the target hardware can spare the RAM/time
// and you want stronger brute-force resistance.
static constexpr unsigned long long PWHASH_OPSLIMIT =
    crypto_pwhash_OPSLIMIT_INTERACTIVE;
static constexpr size_t PWHASH_MEMLIMIT =
    crypto_pwhash_MEMLIMIT_INTERACTIVE;

// Derives a crypto_secretbox key from the master password and a
// given salt. Returns false if Argon2id itself fails (e.g. the
// device genuinely can't satisfy MEMLIMIT) - this is distinct
// from "wrong password", which is instead detected later by
// crypto_secretbox_open_easy() failing its MAC check.
static bool derive_key(
    const std::string &password,
    const unsigned char *salt,
    unsigned char *out_key)
{
    return crypto_pwhash(
               out_key,
               crypto_secretbox_KEYBYTES,
               password.c_str(),
               password.size(),
               salt,
               PWHASH_OPSLIMIT,
               PWHASH_MEMLIMIT,
               crypto_pwhash_ALG_ARGON2ID13) == 0;
}

// Encrypts `plain` under `password`, producing the full on-disk
// blob (magic || salt || nonce || ciphertext+MAC). Generates a
// fresh random salt and nonce internally.
static bool encrypt_vault_blob(
    const std::string &plain,
    const std::string &password,
    std::vector<uint8_t> &out_blob)
{
    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof salt);

    unsigned char key[crypto_secretbox_KEYBYTES];

    if (!derive_key(password, salt, key))
    {
        sodium_memzero(key, sizeof key);
        return false;
    }

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);

    std::vector<uint8_t> ciphertext(
        plain.size() + crypto_secretbox_MACBYTES);

    crypto_secretbox_easy(
        ciphertext.data(),
        reinterpret_cast<const unsigned char *>(plain.data()),
        plain.size(),
        nonce,
        key);

    sodium_memzero(key, sizeof key);

    out_blob.clear();
    out_blob.reserve(
        sizeof(VAULT_MAGIC) +
        sizeof(salt) +
        sizeof(nonce) +
        ciphertext.size());

    out_blob.insert(
        out_blob.end(),
        VAULT_MAGIC,
        VAULT_MAGIC + sizeof(VAULT_MAGIC));

    out_blob.insert(out_blob.end(), salt, salt + sizeof(salt));
    out_blob.insert(out_blob.end(), nonce, nonce + sizeof(nonce));
    out_blob.insert(out_blob.end(), ciphertext.begin(), ciphertext.end());

    return true;
}

// Decrypts a blob produced by encrypt_vault_blob(). Returns false
// on ANY failure - wrong password, corrupted/truncated file, or a
// file that isn't in this format at all (bad magic). The caller
// cannot distinguish these cases, which is intentional: it avoids
// leaking information about *why* decryption failed.
static bool decrypt_vault_blob(
    const std::vector<uint8_t> &blob,
    const std::string &password,
    std::string &out_plain)
{
    const size_t header_len =
        sizeof(VAULT_MAGIC) +
        crypto_pwhash_SALTBYTES +
        crypto_secretbox_NONCEBYTES;

    if (blob.size() < header_len + crypto_secretbox_MACBYTES)
        return false;

    if (std::memcmp(blob.data(), VAULT_MAGIC, sizeof(VAULT_MAGIC)) != 0)
        return false;

    const unsigned char *salt =
        blob.data() + sizeof(VAULT_MAGIC);

    const unsigned char *nonce =
        salt + crypto_pwhash_SALTBYTES;

    const unsigned char *ciphertext =
        nonce + crypto_secretbox_NONCEBYTES;

    const size_t ciphertext_len = blob.size() - header_len;

    unsigned char key[crypto_secretbox_KEYBYTES];

    if (!derive_key(password, salt, key))
    {
        sodium_memzero(key, sizeof key);
        return false;
    }

    std::vector<uint8_t> plain(
        ciphertext_len - crypto_secretbox_MACBYTES);

    const int ok = crypto_secretbox_open_easy(
        plain.data(),
        ciphertext,
        ciphertext_len,
        nonce,
        key);

    sodium_memzero(key, sizeof key);

    if (ok != 0)
        return false; // wrong password OR tampered/corrupted data

    out_plain.assign(plain.begin(), plain.end());

    // Best-effort scrub of decrypted plaintext buffer once copied.
    sodium_memzero(plain.data(), plain.size());

    return true;
}

// ------------------------------------------------------------
// Simple text format (unchanged) - this is the plaintext that
// gets encrypted/decrypted by the functions above.
//
// Each entry:
//
// title
// username
// password
//
// separated by blank line
//
// ------------------------------------------------------------

static std::string serialize_vault()
{
    std::stringstream ss;

    for (const auto &entry : vault)
    {

        ss << entry.title << '\n';
        ss << entry.username << '\n';
        ss << entry.password << '\n';
        ss << "---\n";
    }

    return ss.str();
}

static bool deserialize_vault(const std::string &data)
{
    std::vector<VaultEntry> temp;

    std::stringstream ss(data);
    std::string line;

    VaultEntry current;
    int field = 0;

    while (std::getline(ss, line))
    {

        if (line == "---")
        {

            if (field != 3)
                return false;

            temp.push_back(current);

            current = VaultEntry{};
            field = 0;
            continue;
        }

        if (field == 0)
            current.title = line;

        else if (field == 1)
            current.username = line;

        else if (field == 2)
            current.password = line;

        else
            return false;

        field++;
    }

    if (field != 0)
        return false;

    vault = std::move(temp);

    return true;
}

// ------------------------------------------------------------
// Save vault
// ------------------------------------------------------------

static bool save_vault()
{
    std::string path = vault_path();

    try
    {

        std::filesystem::path file_path(path);

        std::filesystem::create_directories(
            file_path.parent_path());

        std::string plain = serialize_vault();

        std::vector<uint8_t> blob;

        if (!encrypt_vault_blob(plain, masterPassword, blob))
            return false;

        // Scrub the plaintext copy now that it's encrypted.
        sodium_memzero(plain.data(), plain.size());

        std::ofstream file(
            path,
            std::ios::binary |
                std::ios::trunc);

        if (!file)
            return false;

        file.write(
            reinterpret_cast<const char *>(blob.data()),
            static_cast<std::streamsize>(blob.size()));

        return file.good();
    }
    catch (...)
    {
        return false;
    }
}

// ------------------------------------------------------------
// Load vault
// ------------------------------------------------------------

static bool load_vault(const std::string &password)
{
    std::ifstream file(
        vault_path(),
        std::ios::binary);

    if (!file)
        return false;

    std::vector<uint8_t> blob(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());

    std::string plain;

    if (!decrypt_vault_blob(blob, password, plain))
        return false;

    const bool ok = deserialize_vault(plain);

    sodium_memzero(plain.data(), plain.size());

    if (!ok)
        return false;

    masterPassword = password;

    return true;
}

// ------------------------------------------------------------
// LVGL helpers
// ------------------------------------------------------------

static lv_obj_t *make_label(
    lv_obj_t *parent,
    const char *text)
{
    lv_obj_t *label = lv_label_create(parent);

    lv_label_set_text(label, text);

    return label;
}

// Compact button: fixed row height, no internal padding waste.
// Every button gets a vivid fill color + matching readable text
// color instead of the flat default theme button.
//
// `radius` controls the corner rounding: the default (6) gives
// the normal pill-ish rounded look used everywhere else in the
// app. Pass 0 to get a perfectly square button (used for the
// Add/Delete/Lock action bar so those three read as square keys
// rather than rounded buttons).
static lv_obj_t *make_button(
    lv_obj_t *parent,
    const char *text,
    lv_color_t fill_color = {},
    lv_color_t text_color = {},
    int radius = 6)
{
    lv_obj_t *button = lv_button_create(parent);

    lv_obj_set_height(button, ROW_H);
    lv_obj_set_style_pad_all(button, 0, 0);
    lv_obj_set_style_radius(button, radius, 0);
    lv_obj_set_style_border_width(button, 0, 0);

    lv_obj_set_style_bg_color(button, fill_color, 0);
    lv_obj_set_style_bg_opa(button, LV_OPA_COVER, 0);
    lv_obj_set_style_bg_color(button, fill_color, LV_STATE_PRESSED);

    lv_obj_t *label = lv_label_create(button);

    lv_label_set_text(label, text);
    lv_obj_set_style_text_color(label, text_color, 0);

    lv_obj_center(label);

    return button;
}

// Square, non-interactive indicator: a plain lv_obj (NOT an
// lv_button), so it has no press/click behaviour, no touch
// feedback and no button chrome - it is purely a visual label
// telling the user which physical key does what ("4:ADD",
// "6:DELETE", "8:LOCK"). Tapping/clicking it does nothing; only
// pressing the matching digit key on the keyboard triggers the
// action (see vault_key_event).
static lv_obj_t *make_indicator(
    lv_obj_t *parent,
    const char *text,
    lv_color_t fill_color,
    lv_color_t text_color)
{
    lv_obj_t *box = lv_obj_create(parent);

    // lv_obj_create() is not clickable by default (unlike
    // lv_button_create()), so no explicit flag removal is
    // needed - but clear it explicitly anyway to be safe and
    // to document the intent.
    lv_obj_remove_flag(box, LV_OBJ_FLAG_CLICKABLE);

    lv_obj_set_height(box, ROW_H);
    lv_obj_set_style_pad_all(box, 0, 0);
    lv_obj_set_style_radius(box, 0, 0);
    lv_obj_set_style_border_width(box, 0, 0);
    lv_obj_set_style_shadow_width(box, 0, 0);

    lv_obj_set_style_bg_color(box, fill_color, 0);
    lv_obj_set_style_bg_opa(box, LV_OPA_COVER, 0);

    lv_obj_t *label = lv_label_create(box);

    lv_label_set_text(label, text);
    lv_obj_set_style_text_color(label, text_color, 0);

    lv_obj_center(label);

    return box;
}

// Strip a lv_obj_create() panel down to "invisible container":
// no bg fill, no border. Used for layout-only containers (list
// area, button bars) so the white main_screen shows through
// instead of the theme's default card color.
static void make_panel_plain(lv_obj_t *panel)
{
    lv_obj_set_style_bg_opa(panel, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(panel, 0, 0);
    lv_obj_set_style_shadow_width(panel, 0, 0);
}

// ------------------------------------------------------------
// Keyboard navigation: F/X/Z/C act as Up/Down/Left/Right.
// (unchanged from original)
// ------------------------------------------------------------

static bool key_is_up(uint32_t key)
{
    return key == LV_KEY_UP || key == 'f' || key == 'F';
}

static bool key_is_down(uint32_t key)
{
    return key == LV_KEY_DOWN || key == 'x' || key == 'X';
}

static bool key_is_left(uint32_t key)
{
    return key == LV_KEY_LEFT || key == 'z' || key == 'Z';
}

static bool key_is_right(uint32_t key)
{
    return key == LV_KEY_RIGHT || key == 'c' || key == 'C';
}

static void nav_key_event(lv_event_t *e)
{
    if (lv_event_get_code(e) != LV_EVENT_KEY)
        return;

    lv_obj_t *target =
        static_cast<lv_obj_t *>(lv_event_get_target(e));

    lv_group_t *group = lv_obj_get_group(target);

    if (!group)
        return;

    uint32_t key = lv_event_get_key(e);

    const bool is_textarea =
        lv_obj_check_type(target, &lv_textarea_class);

    if (key_is_up(key))
    {
        lv_group_focus_prev(group);
        return;
    }

    if (key_is_down(key))
    {
        lv_group_focus_next(group);
        return;
    }

    // On a textarea, leave Left/Right to the widget itself so
    // they move the text cursor instead of jumping focus.
    if (is_textarea)
        return;

    if (key_is_left(key))
    {
        lv_group_focus_prev(group);
        return;
    }

    if (key_is_right(key))
    {
        lv_group_focus_next(group);
        return;
    }
}

// Add an object to the keyboard-navigation group AND wire up
// the F/X/Z/C handling on it in one call. Use this instead of
// lv_group_add_obj() everywhere in this file.
static void group_add(lv_group_t *group, lv_obj_t *obj)
{
    lv_group_add_obj(group, obj);
    lv_obj_add_event_cb(obj, nav_key_event, LV_EVENT_KEY, nullptr);
}

// Add an object to the keyboard-navigation group WITHOUT the
// F/X/Z/C arrow-nav handler. Use this for textareas where those
// letters need to be typed normally (master password field, the
// Add-entry fields) instead of being hijacked as Up/Down/Left/
// Right focus jumps.
static void group_add_plain(lv_group_t *group, lv_obj_t *obj)
{
    lv_group_add_obj(group, obj);
}

// ------------------------------------------------------------
// Forward declarations
// ------------------------------------------------------------

static void show_login_screen();
static void show_vault_screen();
static void show_add_screen();
static void show_entry_screen();

static void do_add();
static void do_delete();
static void do_lock();

// ------------------------------------------------------------
// Login callback
// ------------------------------------------------------------

static void do_login()
{
    const char *text =
        lv_textarea_get_text(password_box);

    std::string password = text ? text : "";

    if (password.empty())
    {

        lv_label_set_text(
            status_label,
            "Enter password");

        return;
    }

    const bool exists =
        std::filesystem::exists(vault_path());

    if (exists)
    {

        if (!load_vault(password))
        {

            lv_label_set_text(
                status_label,
                "Wrong password");

            lv_textarea_set_text(
                password_box,
                "");

            return;
        }
    }
    else
    {

        masterPassword = password;
        vault.clear();

        if (!save_vault())
        {

            lv_label_set_text(
                status_label,
                "Save failed");

            return;
        }
    }

    show_vault_screen();
}

static void login_event(
    lv_event_t *e)
{
    if (lv_event_get_code(e) != LV_EVENT_CLICKED)
        return;

    do_login();
}

// Fired when the OK/Enter key is pressed while the master
// password field is focused (LVGL sends LV_EVENT_READY for a
// one-line textarea on Enter). Acts exactly like tapping the
// "Unlock" button.
static void password_ready_event(
    lv_event_t *e)
{
    if (lv_event_get_code(e) != LV_EVENT_READY)
        return;

    do_login();
}

// ------------------------------------------------------------
// Add entry callback
// ------------------------------------------------------------

// Real "add" action: jumps to the Add-entry screen. Triggered
// only by pressing the '4' key while the vault screen is
// focused - the "4:ADD" square is an indicator, not a button.
static void do_add()
{
    show_add_screen();
}

static void add_save_event(
    lv_event_t *e)
{
    if (lv_event_get_code(e) != LV_EVENT_CLICKED)
        return;

    const char *title =
        lv_textarea_get_text(title_input);

    const char *user =
        lv_textarea_get_text(username_input);

    const char *pass =
        lv_textarea_get_text(entry_password_input);

    VaultEntry entry;

    entry.title = title ? title : "";
    entry.username = user ? user : "";
    entry.password = pass ? pass : "";

    if (entry.title.empty())
        entry.title = "Untitled";

    vault.push_back(entry);

    save_vault();

    show_vault_screen();
}

static void add_cancel_event(
    lv_event_t *e)
{
    if (lv_event_get_code(e) == LV_EVENT_CLICKED)
        show_vault_screen();
}

// ------------------------------------------------------------
// Delete
// ------------------------------------------------------------

// Real "delete" action: removes the currently selected entry.
// Triggered only by pressing the '6' key while the vault screen
// is focused - the "6:DELETE" square is an indicator, not a
// button.
static void do_delete()
{
    if (vault.empty())
        return;

    if (selected_entry < 0 ||
        selected_entry >= static_cast<int>(vault.size()))
        return;

    vault.erase(
        vault.begin() + selected_entry);

    if (selected_entry >= static_cast<int>(vault.size()))
        selected_entry =
            static_cast<int>(vault.size()) - 1;

    if (selected_entry < 0)
        selected_entry = 0;

    save_vault();

    show_vault_screen();
}

// ------------------------------------------------------------
// Lock
// ------------------------------------------------------------

// Real "lock" action: clears the in-memory master password and
// vault contents and returns to the login screen. Triggered
// only by pressing the '8' key while the vault screen is
// focused - the "8:LOCK" square is an indicator, not a button.
static void do_lock()
{
    // Scrub the master password from memory rather than just
    // dropping the std::string, since clear()/destructor is not
    // guaranteed to zero the old buffer.
    sodium_memzero(
        masterPassword.data(),
        masterPassword.size());

    masterPassword.clear();
    vault.clear();
    show_login_screen();
}

// ------------------------------------------------------------
// Vault-screen digit shortcuts: 4 = Add, 6 = Delete, 8 = Lock.
// (unchanged from original)
// ------------------------------------------------------------

static bool key_is_digit(uint32_t key, char digit)
{
    return key == static_cast<uint32_t>(digit);
}

static void vault_key_event(lv_event_t *e)
{
    if (lv_event_get_code(e) != LV_EVENT_KEY)
        return;

    uint32_t key = lv_event_get_key(e);

    if (key_is_digit(key, '4'))
    {
        do_add();
        return;
    }

    if (key_is_digit(key, '6'))
    {
        do_delete();
        return;
    }

    if (key_is_digit(key, '8'))
    {
        do_lock();
        return;
    }

    // Not a shortcut digit - fall back to the normal
    // Up/Down/Left/Right (F/X/Z/C) focus navigation.
    nav_key_event(e);
}

// Add an object to the keyboard-navigation group AND wire up
// both the digit shortcuts (4/6/8) and the F/X/Z/C navigation.
// Use this instead of group_add() for objects on the vault
// screen only.
static void group_add_vault(lv_group_t *group, lv_obj_t *obj)
{
    lv_group_add_obj(group, obj);
    lv_obj_add_event_cb(obj, vault_key_event, LV_EVENT_KEY, nullptr);
}

// ------------------------------------------------------------
// Track which row is focused (unchanged from original)
// ------------------------------------------------------------

static void row_focus_event(
    lv_event_t *e)
{
    if (lv_event_get_code(e) != LV_EVENT_FOCUSED)
        return;

    lv_obj_t *button =
        static_cast<lv_obj_t *>(
            lv_event_get_target(e));

    intptr_t index =
        reinterpret_cast<intptr_t>(
            lv_obj_get_user_data(button));

    if (index < 0 ||
        index >= static_cast<intptr_t>(vault.size()))
        return;

    selected_entry = static_cast<int>(index);
}

// ------------------------------------------------------------
// Open selected entry
// ------------------------------------------------------------

static void open_entry_event(
    lv_event_t *e)
{
    if (lv_event_get_code(e) != LV_EVENT_CLICKED)
        return;

    lv_obj_t *button =
        static_cast<lv_obj_t *>(
            lv_event_get_target(e));

    intptr_t index =
        reinterpret_cast<intptr_t>(
            lv_obj_get_user_data(button));

    if (index < 0 ||
        index >= static_cast<intptr_t>(vault.size()))
        return;

    selected_entry = static_cast<int>(index);

    show_entry_screen();
}

// ------------------------------------------------------------
// Back
// ------------------------------------------------------------

static void back_event(
    lv_event_t *e)
{
    if (lv_event_get_code(e) == LV_EVENT_CLICKED)
        show_vault_screen();
}

// ------------------------------------------------------------
// Destroy current screen contents
// ------------------------------------------------------------

static void clear_content()
{
    if (!content)
        return;

    lv_obj_clean(content);
}

// ------------------------------------------------------------
// Login screen (unchanged from original)
// ------------------------------------------------------------

static void show_login_screen()
{

    lv_obj_clean(main_screen);

    lv_obj_set_flex_flow(
        main_screen,
        LV_FLEX_FLOW_COLUMN);

    lv_obj_set_flex_align(
        main_screen,
        LV_FLEX_ALIGN_CENTER,
        LV_FLEX_ALIGN_CENTER,
        LV_FLEX_ALIGN_CENTER);

    lv_obj_set_style_pad_all(
        main_screen,
        PAD_SMALL,
        0);

    lv_obj_set_style_pad_row(
        main_screen,
        PAD_TINY,
        0);

    lv_obj_t *title =
        make_label(main_screen,
                   "PASSWORD VAULT");

    // First run (no vault file on disk yet) vs. returning user
    // (a master password already exists) get different copy:
    // the first run should read as "pick a password", not
    // "log in with a password you never set".
    const bool vault_exists =
        std::filesystem::exists(vault_path());

    password_box =
        lv_textarea_create(main_screen);

    lv_obj_set_width(
        password_box,
        180);

    lv_obj_set_height(
        password_box,
        28);

    lv_textarea_set_one_line(
        password_box,
        true);

    lv_textarea_set_password_mode(
        password_box,
        true);

    // Placeholder replaces the old separate "Enter master
    // password" label to save a full row of vertical space.
    lv_textarea_set_placeholder_text(
        password_box,
        vault_exists ? "Master password" : "Select new password");

    // Pressing OK/Enter on the Cardputer while this field is
    // focused confirms the login, same as tapping "Unlock".
    lv_obj_add_event_cb(
        password_box,
        password_ready_event,
        LV_EVENT_READY,
        nullptr);

    lv_obj_t *login =
        make_button(
            main_screen,
            "Unlock",
            color_sky(),
            color_text_dark());

    lv_obj_set_width(login, 100);

    lv_obj_add_event_cb(
        login,
        login_event,
        LV_EVENT_CLICKED,
        nullptr);

    status_label =
        make_label(
            main_screen,
            vault_exists
                ? "To reset delete the \".password-vault\" folder"
                : "");

    lv_obj_set_width(
        status_label,
        LV_PCT(100));

    lv_obj_set_style_text_align(
        status_label,
        LV_TEXT_ALIGN_CENTER,
        0);

    lv_group_t *group =
        lv_group_get_default();

    if (group)
        lv_group_remove_all_objs(group);
    if (group)
    {

        group_add_plain(
            group,
            password_box);

        group_add(
            group,
            login);

        lv_group_focus_obj(password_box);
    }
}

// ------------------------------------------------------------
// Vault screen (unchanged from original)
// ------------------------------------------------------------

static void show_vault_screen()
{
    lv_group_t *group = lv_group_get_default();

    if (group)
        lv_group_remove_all_objs(group);
    lv_obj_clean(main_screen);

    lv_obj_set_flex_flow(
        main_screen,
        LV_FLEX_FLOW_COLUMN);

    lv_obj_set_style_pad_all(
        main_screen,
        PAD_TINY,
        0);

    lv_obj_set_style_pad_row(
        main_screen,
        PAD_TINY,
        0);

    lv_obj_t *header =
        lv_label_create(main_screen);

    lv_label_set_text(
        header,
        "PASSWORD VAULT");

    lv_obj_set_width(
        header,
        LV_PCT(100));

    lv_obj_set_style_text_align(
        header,
        LV_TEXT_ALIGN_CENTER,
        0);

    // Scroll area - takes all remaining vertical space between
    // the header and the fixed-height bottom bar.
    lv_obj_t *list =
        lv_obj_create(main_screen);

    lv_obj_set_width(
        list,
        LV_PCT(100));

    lv_obj_set_flex_grow(
        list,
        1);

    lv_obj_set_style_pad_all(list, PAD_TINY, 0);
    lv_obj_set_style_pad_row(list, PAD_TINY, 0);
    make_panel_plain(list);

    lv_obj_set_flex_flow(
        list,
        LV_FLEX_FLOW_COLUMN);

    lv_obj_set_scroll_dir(
        list,
        LV_DIR_VER);

    if (vault.empty())
    {

        lv_obj_t *empty =
            make_label(
                list,
                "No passwords.");

        lv_obj_center(empty);
    }
    else
    {

        for (size_t i = 0;
             i < vault.size();
             ++i)
        {

            const auto &entry = vault[i];

            lv_obj_t *button =
                lv_button_create(list);

            lv_obj_set_width(
                button,
                LV_PCT(100));

            lv_obj_set_height(
                button,
                ROW_H);

            lv_obj_set_style_pad_all(button, 0, 0);

            lv_obj_set_user_data(
                button,
                reinterpret_cast<void *>(
                    static_cast<intptr_t>(i)));

            lv_obj_t *label =
                lv_label_create(button);

            lv_label_set_text(
                label,
                entry.title.c_str());

            lv_obj_align(
                label,
                LV_ALIGN_LEFT_MID,
                6,
                0);

            lv_obj_add_event_cb(
                button,
                open_entry_event,
                LV_EVENT_CLICKED,
                nullptr);

            lv_obj_add_event_cb(
                button,
                row_focus_event,
                LV_EVENT_FOCUSED,
                nullptr);

            if (group)
                group_add_vault(group, button);
        }
    }

    // Bottom bar - fixed compact bar, three equal columns. These
    // three are plain SQUARE INDICATORS (make_indicator), not
    // buttons: they are not clickable/tappable, they just show
    // which physical key does what - "4:ADD", "6:DELETE",
    // "8:LOCK". Only actually pressing the 4 / 6 / 8 keys on the
    // keyboard performs the action (see vault_key_event).
    lv_obj_t *bottom =
        lv_obj_create(main_screen);

    lv_obj_set_width(
        bottom,
        LV_PCT(100));

    lv_obj_set_height(
        bottom,
        BOTTOM_BAR_H);

    make_panel_plain(bottom);

    lv_obj_set_flex_flow(
        bottom,
        LV_FLEX_FLOW_ROW);

    lv_obj_set_flex_align(
        bottom,
        LV_FLEX_ALIGN_SPACE_AROUND,
        LV_FLEX_ALIGN_CENTER,
        LV_FLEX_ALIGN_CENTER);

    lv_obj_set_style_pad_all(
        bottom,
        PAD_TINY,
        0);

    lv_obj_t *add =
        make_indicator(
            bottom,
            "4:ADD",
            color_yellow(),
            color_text_dark());

    lv_obj_set_width(add, 96);

    lv_obj_t *del =
        make_indicator(
            bottom,
            "6:DELETE",
            color_cherry(),
            color_bg_white());

    lv_obj_set_width(del, 96);

    lv_obj_t *lock =
        make_indicator(
            bottom,
            "8:LOCK",
            color_sky(),
            color_text_dark());

    lv_obj_set_width(lock, 96);

    if (group)
    {
        group_add_vault(group, add);
        group_add_vault(group, del);
        group_add_vault(group, lock);

        // Land the keyboard focus on the first password entry
        // if there is one, otherwise on "4:ADD".
        if (!vault.empty())
        {
            lv_obj_t *first_row =
                lv_obj_get_child(list, 0);

            if (first_row)
                lv_group_focus_obj(first_row);
        }
        else
        {
            lv_group_focus_obj(add);
        }
    }
}

// ------------------------------------------------------------
// Add screen (unchanged from original)
// ------------------------------------------------------------

static void show_add_screen()
{
    lv_obj_clean(main_screen);

    lv_obj_set_flex_flow(
        main_screen,
        LV_FLEX_FLOW_COLUMN);

    lv_obj_set_style_pad_all(
        main_screen,
        PAD_SMALL,
        0);

    lv_obj_set_style_pad_row(
        main_screen,
        PAD_TINY,
        0);

    lv_obj_t *title =
        make_label(
            main_screen,
            "ADD PASSWORD");

    lv_obj_set_width(
        title,
        LV_PCT(100));

    lv_obj_set_style_text_align(
        title,
        LV_TEXT_ALIGN_CENTER,
        0);

    title_input =
        lv_textarea_create(main_screen);

    lv_obj_set_width(
        title_input,
        FIELD_W);

    lv_obj_set_height(
        title_input,
        INPUT_H);

    // Trim the textarea's own internal padding - by default it
    // reserves room for a cursor + scrollbar on all sides, which
    // is what made a "20px" box still look oversized.
    lv_obj_set_style_pad_all(title_input, 3, 0);
    lv_obj_set_style_pad_top(title_input, 1, 0);
    lv_obj_set_style_pad_bottom(title_input, 1, 0);

    lv_textarea_set_one_line(
        title_input,
        true);

    lv_textarea_set_placeholder_text(
        title_input,
        "Title");

    username_input =
        lv_textarea_create(main_screen);

    lv_obj_set_width(
        username_input,
        FIELD_W);

    lv_obj_set_height(
        username_input,
        INPUT_H);

    lv_obj_set_style_pad_all(username_input, 3, 0);
    lv_obj_set_style_pad_top(username_input, 1, 0);
    lv_obj_set_style_pad_bottom(username_input, 1, 0);

    lv_textarea_set_one_line(
        username_input,
        true);

    lv_textarea_set_placeholder_text(
        username_input,
        "Username");

    entry_password_input =
        lv_textarea_create(main_screen);

    lv_obj_set_width(
        entry_password_input,
        FIELD_W);

    lv_obj_set_height(
        entry_password_input,
        INPUT_H);

    lv_obj_set_style_pad_all(entry_password_input, 3, 0);
    lv_obj_set_style_pad_top(entry_password_input, 1, 0);
    lv_obj_set_style_pad_bottom(entry_password_input, 1, 0);

    lv_textarea_set_one_line(
        entry_password_input,
        true);

    lv_textarea_set_password_mode(
        entry_password_input,
        true);

    lv_textarea_set_placeholder_text(
        entry_password_input,
        "Password");

    lv_obj_t *buttons =
        lv_obj_create(main_screen);

    lv_obj_set_width(
        buttons,
        LV_PCT(100));

    lv_obj_set_height(
        buttons,
        BOTTOM_BAR_H);

    make_panel_plain(buttons);

    lv_obj_set_flex_flow(
        buttons,
        LV_FLEX_FLOW_ROW);

    lv_obj_set_flex_align(
        buttons,
        LV_FLEX_ALIGN_SPACE_AROUND,
        LV_FLEX_ALIGN_CENTER,
        LV_FLEX_ALIGN_CENTER);

    lv_obj_set_style_pad_all(
        buttons,
        PAD_TINY,
        0);

    lv_obj_t *save =
        make_button(
            buttons,
            "Save",
            color_yellow(),
            color_text_dark());

    lv_obj_set_width(
        save,
        70);

    lv_obj_add_event_cb(
        save,
        add_save_event,
        LV_EVENT_CLICKED,
        nullptr);

    lv_obj_t *cancel =
        make_button(
            buttons,
            "Cancel",
            color_cherry(),
            color_bg_white());

    lv_obj_set_width(
        cancel,
        70);

    lv_obj_add_event_cb(
        cancel,
        add_cancel_event,
        LV_EVENT_CLICKED,
        nullptr);

    lv_group_t *group =
        lv_group_get_default();

    if (group)
    {

        group_add_plain(
            group,
            title_input);

        group_add_plain(
            group,
            username_input);

        group_add_plain(
            group,
            entry_password_input);

        group_add(
            group,
            save);

        group_add(
            group,
            cancel);

        lv_group_focus_obj(title_input);
    }
}

// ------------------------------------------------------------
// Entry screen (unchanged from original)
// ------------------------------------------------------------

static void show_entry_screen()
{
    lv_obj_clean(main_screen);

    if (selected_entry < 0 ||
        selected_entry >= static_cast<int>(vault.size()))
    {

        show_vault_screen();
        return;
    }

    const VaultEntry &entry =
        vault[selected_entry];

    lv_obj_set_flex_flow(
        main_screen,
        LV_FLEX_FLOW_COLUMN);

    lv_obj_set_style_pad_all(
        main_screen,
        PAD_SMALL,
        0);

    lv_obj_set_style_pad_row(
        main_screen,
        PAD_TINY,
        0);

    lv_obj_t *title =
        make_label(
            main_screen,
            entry.title.c_str());

    lv_obj_set_width(
        title,
        LV_PCT(100));

    lv_obj_set_style_text_align(
        title,
        LV_TEXT_ALIGN_CENTER,
        0);

    std::string user_text =
        "User: " + entry.username;

    lv_obj_t *user =
        make_label(
            main_screen,
            user_text.c_str());

    lv_obj_set_width(
        user,
        LV_PCT(100));

    std::string pass_text =
        "Pass: " + entry.password;

    lv_obj_t *pass =
        make_label(
            main_screen,
            pass_text.c_str());

    lv_obj_set_width(
        pass,
        LV_PCT(100));

    lv_label_set_long_mode(
        pass,
        LV_LABEL_LONG_SCROLL_CIRCULAR);

    lv_obj_t *back =
        make_button(
            main_screen,
            "Back",
            color_sky(),
            color_text_dark());

    lv_obj_set_width(
        back,
        70);

    lv_obj_add_event_cb(
        back,
        back_event,
        LV_EVENT_CLICKED,
        nullptr);

    lv_group_t *group =
        lv_group_get_default();

    if (group)
        lv_group_remove_all_objs(group);
    if (group)
    {

        group_add(
            group,
            back);

        lv_group_focus_obj(back);
    }
}

// ------------------------------------------------------------
// Display initialization (unchanged from original)
// ------------------------------------------------------------

#if !USE_DESKTOP

static lv_display_t *init_device_display()
{
#if APP_USE_DRM

    auto *display =
        lv_linux_drm_create();

    if (!display)
        return nullptr;

    if (lv_linux_drm_set_file(
            display,
            APP_DRM_DEVICE,
            APP_DRM_CONNECTOR_ID) != LV_RESULT_OK)
    {

        lv_display_delete(display);
        return nullptr;
    }

    platform::init_key_input(display);

    return display;

#else

    auto *display =
        lv_linux_fbdev_create();

    if (!display)
        return nullptr;

    if (lv_linux_fbdev_set_file(
            display,
            APP_FRAMEBUFFER_DEVICE) != LV_RESULT_OK)
    {

        lv_display_delete(display);
        return nullptr;
    }

    platform::init_key_input(display);

    return display;

#endif
}

#endif

// ------------------------------------------------------------
// Main
// ------------------------------------------------------------

int main()
{
    // Must be called before any other sodium_*/crypto_* function.
    // Returns 0 on success, 1 if already initialized (also fine),
    // -1 on failure (e.g. couldn't initialize the RNG) - treat
    // that as fatal since encryption can't be trusted otherwise.
    if (sodium_init() < 0)
        return 1;

    lv_init();

    app::AssetManager assets;

    lv_group_t *keyboard_group = lv_group_create();
    lv_group_set_default(keyboard_group);
#if USE_DESKTOP

    DesktopSimulatorFrame simulator_frame(assets);
    lv_display_t *display = simulator_frame.display();

#else

    lv_display_t *display = init_device_display();

#endif

    if (!display)
        return 1;

    lv_group_set_default(keyboard_group);

    lv_indev_t *indev = lv_indev_get_next(nullptr);

    while (indev)
    {
        if (lv_indev_get_type(indev) == LV_INDEV_TYPE_KEYPAD)
        {
            lv_indev_set_group(indev, keyboard_group);
        }

        indev = lv_indev_get_next(indev);
    }

    // Smaller font: on a 170px-tall screen a 14px font eats a
    // disproportionate share of vertical space across 3-5 stacked
    // rows. 10px keeps every screen legible without clipping.
    auto *font =
        assets.load_standard_font(10);

    // Light theme so the base UI colors (labels, textareas) read
    // as dark-on-white instead of the old light-on-dark scheme.
    view::apply_lvgl_theme(
        display,
        false,
        font ? font : LV_FONT_DEFAULT);

    main_screen =
        lv_obj_create(nullptr);

    // Force a pure white background regardless of the theme's
    // exact default shade, with dark text on top of it.
    lv_obj_set_style_bg_color(main_screen, color_bg_white(), 0);
    lv_obj_set_style_bg_opa(main_screen, LV_OPA_COVER, 0);
    lv_obj_set_style_text_color(main_screen, color_text_dark(), 0);

    lv_screen_load(main_screen);

    show_login_screen();

    bool running = true;

    while (running
#if USE_DESKTOP
           && simulator_frame.process_events()
#endif
    )
    {

        lv_timer_handler();

        lv_delay_ms(5);
    }

    return 0;
}
