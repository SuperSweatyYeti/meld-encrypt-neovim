# meld-encrypt-neovim

A Neovim plugin that provides full interoperability with the
[meld-cp/obsidian-encrypt](https://github.com/meld-cp/obsidian-encrypt) Obsidian plugin.
Encrypt, decrypt, and seamlessly edit `.mdenc` and `.encrypted` files from Neovim using
the same AES-256-GCM cryptographic format as Meld Encrypt for Obsidian.

---

## Features

- **Encrypt** any buffer's content into a Meld Encrypt–compatible `.mdenc` file.
- **Decrypt** `.mdenc` / `.encrypted` files into a read-only scratch buffer.
- **Edit** encrypted files in-place: edits are re-encrypted on `:w` — **plaintext is never
  written to disk**.
- Reads both v2.0 (current) and v1.0 (legacy) Meld Encrypt files.
- Passwords are never echoed on screen (`vim.fn.inputsecret`).
- Optional password-hint support.

---

## Requirements

- **Neovim ≥ 0.9** (uses `vim.base64`, `vim.api.nvim_create_user_command`, etc.)
- **OpenSSL / libcrypto** — must be installed and discoverable by the dynamic linker.
  - Linux: `libcrypto.so.3` or `libcrypto.so.1.1` (from the `openssl` package)
  - macOS: `libcrypto.dylib` (ships with macOS via LibreSSL / Homebrew OpenSSL)
  - Windows: `libcrypto-3-x64.dll` or `libcrypto-1_1-x64.dll` (from an OpenSSL distribution)
- **LuaJIT** — included in standard Neovim builds (the plugin uses `ffi` to call libcrypto).

---

## Installation

### lazy.nvim (recommended)

```lua
{
  "SuperSweatyYeti/meld-encrypt-neovim",
  ft  = { "mdenc", "encrypted" },
  cmd = { "MeldEncryptEncrypt", "MeldEncryptDecrypt", "MeldEncryptEdit" },
  config = function()
    require("meld-encrypt").setup()
  end,
}
```

### packer.nvim

```lua
use {
  "SuperSweatyYeti/meld-encrypt-neovim",
  config = function()
    require("meld-encrypt").setup()
  end,
}
```

---

## Commands

| Command | Description |
|---|---|
| `:MeldEncryptEncrypt` | Prompt for a password (confirmed twice) and an optional hint, then encrypt the current buffer's content to a `.mdenc` file (same base name). The original buffer is left unchanged. |
| `:MeldEncryptDecrypt` | If the current buffer is a `.mdenc` / `.encrypted` file, prompt for the password and open the decrypted plaintext in a new buffer (filetype `markdown`, unsaved). |
| `:MeldEncryptEdit` | If the current buffer is a `.mdenc` / `.encrypted` file, prompt for the password and open the decrypted content in a scratch buffer. When you `:w`, the content is re-encrypted and written back to the original file. **Plaintext is never written to disk.** |

---

## Configuration

Pass options to `setup()` to override defaults:

```lua
require("meld-encrypt").setup({
  -- File extensions recognised as encrypted files
  extensions = { "mdenc", "encrypted" },
  -- Default extension used when encrypting
  default_extension = "mdenc",
  -- PBKDF2 iterations (must match the writer; Meld Encrypt v2.0 default)
  iterations = 210000,
  -- Random salt size in bytes
  salt_size = 16,
  -- AES-GCM IV size in bytes
  vector_size = 16,
})
```

### Default configuration

| Option | Default | Description |
|---|---|---|
| `extensions` | `{ "mdenc", "encrypted" }` | Extensions treated as encrypted files |
| `default_extension` | `"mdenc"` | Extension appended when encrypting |
| `iterations` | `210000` | PBKDF2-SHA512 iteration count |
| `salt_size` | `16` | Salt length in bytes |
| `vector_size` | `16` | IV length in bytes |

---

## Cryptographic Format

Files are JSON envelopes:

```json
{
  "version": "2.0",
  "hint": "optional hint",
  "encodedData": "<base64>"
}
```

The `encodedData` field is a Base64-encoded binary blob laid out as:

```
[ IV (16 bytes) ][ Salt (16 bytes) ][ AES-256-GCM ciphertext + 16-byte auth tag ]
```

Key derivation: **PBKDF2-SHA512**, 210 000 iterations.

This is byte-for-byte compatible with Meld Encrypt for Obsidian v2.0
(`CryptoHelper2304`). Legacy v1.0 files (PBKDF2-SHA256, fixed salt) can be read
but are not written.

---

## Security Notes

- **`:MeldEncryptEdit`**: the plaintext only ever lives in a Neovim in-memory buffer
  (`buftype=acwrite`). Saving with `:w` re-encrypts in memory and writes the ciphertext
  to disk — no temporary plaintext file is created.
- Passwords are entered via `vim.fn.inputsecret()` so they are not echoed or stored in
  command history.
- The plugin relies on OpenSSL for all cryptographic primitives (AES-256-GCM, PBKDF2).
  No custom crypto implementations are used.
- Swap files, undo history, and ShaDa may still contain plaintext from the scratch
  buffer. Consider setting `noswapfile` and `noundofile` for sensitive editing sessions.

