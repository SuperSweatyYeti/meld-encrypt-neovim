-- crypto.lua
-- LuaJIT FFI bindings to OpenSSL libcrypto for AES-256-GCM + PBKDF2
-- Compatible with meld-cp/obsidian-encrypt v2.0 (and v1.0 legacy read)

local M = {}

local ffi = require("ffi")

-- ── FFI declarations ─────────────────────────────────────────────────────────

ffi.cdef([[
  /* Random bytes */
  int RAND_bytes(unsigned char *buf, int num);

  /* EVP cipher context */
  typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
  typedef struct evp_cipher_st     EVP_CIPHER;
  typedef struct evp_md_st         EVP_MD;

  EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
  void            EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);

  const EVP_CIPHER *EVP_aes_256_gcm(void);
  const EVP_MD     *EVP_sha256(void);
  const EVP_MD     *EVP_sha512(void);

  int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                         void *impl, const unsigned char *key,
                         const unsigned char *iv);
  int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
  int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

  int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                         void *impl, const unsigned char *key,
                         const unsigned char *iv);
  int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
  int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

  int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

  /* PBKDF2 */
  int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
                         const unsigned char *salt, int saltlen,
                         int iter, const EVP_MD *digest,
                         int keylen, unsigned char *out);
]])

-- EVP_CTRL constants
local EVP_CTRL_GCM_SET_IVLEN = 0x9
local EVP_CTRL_GCM_GET_TAG   = 0x10
local EVP_CTRL_GCM_SET_TAG   = 0x11
local GCM_TAG_LEN             = 16

-- ── Load libcrypto ────────────────────────────────────────────────────────────

local libcrypto = nil
local load_error = nil

local candidates = {
  "libcrypto.so",
  "libcrypto.so.3",
  "libcrypto.so.1.1",
  "libcrypto.so.1.0.0",
  "libcrypto.dylib",
  "libcrypto-3-x64.dll",
  "libcrypto-1_1-x64.dll",
}

for _, name in ipairs(candidates) do
  local ok, lib = pcall(ffi.load, name)
  if ok then
    libcrypto = lib
    break
  end
end

if not libcrypto then
  load_error = "meld-encrypt: Could not load libcrypto. "
    .. "Please ensure OpenSSL is installed on your system."
end

M.available = libcrypto ~= nil
M.load_error = load_error

-- ── Helpers ───────────────────────────────────────────────────────────────────

-- Generate `n` random bytes, returned as a Lua string.
local function rand_bytes(n)
  local buf = ffi.new("unsigned char[?]", n)
  if libcrypto.RAND_bytes(buf, n) ~= 1 then
    error("RAND_bytes failed")
  end
  return ffi.string(buf, n)
end

-- Derive a 32-byte AES-256 key via PBKDF2.
-- digest: libcrypto.EVP_sha512() or libcrypto.EVP_sha256()
local function pbkdf2(password, salt, iterations, digest)
  local key = ffi.new("unsigned char[32]")
  local salt_ptr = ffi.cast("const unsigned char *", salt)
  local ret = libcrypto.PKCS5_PBKDF2_HMAC(
    password, #password,
    salt_ptr, #salt,
    iterations,
    digest,
    32, key
  )
  if ret ~= 1 then
    error("PKCS5_PBKDF2_HMAC failed")
  end
  return ffi.string(key, 32)
end

-- Base64 encode / decode using Neovim's built-in (available in nvim ≥ 0.9).
local function b64_encode(s)
  return vim.base64.encode(s)
end

local function b64_decode(s)
  return vim.base64.decode(s)
end

-- ── AES-256-GCM encrypt ───────────────────────────────────────────────────────

-- Returns ciphertext (bytes including 16-byte GCM tag appended).
local function aes256gcm_encrypt(plaintext, key, iv)
  local ctx = libcrypto.EVP_CIPHER_CTX_new()
  assert(ctx ~= nil, "EVP_CIPHER_CTX_new failed")
  local ok, result = pcall(function()
    assert(libcrypto.EVP_EncryptInit_ex(ctx, libcrypto.EVP_aes_256_gcm(), nil, nil, nil) == 1)
    assert(libcrypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, #iv, nil) == 1)
    local key_ptr = ffi.cast("const unsigned char *", key)
    local iv_ptr  = ffi.cast("const unsigned char *", iv)
    assert(libcrypto.EVP_EncryptInit_ex(ctx, nil, nil, key_ptr, iv_ptr) == 1)

    local outbuf = ffi.new("unsigned char[?]", #plaintext + 16)
    local outl   = ffi.new("int[1]")

    local pt_ptr = ffi.cast("const unsigned char *", plaintext)
    assert(libcrypto.EVP_EncryptUpdate(ctx, outbuf, outl, pt_ptr, #plaintext) == 1)
    local total = outl[0]

    local finbuf = ffi.new("unsigned char[16]")
    assert(libcrypto.EVP_EncryptFinal_ex(ctx, finbuf, outl) == 1)
    total = total + outl[0]

    local tag = ffi.new("unsigned char[16]")
    assert(libcrypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) == 1)

    return ffi.string(outbuf, total) .. ffi.string(tag, GCM_TAG_LEN)
  end)
  libcrypto.EVP_CIPHER_CTX_free(ctx)
  if not ok then error(result) end
  return result
end

-- ── AES-256-GCM decrypt ───────────────────────────────────────────────────────

-- `ciphertext` must include the 16-byte GCM tag at the end.
-- Returns plaintext or raises an error on authentication failure.
local function aes256gcm_decrypt(ciphertext, key, iv)
  if #ciphertext < GCM_TAG_LEN then
    error("ciphertext too short")
  end
  local ct_len   = #ciphertext - GCM_TAG_LEN
  local ct_body  = ciphertext:sub(1, ct_len)
  local tag_body = ciphertext:sub(ct_len + 1)

  local ctx = libcrypto.EVP_CIPHER_CTX_new()
  assert(ctx ~= nil, "EVP_CIPHER_CTX_new failed")
  local ok, result = pcall(function()
    assert(libcrypto.EVP_DecryptInit_ex(ctx, libcrypto.EVP_aes_256_gcm(), nil, nil, nil) == 1)
    assert(libcrypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, #iv, nil) == 1)
    local key_ptr = ffi.cast("const unsigned char *", key)
    local iv_ptr  = ffi.cast("const unsigned char *", iv)
    assert(libcrypto.EVP_DecryptInit_ex(ctx, nil, nil, key_ptr, iv_ptr) == 1)

    local outbuf = ffi.new("unsigned char[?]", #ct_body + 16)
    local outl   = ffi.new("int[1]")

    local ct_ptr = ffi.cast("const unsigned char *", ct_body)
    assert(libcrypto.EVP_DecryptUpdate(ctx, outbuf, outl, ct_ptr, #ct_body) == 1)
    local total = outl[0]

    -- Set the GCM tag before calling Final
    local tag_ptr = ffi.cast("void *", ffi.cast("const unsigned char *", tag_body))
    assert(libcrypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag_ptr) == 1)

    local finbuf = ffi.new("unsigned char[16]")
    local fin_ok = libcrypto.EVP_DecryptFinal_ex(ctx, finbuf, outl)
    if fin_ok ~= 1 then
      error("Decryption failed: wrong password or corrupted data")
    end
    total = total + outl[0]
    return ffi.string(outbuf, total)
  end)
  libcrypto.EVP_CIPHER_CTX_free(ctx)
  if not ok then error(result) end
  return result
end

-- ── Public API ────────────────────────────────────────────────────────────────

--- Encrypt plaintext with the given password.
-- @param plaintext string  UTF-8 plaintext to encrypt
-- @param password  string  User-supplied password
-- @param hint      string  Optional password hint (may be empty)
-- @param cfg       table   Plugin config (iterations, salt_size, vector_size)
-- @return string   JSON envelope ready to write to disk
function M.encrypt(plaintext, password, hint, cfg)
  if not libcrypto then error(load_error) end

  local salt = rand_bytes(cfg.salt_size)
  local iv   = rand_bytes(cfg.vector_size)
  local key  = pbkdf2(password, salt, cfg.iterations, libcrypto.EVP_sha512())

  local ciphertext = aes256gcm_encrypt(plaintext, key, iv)

  -- Binary blob: IV || Salt || Ciphertext+Tag
  local blob        = iv .. salt .. ciphertext
  local encoded     = b64_encode(blob)

  local envelope = vim.fn.json_encode({
    version     = "2.0",
    hint        = hint or "",
    encodedData = encoded,
  })
  return envelope
end

--- Decrypt a JSON envelope with the given password.
-- @param json_str  string  Contents of the .mdenc / .encrypted file
-- @param password  string  User-supplied password
-- @return string   Decrypted UTF-8 plaintext
function M.decrypt(json_str, password)
  if not libcrypto then error(load_error) end

  local ok, envelope = pcall(vim.fn.json_decode, json_str)
  if not ok or type(envelope) ~= "table" then
    error("Failed to parse encrypted file: invalid JSON")
  end

  local version      = envelope.version or "2.0"
  local encoded_data = envelope.encodedData
  if not encoded_data then
    error("Failed to parse encrypted file: missing encodedData field")
  end

  local blob = b64_decode(encoded_data)

  if version == "1.0" then
    -- Legacy: [IV (16)] [Ciphertext+Tag], fixed salt
    local iv         = blob:sub(1, 16)
    local ciphertext = blob:sub(17)
    local fixed_salt = "XHWnDAT6ehMVY2zD"
    local key        = pbkdf2(password, fixed_salt, 1000, libcrypto.EVP_sha256())
    return aes256gcm_decrypt(ciphertext, key, iv)
  else
    -- v2.0: [IV (16)] [Salt (16)] [Ciphertext+Tag]
    local iv         = blob:sub(1, 16)
    local salt       = blob:sub(17, 32)
    local ciphertext = blob:sub(33)
    local key        = pbkdf2(password, salt, 210000, libcrypto.EVP_sha512())
    return aes256gcm_decrypt(ciphertext, key, iv)
  end
end

--- Return the hint string from a JSON envelope, or nil.
function M.get_hint(json_str)
  local ok, envelope = pcall(vim.fn.json_decode, json_str)
  if not ok or type(envelope) ~= "table" then return nil end
  local h = envelope.hint
  if h and h ~= "" then return h end
  return nil
end

return M
