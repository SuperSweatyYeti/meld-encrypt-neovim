-- init.lua
-- Main entry point for meld-encrypt-neovim
-- Compatible with meld-cp/obsidian-encrypt (Obsidian plugin)

local M = {}

local config_mod = require("meld-encrypt.config")
local crypto     = require("meld-encrypt.crypto")

local cfg = config_mod.defaults  -- replaced by setup()

-- Secure in-memory store for edit-buffer credentials (never stored in vim.b).
-- Keyed by buffer number; cleared on BufDelete.
local _edit_creds = {}

-- ── Utilities ─────────────────────────────────────────────────────────────────

--- Return true if `filename` has one of the configured encrypted extensions.
local function is_encrypted_file(filename)
  if not filename or filename == "" then return false end
  for _, ext in ipairs(cfg.extensions) do
    if filename:match("%." .. ext .. "$") then return true end
  end
  return false
end

--- Prompt for a password using inputsecret (not echoed).
local function prompt_password(prompt_text)
  return vim.fn.inputsecret(prompt_text)
end

--- Read all lines from buffer `bufnr` and return as a single string.
local function buf_get_text(bufnr)
  local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
  return table.concat(lines, "\n")
end

--- Set buffer contents from a string (splits on newlines).
local function buf_set_text(bufnr, text)
  local lines = vim.split(text, "\n", { plain = true })
  vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, lines)
end

-- ── :MeldEncryptEncrypt ───────────────────────────────────────────────────────

local function cmd_encrypt()
  if not crypto.available then
    vim.notify(crypto.load_error, vim.log.levels.ERROR)
    return
  end

  local src_bufnr = vim.api.nvim_get_current_buf()
  local src_name  = vim.api.nvim_buf_get_name(src_bufnr)

  -- Determine output filename
  local base
  if src_name and src_name ~= "" then
    -- Strip any existing encrypted extension so we don't double-up
    base = src_name
    for _, ext in ipairs(cfg.extensions) do
      base = base:gsub("%." .. ext .. "$", "")
    end
    -- Strip .md if present
    base = base:gsub("%.md$", "")
  else
    base = "untitled"
  end
  local out_file = base .. "." .. cfg.default_extension

  -- Password prompt with confirmation
  vim.api.nvim_echo({ { "" } }, false, {})  -- flush prompt area
  local pass1 = prompt_password("Enter password: ")
  if pass1 == "" then
    vim.notify("meld-encrypt: Encryption cancelled (empty password).", vim.log.levels.WARN)
    return
  end
  local pass2 = prompt_password("Confirm password: ")
  if pass1 ~= pass2 then
    vim.notify("meld-encrypt: Passwords do not match. Encryption cancelled.", vim.log.levels.ERROR)
    return
  end
  local hint = vim.fn.input("Password hint (optional, leave blank for none): ")

  -- Encrypt
  local plaintext = buf_get_text(src_bufnr)
  local ok, result = pcall(crypto.encrypt, plaintext, pass1, hint, cfg)
  if not ok then
    vim.notify("meld-encrypt: Encryption failed: " .. tostring(result), vim.log.levels.ERROR)
    return
  end

  -- Write to file
  local f, err = io.open(out_file, "w")
  if not f then
    vim.notify("meld-encrypt: Could not write file: " .. tostring(err), vim.log.levels.ERROR)
    return
  end
  f:write(result)
  f:close()

  vim.notify("meld-encrypt: Encrypted → " .. out_file, vim.log.levels.INFO)
end

-- ── :MeldEncryptDecrypt ───────────────────────────────────────────────────────

local function cmd_decrypt()
  if not crypto.available then
    vim.notify(crypto.load_error, vim.log.levels.ERROR)
    return
  end

  local src_bufnr  = vim.api.nvim_get_current_buf()
  local src_name   = vim.api.nvim_buf_get_name(src_bufnr)

  if not is_encrypted_file(src_name) then
    vim.notify(
      "meld-encrypt: Current buffer is not an encrypted file (.mdenc / .encrypted).",
      vim.log.levels.WARN
    )
    return
  end

  local json_str = buf_get_text(src_bufnr)

  -- Show hint if available
  local hint = crypto.get_hint(json_str)
  if hint then
    vim.notify("meld-encrypt: Password hint: " .. hint, vim.log.levels.INFO)
  end

  local password = prompt_password("Enter password to decrypt: ")
  if password == "" then
    vim.notify("meld-encrypt: Decryption cancelled (empty password).", vim.log.levels.WARN)
    return
  end

  local ok, plaintext = pcall(crypto.decrypt, json_str, password)
  if not ok then
    vim.notify("meld-encrypt: Decryption failed: " .. tostring(plaintext), vim.log.levels.ERROR)
    return
  end

  -- Open plaintext in a new scratch buffer
  local new_buf = vim.api.nvim_create_buf(true, false)
  buf_set_text(new_buf, plaintext)
  vim.api.nvim_set_option_value("filetype", "markdown", { buf = new_buf })
  vim.api.nvim_set_option_value("modified", false, { buf = new_buf })
  vim.api.nvim_set_current_buf(new_buf)
  vim.notify("meld-encrypt: Decrypted successfully (read-only copy).", vim.log.levels.INFO)
end

-- ── :MeldEncryptEdit ──────────────────────────────────────────────────────────

local function cmd_edit()
  if not crypto.available then
    vim.notify(crypto.load_error, vim.log.levels.ERROR)
    return
  end

  local src_bufnr = vim.api.nvim_get_current_buf()
  local src_name  = vim.api.nvim_buf_get_name(src_bufnr)

  if not is_encrypted_file(src_name) then
    vim.notify(
      "meld-encrypt: Current buffer is not an encrypted file (.mdenc / .encrypted).",
      vim.log.levels.WARN
    )
    return
  end

  local json_str = buf_get_text(src_bufnr)

  -- Show hint if available
  local hint = crypto.get_hint(json_str)
  if hint then
    vim.notify("meld-encrypt: Password hint: " .. hint, vim.log.levels.INFO)
  end

  local password = prompt_password("Enter password to decrypt for editing: ")
  if password == "" then
    vim.notify("meld-encrypt: Edit cancelled (empty password).", vim.log.levels.WARN)
    return
  end

  local ok, plaintext = pcall(crypto.decrypt, json_str, password)
  if not ok then
    vim.notify("meld-encrypt: Decryption failed: " .. tostring(plaintext), vim.log.levels.ERROR)
    return
  end

  -- Create a scratch buffer with the decrypted content
  local edit_buf = vim.api.nvim_create_buf(true, false)
  buf_set_text(edit_buf, plaintext)
  vim.api.nvim_set_option_value("filetype", "markdown", { buf = edit_buf })
  vim.api.nvim_set_option_value("buftype", "acwrite", { buf = edit_buf })  -- triggers BufWriteCmd
  vim.api.nvim_buf_set_name(edit_buf, "[meld-encrypt] " .. vim.fn.fnamemodify(src_name, ":t"))
  vim.api.nvim_set_option_value("modified", false, { buf = edit_buf })

  -- Keep the original file path, hint, and password securely in a Lua table
  -- (never in vim.b, which is inspectable by other plugins and users)
  _edit_creds[edit_buf] = {
    src      = src_name,
    password = password,
    hint     = hint or "",
  }

  -- BufWriteCmd: intercept :w and re-encrypt back to the original file
  local augroup = vim.api.nvim_create_augroup(
    "MeldEncryptEdit_" .. edit_buf,
    { clear = true }
  )
  vim.api.nvim_create_autocmd("BufWriteCmd", {
    group  = augroup,
    buffer = edit_buf,
    callback = function()
      local ebuf  = vim.api.nvim_get_current_buf()
      local creds = _edit_creds[ebuf]
      if not creds then
        vim.notify("meld-encrypt: No credentials found for this buffer.", vim.log.levels.ERROR)
        return
      end
      local new_text = buf_get_text(ebuf)
      local ep       = creds.password
      local eh       = creds.hint
      local dest     = creds.src

      local enc_ok, enc_result = pcall(crypto.encrypt, new_text, ep, eh, cfg)
      if not enc_ok then
        vim.notify(
          "meld-encrypt: Re-encryption failed: " .. tostring(enc_result),
          vim.log.levels.ERROR
        )
        return
      end

      local f, err = io.open(dest, "w")
      if not f then
        vim.notify(
          "meld-encrypt: Could not write encrypted file: " .. tostring(err),
          vim.log.levels.ERROR
        )
        return
      end
      f:write(enc_result)
      f:close()

      -- Mark buffer as unmodified and reload the source buffer if visible
      vim.api.nvim_set_option_value("modified", false, { buf = ebuf })
      vim.notify("meld-encrypt: Saved and re-encrypted → " .. dest, vim.log.levels.INFO)

      -- Reload source buffer if it's loaded
      for _, bufnr in ipairs(vim.api.nvim_list_bufs()) do
        if vim.api.nvim_buf_get_name(bufnr) == dest and vim.api.nvim_buf_is_loaded(bufnr) then
          vim.api.nvim_buf_call(bufnr, function()
            vim.cmd("edit!")
          end)
          break
        end
      end
    end,
  })

  -- Clear credentials from the secure table when the buffer is deleted
  vim.api.nvim_create_autocmd("BufDelete", {
    group  = augroup,
    buffer = edit_buf,
    once   = true,
    callback = function()
      _edit_creds[edit_buf] = nil
      pcall(vim.api.nvim_del_augroup_by_name, "MeldEncryptEdit_" .. edit_buf)
    end,
  })

  vim.api.nvim_set_current_buf(edit_buf)
  vim.notify(
    "meld-encrypt: Editing in scratch buffer. Use :w to save back to " .. src_name
      .. " (plaintext is never written to disk).",
    vim.log.levels.INFO
  )
end

-- ── Autocommands ──────────────────────────────────────────────────────────────

local function setup_autocommands()
  local augroup = vim.api.nvim_create_augroup("MeldEncrypt", { clear = true })

  -- Set filetype for encrypted files
  vim.api.nvim_create_autocmd({ "BufRead", "BufNewFile" }, {
    group   = augroup,
    pattern = { "*.mdenc", "*.encrypted" },
    callback = function()
      vim.api.nvim_set_option_value("filetype", "mdenc", { buf = 0 })

      -- Show hint if available (only for existing files)
      if vim.fn.filereadable(vim.api.nvim_buf_get_name(0)) == 1 then
        local lines = vim.api.nvim_buf_get_lines(0, 0, -1, false)
        local content = table.concat(lines, "\n")
        if content ~= "" then
          local hint = crypto.get_hint(content)
          if hint then
            vim.schedule(function()
              vim.notify("meld-encrypt: Password hint: " .. hint, vim.log.levels.INFO)
            end)
          end
        end
      end
    end,
  })
end

-- ── setup() ───────────────────────────────────────────────────────────────────

function M.setup(opts)
  cfg = config_mod.merge(opts)

  if not crypto.available then
    vim.notify(crypto.load_error, vim.log.levels.WARN)
  end

  setup_autocommands()

  vim.api.nvim_create_user_command("MeldEncryptEncrypt", cmd_encrypt, {
    desc = "Encrypt the current buffer to an .mdenc file",
  })
  vim.api.nvim_create_user_command("MeldEncryptDecrypt", cmd_decrypt, {
    desc = "Decrypt the current .mdenc/.encrypted buffer into a new buffer",
  })
  vim.api.nvim_create_user_command("MeldEncryptEdit", cmd_edit, {
    desc = "Decrypt the current .mdenc/.encrypted buffer for editing (re-encrypts on :w)",
  })
end

return M
