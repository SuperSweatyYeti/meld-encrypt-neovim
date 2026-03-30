local M = {}

M.defaults = {
  extensions = { "mdenc", "encrypted" },
  default_extension = "mdenc",
  iterations = 210000,
  salt_size = 16,
  vector_size = 16,
}

function M.merge(opts)
  return vim.tbl_deep_extend("force", M.defaults, opts or {})
end

return M
