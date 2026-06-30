-- LuCI Controller for Clash Config Generator
-- Menu: Services > Clash Config Gen

module("luci.controller.clash_config_gen", package.seeall)

function index()
  entry({"admin", "services", "clash_config_gen"},
    call("action_page"),
    _("Clash Config Gen"), 60)

  -- API endpoint for server-side generation (fallback)
  entry({"admin", "services", "clash_config_gen", "generate"},
    call("action_generate")).leaf = true
end

function action_page()
  -- Render the main UI page
  luci.template.render("clash_config_gen/config")
end

function action_generate()
  local http = require "luci.http"

  http.prepare_content("application/json")

  local input = http.formvalue("uris") or ""
  if input == "" then
    http.write_json({ error = "No proxy URIs provided" })
    return
  end

  local proxies_only = http.formvalue("proxies_only") or "0"
  local dns_mode = http.formvalue("dns_mode") or "redir-host"

  local tmpfile = os.tmpname()
  local f = io.open(tmpfile, "w")
  if f then
    f:write(input)
    f:close()
  end

  local flag_p = proxies_only == "1" and "-p" or ""
  local cmd = string.format(
    "/usr/bin/clash-config-gen %s -m %s -f %s 2>/dev/null",
    flag_p, dns_mode, tmpfile
  )

  local output = luci.sys.exec(cmd)
  os.remove(tmpfile)

  http.write_json({ yaml = output })
end
