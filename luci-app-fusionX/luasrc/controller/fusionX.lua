module("luci.controller.fusionX", package.seeall)

function index()
    entry({"admin", "fusionx"}, firstchild(), "FusionX", 60).dependent=false
    entry({"admin", "fusionx", "bonding"}, cbi("fusionX"), _("Bonding"), 1)
    entry({"admin", "fusionx", "statistics"}, call("action_statistics")).leaf = true
    entry({"admin", "fusionx", "set_lan1_static"}, call("action_set_lan1_static")).leaf = true
    entry({"admin", "fusionx", "info"}, cbi("fusionXinfo"), _("Info"), 2).leaf = true 
    entry({"admin", "fusionx", "changelog"}, cbi("fusionXchangelog"), _("Changelog"), 3).leaf = true 
end

function action_statistics()
    local sys = require "luci.sys"
    local interfaces = {"wwan0", "wwan1", "wwan2", "lan1", "lan2", "eth1", "eth2", "wan"}
    local data = {}
    
    for _, iface in ipairs(interfaces) do
        local status = sys.exec("ping -I " .. iface .. " -c 1 -W 1 8.8.8.8 > /dev/null 2>&1 && echo 'up' || echo 'down'")
        if status:match("up") then
            local rx = sys.exec("cat /sys/class/net/" .. iface .. "/statistics/rx_bytes")
            local tx = sys.exec("cat /sys/class/net/" .. iface .. "/statistics/tx_bytes")
            table.insert(data, {iface = iface, rx = rx, tx = tx})
        end
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(data)
end

function action_info()
    luci.http.prepare_content("text/plain")
    luci.http.write("This is the info page for FusionX.")
end
