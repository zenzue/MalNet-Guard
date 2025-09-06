from typing import Dict, Any
from malnet_guard import PluginBase, PluginResult
from malnet_guard import analyze_arp_spoof

class Plugin(PluginBase):
    name = "gateway_mac_allowlist"

    def run(self, context: Dict[str, Any]) -> PluginResult:
        res: PluginResult = PluginResult()
        rules = context.get("rules",{}).get("plugins",{}).get(self.name,{})
        allowed = set(map(str.lower, rules.get("allowed_macs", [])))
        if not allowed:
            res["note"] = "No allowed_macs configured."
            res["critical"] = False
            res["why"] = "Allow-listing known gateway MACs reduces false positives and spots rogue APs/mitm."
            return res
        arp = analyze_arp_spoof()
        gw_mac = (arp.get("gateway_mac") or "").lower() if arp.get("gateway_mac") else ""
        res["gateway_mac"] = gw_mac
        res["allowed"] = list(allowed)
        res["ok"] = (gw_mac in allowed) if gw_mac else False
        res["critical"] = (gw_mac != "" and gw_mac not in allowed)
        res["why"] = "If the default gateway MAC differs from the known allowlist, a rogue gateway/mitm may exist."
        return res
