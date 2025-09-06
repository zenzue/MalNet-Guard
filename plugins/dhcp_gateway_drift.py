from typing import Dict, Any
import os, json, time
from malnet_guard import PluginBase, PluginResult, get_default_gateway, analyze_arp_spoof

STATE_FILE = os.path.expanduser("~/.malnet_guard_state.json")

class Plugin(PluginBase):
    name = "dhcp_gateway_drift"

    def run(self, context: Dict[str, Any]) -> PluginResult:
        res: PluginResult = PluginResult()
        gw = get_default_gateway()
        arp = analyze_arp_spoof()
        gw_mac = arp.get("gateway_mac")
        now = int(time.time())

        prev = {}
        try:
            if os.path.exists(STATE_FILE):
                with open(STATE_FILE,"r") as f:
                    prev = json.load(f)
        except Exception:
            prev = {}

        drift = {}
        if prev.get("gateway_ip") and prev.get("gateway_ip") != gw:
            drift["gateway_ip_changed"] = [prev.get("gateway_ip"), gw]
        if prev.get("gateway_mac") and prev.get("gateway_mac") != gw_mac:
            drift["gateway_mac_changed"] = [prev.get("gateway_mac"), gw_mac]

        # Save current
        try:
            with open(STATE_FILE,"w") as f:
                json.dump({"gateway_ip": gw, "gateway_mac": gw_mac, "ts": now}, f)
        except Exception:
            pass

        res["current"] = {"gateway_ip": gw, "gateway_mac": gw_mac, "ts": now}
        res["drift"] = drift
        res["critical"] = bool(drift)
        res["why"] = "Detects default route or gateway MAC changes across runs (DHCP flip, rogue AP, MITM)."
        return res
