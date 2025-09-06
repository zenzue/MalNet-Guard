from typing import Dict, Any
import time
from malnet_guard import PluginBase, PluginResult, get_default_gateway

class Plugin(PluginBase):
    name = "gateway_drift_monitor"

    def run(self, context: Dict[str, Any]) -> PluginResult:
        res: PluginResult = PluginResult()
        gw1 = get_default_gateway()
        time.sleep(1)
        gw2 = get_default_gateway()
        drift = (gw1 != gw2)
        res["gw_initial"] = gw1
        res["gw_second"] = gw2
        res["drift"] = drift
        res["critical"] = drift
        res["why"] = "Default gateway drift mid-scan indicates DHCP spoofing or rogue router reconfiguration."
        return res
