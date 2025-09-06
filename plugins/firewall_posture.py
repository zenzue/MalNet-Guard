from typing import Dict, Any
import platform, subprocess
from malnet_guard import PluginBase, PluginResult

class Plugin(PluginBase):
    name = "firewall_posture"

    def run(self, context: Dict[str, Any]) -> PluginResult:
        res: PluginResult = PluginResult()
        sysname = platform.system().lower()
        status = "unknown"
        detail = ""
        try:
            if sysname == "linux":
                try:
                    out = subprocess.check_output("ufw status", shell=True, text=True, timeout=5)
                    status = "enabled" if "Status: active" in out else "disabled"
                    detail = out.strip()[:600]
                except Exception:
                    try:
                        out = subprocess.check_output("firewall-cmd --state", shell=True, text=True, timeout=5)
                        status = "enabled" if "running" in out else "disabled"
                        detail = out.strip()[:600]
                    except Exception:
                        status = "unknown"
            elif sysname == "darwin":
                out = subprocess.check_output("pfctl -s info", shell=True, text=True, timeout=5)
                status = "enabled" if "Status: Enabled" in out else "disabled"
                detail = out.strip()[:600]
            elif sysname == "windows":
                out = subprocess.check_output("netsh advfirewall show allprofiles", shell=True, text=True, timeout=8)
                status = "enabled" if "State ON" in out or "ON" in out else "disabled"
                detail = out.strip()[:600]
        except Exception:
            pass

        res["status"] = status
        res["detail"] = detail
        res["critical"] = (status == "disabled")
        res["why"] = "Host-based firewall reduces lateral movement and blocks unsolicited inbound connections commonly used by malware."
        return res
