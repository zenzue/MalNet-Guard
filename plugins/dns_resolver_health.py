from typing import Dict, Any, List
import os, socket, platform, subprocess, re
from malnet_guard import PluginBase, PluginResult

class Plugin(PluginBase):
    name = "dns_resolver_health"

    def run(self, context: Dict[str, Any]) -> PluginResult:
        res: PluginResult = PluginResult()
        resolvers: List[str] = []
        hijack_symptoms: List[str] = []
        try:
            if os.path.exists("/etc/resolv.conf"):
                with open("/etc/resolv.conf","r") as f:
                    for ln in f:
                        m = re.match(r'\\s*nameserver\\s+([0-9\\.]+)', ln)
                        if m:
                            resolvers.append(m.group(1))
        except Exception:
            pass
        if not resolvers and platform.system().lower() == "windows":
            try:
                out = subprocess.check_output("nslookup -type=a example.com", shell=True, text=True, timeout=5)
                if "Server:" in out:
                    pass
            except Exception:
                hijack_symptoms.append("nslookup_failed")

        corp_only = context.get("rules",{}).get("plugins",{}).get(self.name,{}).get("require_corporate_dns", False)
        public_dns = {"1.1.1.1","8.8.8.8","9.9.9.9","208.67.222.222"}
        if corp_only:
            if any(r in public_dns for r in resolvers):
                hijack_symptoms.append("using_public_dns_on_corp_policy")

        res["resolvers"] = resolvers
        res["symptoms"] = hijack_symptoms
        res["critical"] = bool(hijack_symptoms and corp_only)
        res["why"] = "Detect DNS misconfig or hijack symptoms; public DNS use can bypass corporate filtering or indicate captive-portal tampering."
        return res
