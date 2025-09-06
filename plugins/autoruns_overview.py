from typing import Dict, Any, List
import os, platform, subprocess, re
from malnet_guard import PluginBase, PluginResult

class Plugin(PluginBase):
    name = "autoruns_overview"

    def run(self, context: Dict[str, Any]) -> PluginResult:
        res: PluginResult = PluginResult()
        sysname = platform.system().lower()
        hits: List[str] = []
        try:
            if sysname == "linux":
                for p in ["/etc/crontab", "/etc/cron.d"]:
                    if os.path.exists(p):
                        hits.append(f"cron:{p}")
                for d in ["/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"]:
                    if os.path.isdir(d):
                        hits.append(f"systemd_dir:{d}")
            elif sysname == "darwin":
                for d in ["/Library/LaunchAgents","/Library/LaunchDaemons", os.path.expanduser("~/Library/LaunchAgents")]:
                    if os.path.isdir(d): hits.append(f"launchd:{d}")
            elif sysname == "windows":
                hits.extend(["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                             "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                             "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"])
        except Exception:
            pass

        res["locations"] = hits
        res["critical"] = False
        res["why"] = "Persisted autoruns indicate possible malware persistence. Review these launch points for unknown entries."
        return res
