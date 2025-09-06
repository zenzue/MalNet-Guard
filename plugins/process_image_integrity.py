from typing import Dict, Any, List
import os, hashlib
try:
    import psutil  # type: ignore
except Exception:
    psutil = None

from malnet_guard import PluginBase, PluginResult

class Plugin(PluginBase):
    name = "process_image_integrity"

    def _sha256(self, path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024*1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def run(self, context: Dict[str, Any]) -> PluginResult:
        res: PluginResult = PluginResult()
        allow_hashes = set((context.get("rules",{})
                            .get("plugins",{})
                            .get(self.name,{})
                            .get("allow_hashes", [])))
        rows = context.get("rows", [])
        unknown: List[Dict[str, Any]] = []
        hashed = 0
        if not psutil:
            res["note"] = "psutil not available; process image integrity limited."
            return res

        seen = set()
        for r in rows:
            pid = r.get("pid")
            if not pid or pid in seen: 
                continue
            seen.add(pid)
            try:
                p = psutil.Process(pid)
                exe = p.exe()
                if not exe or not os.path.isfile(exe):
                    continue
                sha = self._sha256(exe)
                hashed += 1
                if allow_hashes and sha not in allow_hashes:
                    unknown.append({"pid": pid, "proc": p.name(), "exe": exe, "sha256": sha})
            except Exception:
                continue

        res["hashed"] = hashed
        res["unknown_binaries"] = unknown
        res["critical"] = bool(unknown) and bool(allow_hashes)
        res["why"] = "Hash running processes and compare to allowlist; unknown binaries may indicate malware or unapproved tools."
        return res
