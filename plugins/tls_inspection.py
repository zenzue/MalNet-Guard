from typing import Dict, Any, List, Tuple
import socket, ssl, time
from malnet_guard import PluginBase, PluginResult

def fetch_cert(ip: str, port: int, timeout: float = 3.5) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    info: Dict[str, Any] = {}
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                info["subject"] = cert.get("subject", [])
                info["issuer"] = cert.get("issuer", [])
                info["subjectAltName"] = cert.get("subjectAltName", [])
                info["notBefore"] = cert.get("notBefore")
                info["notAfter"] = cert.get("notAfter")
    except Exception as e:
        info["error"] = type(e).__name__
    return info

def names_in_cert(cert: Dict[str, Any]) -> List[str]:
    names = []
    for k, v in cert.get("subjectAltName", []):
        if k.lower() == "dns":
            names.append(v.lower())
    for tup in cert.get("subject", []):
        for k, v in tup:
            if k.lower() == "commonname":
                names.append(v.lower())
    return list(dict.fromkeys(names))

class Plugin(PluginBase):
    name = "tls_inspection"

    def run(self, context: Dict[str, Any]) -> PluginResult:
        res: PluginResult = PluginResult()
        rows = context.get("rows", [])
        checked = []
        mismatches = []
        for r in rows:
            raddr = r.get("raddr","")
            proto = r.get("proto","")
            status = r.get("status","")
            try:
                ip, port = raddr.split(":")
                port = int(port)
            except Exception:
                continue
            if proto != "tcp" or port not in (443, 8443):
                continue
            cert = fetch_cert(ip, port)
            checked.append({"ip": ip, "port": port, "cert_error": cert.get("error")})
            if cert.get("error"):
                continue
            names = names_in_cert(cert)
            if not names:
                mismatches.append({"ip": ip, "port": port, "why": "no_san_cn", "names": names})
        res["checked"] = checked[:20]
        res["mismatches"] = mismatches
        res["critical"] = False
        res["why"] = "Fetches server certs on common TLS ports; flags empty SAN/CN as a weak signal of TLS interception/misconfig. (Best-effort; SNI not observable.)"
        return res