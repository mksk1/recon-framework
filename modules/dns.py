import subprocess
import socket
import re
import json
from pathlib import Path
from utils.logger import log

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

DEFAULT_WORDLISTS = [
    "/home/mksk/wordlists/subdomains-top1million-5000.txt",
    "/home/mksk/wordlists/shubs-subdomains.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
]

# Regex para detectar dominios (con TLD común en CTFs)
DOMAIN_RE = re.compile(
    r'\b([a-z0-9][a-z0-9-]{1,62}\.(?:local|htb|thm|lan|internal|corp|com|net|org|io))\b',
    re.I
)

PRIORITY_SCRIPTS = [
    "rdp-ntlm-info",
    "smb-os-discovery",
    "ldap-rootdse",
    "ssl-cert",
    "http-title",
    "http-server-header",
    "dns-nsid",
]


def _run(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return ANSI_RE.sub("", r.stdout).strip()
    except subprocess.TimeoutExpired:
        log.warning(f"[!] timeout: {' '.join(cmd)}")
    except FileNotFoundError:
        log.error(f"[!] comando no encontrado: {cmd[0]}")
    except Exception as e:
        log.warning(f"[!] fallo {' '.join(cmd)}: {e}")
    return None


def _find_wordlist():
    for w in DEFAULT_WORDLISTS:
        if Path(w).exists():
            return w
    return None


def _discover_domain(target, service, all_services=None):
    """Intenta descubrir el dominio del servidor DNS.

    Orden:
      1. Reverse DNS (PTR).
      2. Scripts de nmap de alta prioridad en TODOS los servicios.
      3. Cualquier script de nmap en TODOS los servicios.

    Nota: filtra elementos no-dict en all_services (defensivo).
    """
    # 1. Reverse DNS
    try:
        fqdn = socket.gethostbyaddr(target)[0]
        parts = fqdn.split(".")
        if len(parts) >= 2 and not fqdn.startswith("localhost"):
            if len(parts) == 2:
                return fqdn.lower()
            return ".".join(parts[-2:]).lower()
    except Exception:
        pass

    # Construye lista solo con dicts válidos
    services_to_check = []
    if all_services:
        for s in all_services:
            if isinstance(s, dict):
                services_to_check.append(s)

    if isinstance(service, dict) and service not in services_to_check:
        services_to_check.append(service)

    # 2. Scripts de alta prioridad
    for svc in services_to_check:
        scripts = svc.get("scripts", {}) or {}
        for key in PRIORITY_SCRIPTS:
            if key in scripts:
                m = DOMAIN_RE.search(str(scripts[key]))
                if m:
                    return m.group(1).lower()

    # 3. Cualquier script
    for svc in services_to_check:
        scripts = svc.get("scripts", {}) or {}
        for key, val in scripts.items():
            m = DOMAIN_RE.search(str(val))
            if m:
                return m.group(1).lower()

    return None


def _try_axfr(target, domain, timeout=30):
    """Intenta transferencia de zona contra el target."""
    out = _run(["dig", "AXFR", f"@{target}", domain], timeout=timeout)
    if not out:
        return None
    if "Transfer failed" in out or "communications error" in out:
        return None
    if "SOA" in out and len(out.splitlines()) > 2:
        return out
    return None


def _parse_axfr(output, domain):
    """Parsea la salida de dig AXFR a lista de registros."""
    records = []
    seen_soa = False
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split()
        if len(parts) < 4 or "IN" not in parts:
            continue
        try:
            idx = parts.index("IN")
            name = parts[0].rstrip(".")
            rtype = parts[idx + 1]
            value = " ".join(parts[idx + 2:])
            if rtype == "SOA":
                if seen_soa:
                    continue
                seen_soa = True
            records.append({
                "name": name,
                "type": rtype,
                "value": value,
            })
        except (ValueError, IndexError):
            continue
    return records


def _brute_subdomains(domain, wordlist, threads=10, timeout=300):
    """Lanza dnsrecon brute force contra el dominio."""
    out_json = Path("/tmp") / f"dnsrecon_{domain}.json"
    if out_json.exists():
        out_json.unlink()

    cmd = [
        "dnsrecon", "-d", domain,
        "-D", wordlist,
        "-t", "brt",
        "-f",
        "--threads", str(threads),
        "-j", str(out_json),
    ]
    _run(cmd, timeout=timeout)

    if out_json.exists():
        try:
            return json.loads(out_json.read_text())
        except Exception as e:
            log.warning(f"[!] no pude parsear dnsrecon JSON: {e}")
    return None


def _parse_dnsrecon(data):
    subdomains = []
    for rec in data.get("records", []) or []:
        rtype = rec.get("type", "").upper()
        if rtype in ("A", "CNAME", "AAAA"):
            name = rec.get("name", "")
            address = rec.get("address") or rec.get("target") or ""
            if name:
                subdomains.append({
                    "name": name,
                    "address": address,
                    "type": rtype,
                })
    return subdomains


def enumerate(service, target, outdir, wordlist=None, all_services=None):
    port = service["port"]

    result = {
        "port": port,
        "service": service["name"],
        "product": service.get("product", ""),
        "version": service.get("version", ""),
        "nmap_scripts": service.get("scripts", {}),
        "domain": None,
        "reverse": None,
        "axfr": False,
        "axfr_records": [],
        "subdomains": [],
        "findings": [],
    }

    # --- 1. Reverse lookup ---
    try:
        result["reverse"] = socket.gethostbyaddr(target)[0]
    except Exception:
        pass

    # --- 2. Descubrir dominio (con contexto global) ---
    result["domain"] = _discover_domain(
        target, service, all_services=all_services
    )
    if not result["domain"]:
        log.info(f"[-] DNS sin dominio descubierto en {target}:{port}")
        return result

    log.success(f"[+] DNS dominio descubierto: {result['domain']}")

    # --- 3. AXFR ---
    axfr_out = _try_axfr(target, result["domain"])
    if axfr_out:
        result["axfr"] = True
        result["axfr_records"] = _parse_axfr(axfr_out, result["domain"])
        log.warning(
            f"[!] DNS AXFR permitido en {target}:{port} "
            f"({len(result['axfr_records'])} registros)"
        )
        result["findings"].append({
            "severity": "critical",
            "title": "DNS zone transfer permitido (AXFR)",
            "detail": f"{len(result['axfr_records'])} registros expuestos. "
                      f"Zona: {result['domain']}",
        })
        result["subdomains"] = [
            {"name": r["name"], "address": r["value"], "type": r["type"]}
            for r in result["axfr_records"]
            if r["type"] in ("A", "CNAME", "AAAA")
        ]
    else:
        log.info(f"[-] DNS AXFR denegado en {target}:{port}")

    # --- 4. Brute force (solo si AXFR no dio nada) ---
    if not result["subdomains"]:
        if wordlist is None:
            wordlist = _find_wordlist()

        if not wordlist:
            log.warning(f"[!] DNS sin wordlist disponible, saltando brute force")
        else:
            log.info(f"[*] DNS brute force contra {result['domain']} con {wordlist}")
            data = _brute_subdomains(result["domain"], wordlist)
            if data:
                result["subdomains"] = _parse_dnsrecon(data)
                if result["subdomains"]:
                    log.success(
                        f"[+] {len(result['subdomains'])} subdominios encontrados "
                        f"en {result['domain']}"
                    )
                    result["findings"].append({
                        "severity": "warning",
                        "title": f"{len(result['subdomains'])} subdominios DNS",
                        "detail": ", ".join(
                            s["name"] for s in result["subdomains"][:5]
                        ),
                    })
                else:
                    log.info(f"[-] DNS sin subdominios encontrados en {result['domain']}")

    # --- Findings info ---
    if result["reverse"]:
        result["findings"].append({
            "severity": "info",
            "title": f"DNS reverse: {result['reverse']}",
        })

    return result