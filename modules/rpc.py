import subprocess
import re
from utils.logger import log


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Programas RPC que merecen atención (posibles vectores)
INTERESTING_PROGRAMS = {
    100000: "portmapper",
    100003: "nfs",
    100005: "mountd",
    100021: "nlockmgr",
    100024: "status",
    100227: "nfs_acl",
    100004: "ypserv",
    100007: "ypbind",
    100009: "yppasswdd",
    100068: "cmountd",
}


def _run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return ANSI_RE.sub("", r.stdout).strip()
    except subprocess.TimeoutExpired:
        log.warning(f"[!] timeout: {' '.join(cmd)}")
    except FileNotFoundError:
        log.error(f"[!] comando no encontrado: {cmd[0]} (apt install rpcbind)")
    except Exception as e:
        log.warning(f"[!] fallo {' '.join(cmd)}: {e}")
    return None


def _parse_rpcinfo(output):
    """Parsea la salida de 'rpcinfo -p' a lista de dicts.

    Formato esperado:
       program vers proto   port  service
        100000    4   tcp    111  portmapper
        100000    3   tcp    111  portmapper
    """
    programs = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("program"):
            continue
        parts = stripped.split()
        if len(parts) < 5:
            continue
        try:
            programs.append({
                "program": int(parts[0]),
                "version": int(parts[1]),
                "proto": parts[2],
                "port": int(parts[3]),
                "service": parts[4] if len(parts) > 4 else "",
            })
        except (ValueError, IndexError):
            continue
    return programs


def enumerate(service, target, outdir):
    port = service["port"]

    result = {
        "port": port,
        "service": service["name"],
        "product": service.get("product", ""),
        "version": service.get("version", ""),
        "nmap_scripts": service.get("scripts", {}),
        "programs": [],
        "interesting": [],
        "findings": [],
    }

    # --- rpcinfo -p ---
    raw = _run(["rpcinfo", "-p", target])
    if not raw:
        log.info(f"[-] rpcbind sin respuesta en {target}:{port}")
        return result

    result["programs"] = _parse_rpcinfo(raw)

    if not result["programs"]:
        log.info(f"[-] rpcbind sin programas RPC listados en {target}:{port}")
        return result

    # --- Detectar programas interesantes ---
    for p in result["programs"]:
        name = INTERESTING_PROGRAMS.get(p["program"])
        if name and name != "portmapper":
            result["interesting"].append({
                "program": p["program"],
                "name": name,
                "version": p["version"],
                "proto": p["proto"],
                "port": p["port"],
            })

    # --- Log ---
    services_found = sorted({p["service"] for p in result["programs"] if p["service"]})
    log.success(
        f"[+] rpcbind en {target}:{port} → "
        f"{len(result['programs'])} programas RPC "
        f"({', '.join(services_found)})"
    )

    # --- Findings ---
    if result["interesting"]:
        names = sorted({i["name"] for i in result["interesting"]})
        log.warning(
            f"[!] Servicios RPC interesantes en {target}:{port}: "
            f"{', '.join(names)}"
        )
        result["findings"].append({
            "severity": "warning",
            "title": f"Servicios RPC expuestos: {', '.join(names)}",
            "detail": "Pueden permitir enumeración o acceso a NFS/NIS.",
        })
    else:
        result["findings"].append({
            "severity": "info",
            "title": f"{len(result['programs'])} programas RPC (solo portmapper)",
        })

    return result
