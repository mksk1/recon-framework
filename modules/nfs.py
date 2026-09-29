import subprocess
import re
from utils.logger import log


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return ANSI_RE.sub("", r.stdout).strip()
    except subprocess.TimeoutExpired:
        log.warning(f"[!] timeout: {' '.join(cmd)}")
    except FileNotFoundError:
        log.error(f"[!] comando no encontrado: {cmd[0]} (apt install nfs-common)")
    except Exception as e:
        log.warning(f"[!] fallo {' '.join(cmd)}: {e}")
    return None


def _showmount(target, timeout=30):
    """Lista los exports NFS del target."""
    out = _run(["showmount", "-e", target], timeout=timeout)
    if not out:
        return []

    exports = []
    for line in out.splitlines():
        line = line.strip()
        # Ignora cabecera "Export list for..."
        if not line or line.startswith("Export list"):
            continue
        # Formato: "/srv/nfs/public *"
        parts = line.split(None, 1)
        if parts:
            exports.append({
                "path": parts[0],
                "clients": parts[1] if len(parts) > 1 else "",
            })
    return exports


def enumerate(service, target, outdir):
    port = service["port"]

    result = {
        "port": port,
        "service": service["name"],
        "product": service.get("product", ""),
        "version": service.get("version", ""),
        "nmap_scripts": service.get("scripts", {}),
        "exports": [],
        "findings": [],
    }

    # --- showmount -e ---
    exports = _showmount(target)

    if not exports:
        log.info(f"[-] NFS sin exports accesibles en {target}:{port}")
        result["findings"].append({
            "severity": "info",
            "title": "NFS detectado (sin exports accesibles)",
        })
        return result

    result["exports"] = exports
    log.success(f"[+] NFS {len(exports)} exports en {target}:{port}")

    # --- Findings ---
    export_word = "export" if len(exports) == 1 else "exports"
    result["findings"].append({
        "severity": "warning",
        "title": f"NFS con {len(exports)} {export_word} accesibles",
        "detail": ", ".join(e["path"] for e in exports[:5]),
    })

    # Exports con wildcard "*" son especialmente peligrosos
    wildcard = [e for e in exports if "*" in e.get("clients", "")]
    if wildcard:
        result["findings"].append({
            "severity": "critical",
            "title": f"{len(wildcard)} exports NFS con acceso desde cualquier IP (*)",
            "detail": ", ".join(e["path"] for e in wildcard[:5]),
        })

    return result
