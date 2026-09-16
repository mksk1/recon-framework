import subprocess
import json
from utils.logger import log


# Máximo de hallazgos críticos a mostrar en consola antes de resumir
MAX_LOG_FINDINGS = 3


def _run_ssh_audit(target, port, timeout=60):
    """Ejecuta ssh-audit en modo JSON y devuelve el dict parseado, o None."""
    try:
        cmd = ["ssh-audit", "-j"]
        if port != 22:
            cmd += ["-p", str(port)]
        cmd.append(target)

        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        out = r.stdout.strip()
        if not out:
            log.warning(f"[!] ssh-audit sin salida para {target}:{port}")
            return None
        return json.loads(out)
    except subprocess.TimeoutExpired:
        log.warning(f"[!] ssh-audit timeout en {target}:{port}")
    except FileNotFoundError:
        log.error("[!] ssh-audit no está instalado (pip install ssh-audit)")
    except json.JSONDecodeError as e:
        log.warning(f"[!] ssh-audit JSON inválido para {target}:{port}: {e}")
    except Exception as e:
        log.warning(f"[!] ssh-audit falló en {target}:{port}: {e}")
    return None


def _extract_weaknesses(data):
    """Extrae algoritmos con notas fail/warn de cada categoría."""
    findings = {"critical": [], "warning": []}

    for category in ("kex", "key", "enc", "mac"):
        for item in data.get(category, []) or []:
            alg = item.get("algorithm", "?")
            notes = item.get("notes", {}) or {}

            for reason in notes.get("fail", []) or []:
                findings["critical"].append({
                    "category": category,
                    "algorithm": alg,
                    "reason": reason,
                })

            for reason in notes.get("warn", []) or []:
                findings["warning"].append({
                    "category": category,
                    "algorithm": alg,
                    "reason": reason,
                })

    return findings


def enumerate(service, target, outdir):
    port = service["port"]

    result = {
        "port": port,
        "service": service["name"],
        "product": service.get("product", ""),
        "version": service.get("version", ""),
        "nmap_scripts": service.get("scripts", {}),
        "banner": None,
        "software": None,
        "protocol": None,
        "fingerprints": [],
        "critical_findings": [],
        "warnings": [],
        "recommendations": {},
        "cves": [],
    }

    data = _run_ssh_audit(target, port)
    if not data:
        return result

    # --- Banner / software ---
    banner = data.get("banner", {}) or {}
    result["banner"] = banner.get("raw")
    result["software"] = banner.get("software")
    result["protocol"] = banner.get("protocol")

    # --- Fingerprints (solo SHA256, evita duplicados MD5) ---
    result["fingerprints"] = [
        {
            "hostkey": fp.get("hostkey"),
            "hash_alg": fp.get("hash_alg"),
            "hash": fp.get("hash"),
        }
        for fp in data.get("fingerprints", []) or []
        if fp.get("hash_alg") == "SHA256"
    ]

    # --- Debilidades ---
    weaknesses = _extract_weaknesses(data)
    result["critical_findings"] = weaknesses["critical"]
    result["warnings"] = weaknesses["warning"]

    # --- Recomendaciones y CVEs ---
    result["recommendations"] = data.get("recommendations", {}) or {}
    result["cves"] = data.get("cves", []) or []

    # --- Log resumen (limitado) ---
    n_crit = len(result["critical_findings"])
    n_warn = len(result["warnings"])

    if n_crit:
        log.warning(
            f"[!] SSH {target}:{port} → {n_crit} críticos, {n_warn} warnings"
        )
        for f in result["critical_findings"][:MAX_LOG_FINDINGS]:
            log.warning(f"    ✗ {f['category']}/{f['algorithm']}: {f['reason']}")
        restantes = n_crit - MAX_LOG_FINDINGS
        if restantes > 0:
            log.warning(f"    ... y {restantes} críticos más (ver reporte)")
    elif n_warn:
        log.info(f"[+] SSH {target}:{port} → sin críticos, {n_warn} warnings")
    else:
        log.success(f"[+] SSH {target}:{port} → configuración fuerte")

    return result
