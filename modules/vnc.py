import subprocess
import re
from pathlib import Path
from utils.logger import log


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Passwords típicos de CTF / labs (VNC solo acepta 8 chars max)
COMMON_PASSWORDS = [
    "password", "123456", "vnc", "vncpass", "admin", "root",
    "toor", "letmein", "secret", "qwerty", "12345678",
    "password1", "changeme", "default", "vncpassword",
]


def _run(cmd, timeout=60):
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return ANSI_RE.sub("", r.stdout).strip()
    except subprocess.TimeoutExpired:
        log.warning(f"[!] timeout: {' '.join(cmd)}")
    except FileNotFoundError:
        log.error(f"[!] comando no encontrado: {cmd[0]}")
    except Exception as e:
        log.warning(f"[!] fallo {' '.join(cmd)}: {e}")
    return None


def _parse_vnc_info(scripts):
    """Extrae info útil del output de vnc-info (NSE)."""
    info = {}
    raw = scripts.get("vnc-info", "")
    if not raw:
        return info

    # Protocol version
    m = re.search(r"Protocol version:\s*([\d.]+)", raw)
    if m:
        info["protocol_version"] = m.group(1)

    # Security types
    m = re.search(r"Security types:\s*\n((?:\s+.+\n?)+)", raw)
    if m:
        types = [l.strip() for l in m.group(1).splitlines() if l.strip()]
        info["security_types"] = types

    # Auth (None / VNC Authentication)
    m = re.search(r"Authentication:\s*(.+)", raw)
    if m:
        info["authentication"] = m.group(1).strip()

    return info


def _try_password(target, port, password, timeout=15):
    """Prueba una password con vncdotool si está disponible.

    Devuelve True si la autenticación tuvo éxito.
    """
    # vncdotool -s host::port -p password capture /tmp/x.png
    try:
        r = subprocess.run(
            [
                "vncdotool", "-s", f"{target}::{port}",
                "-p", password,
                "capture", "/tmp/vnc_probe.png",
            ],
            capture_output=True, text=True, timeout=timeout,
        )
        # Si el return code es 0, la auth funcionó
        return r.returncode == 0
    except FileNotFoundError:
        return None  # vncdotool no instalado
    except Exception:
        return False


def enumerate(service, target, outdir):
    port = service["port"]
    scripts = service.get("scripts", {})

    result = {
        "port": port,
        "service": "vnc",
        "product": service.get("product", ""),
        "version": service.get("version", ""),
        "nmap_scripts": scripts,
        "vnc_info": _parse_vnc_info(scripts),
        "no_auth": False,
        "weak_password": None,
        "findings": [],
    }

    # --- 1. Análisis del NSE vnc-info ---
    vnc_info = result["vnc_info"]
    auth = vnc_info.get("authentication", "").lower()

    # VNC sin autenticación → CRÍTICO
    if "none" in auth:
        result["no_auth"] = True
        log.warning(f"[!] VNC SIN autenticación en {target}:{port}")
        result["findings"].append({
            "severity": "critical",
            "title": "VNC sin autenticación",
            "detail": "Cualquiera puede conectarse al escritorio remoto.",
        })

    # realvnc-auth-bypass (CVE-2006-2369)
    bypass = scripts.get("realvnc-auth-bypass", "")
    if bypass and "bypass" in bypass.lower() and "not vulnerable" not in bypass.lower():
        result["findings"].append({
            "severity": "critical",
            "title": "RealVNC auth bypass (CVE-2006-2369)",
            "detail": "Autenticación evadible sin credenciales.",
        })

    # vnc-title → a veces revela el nombre del host/sesión
    title = scripts.get("vnc-title", "")
    if title:
        result["desktop_title"] = title.strip()
        log.info(f"[*] VNC título: {title.strip()}")

    # --- 2. Probar passwords débiles con vncdotool (si auth VNC) ---
    if not result["no_auth"] and "vnc authentication" in auth:
        vncdotool_ok = _try_password(target, port, "___probe___")
        if vncdotool_ok is None:
            log.info("[-] vncdotool no instalado; saltando prueba de passwords débiles")
        else:
            for pw in COMMON_PASSWORDS:
                if _try_password(target, port, pw):
                    result["weak_password"] = pw
                    log.success(f"[+] VNC password débil en {target}:{port}: '{pw}'")
                    result["findings"].append({
                        "severity": "critical",
                        "title": f"VNC password débil: '{pw}'",
                        "detail": "Acceso completo al escritorio remoto.",
                    })
                    break

    # --- 3. Findings informativos ---
    if vnc_info.get("protocol_version"):
        result["findings"].append({
            "severity": "info",
            "title": f"VNC protocol {vnc_info['protocol_version']}",
        })

    if vnc_info.get("security_types"):
        result["findings"].append({
            "severity": "info",
            "title": "VNC security types",
            "detail": ", ".join(vnc_info["security_types"][:5]),
        })

    return result
