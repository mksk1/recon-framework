import subprocess
import re
from utils.logger import log

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
PROGRESS_RE = re.compile(r"\[[\\|/\-*]\] .*?\.\.\.\s*")


def _clean_smbmap(out):
    """Limpia el output de smbmap: quita ANSI, spinners y líneas vacías."""
    out = ANSI_RE.sub("", out)
    out = PROGRESS_RE.sub("", out)
    out = out.replace("\r", "\n")
    lines = [l.rstrip() for l in out.splitlines() if l.strip()]
    return "\n".join(lines)


def _parse_shares(output):
    """Extrae la tabla de shares del output de smbmap a lista de dicts.

    Formato esperado (separado por TABS):
        \\tDisk\\tPermissions\\tComment
        \\t----\\t-----------\\t-------
        \\tprint$\\tNO ACCESS\\tPrinter Drivers
        \\tpublic\\tREAD, WRITE\\t
    """
    shares = []
    in_table = False
    for line in output.splitlines():
        stripped = line.strip()

        # Cabecera de la tabla
        if "Disk" in stripped and "Permissions" in stripped:
            in_table = True
            continue
        # Separador
        if in_table and stripped.startswith("----"):
            continue
        # Filas
        if in_table and stripped:
            # Corta al salir de la tabla
            if stripped.startswith("[") or stripped.startswith("+"):
                break

            # CLAVE: partir por TAB, no por whitespace genérico
            parts = [p.strip() for p in line.split("\t") if p.strip()]
            if len(parts) < 2:
                # Fallback por si no hay tabs
                parts = stripped.split(None, 2)

            name = parts[0]
            permissions = parts[1] if len(parts) > 1 else ""
            comment = parts[2] if len(parts) > 2 else ""

            shares.append({
                "name": name,
                "permissions": permissions,
                "comment": comment,
            })
    return shares


def _run_smbmap(target, port, extra_args):
    """Ejecuta smbmap con args extra y devuelve stdout limpio o None."""
    try:
        r = subprocess.run(
            ["smbmap", "-H", target, "-P", str(port),
             *extra_args, "--no-banner", "--no-color"],
            capture_output=True, text=True, timeout=120
        )
        return _clean_smbmap(r.stdout)
    except subprocess.TimeoutExpired:
        log.warning(f"[!] smbmap timeout en {target}:{port}")
    except FileNotFoundError:
        log.error("[!] smbmap no está instalado")
    except Exception as e:
        log.warning(f"[!] smbmap falló en {target}:{port}: {e}")
    return None


def _session_info(output):
    """Analiza el output de smbmap y devuelve info sobre la sesión.

    Devuelve un dict con:
      - status: "none" | "authenticated" | "denied"
      - shares_with_access: lista de nombres de shares accesibles
    """
    info = {"status": "none", "shares_with_access": []}

    if not output:
        return info

    if "Status: Authenticated" in output:
        info["status"] = "authenticated"
    elif "Status: Authentication error" in output or "denied" in output.lower():
        info["status"] = "denied"
        return info

    # Buscar shares con acceso (no "NO ACCESS")
    shares = _parse_shares(output)
    for s in shares:
        perms = s.get("permissions", "").upper()
        if perms and "NO ACCESS" not in perms:
            info["shares_with_access"].append(s["name"])

    return info


def enumerate(service, target, outdir):
    port = service["port"]

    result = {
        "port": port,
        "service": service["name"],
        "product": service.get("product", ""),
        "version": service.get("version", ""),
        "nmap_scripts": service.get("scripts", {}),
        "smbmap": None,
        "smbmap_anon": None,
        "shares": [],
        "shares_anon": [],
        "session_anon": None,
        "session_guest": None,
    }

    # --- 1) Sesión nula real (-u '' -p '') ---
    result["smbmap_anon"] = _run_smbmap(target, port, ["-u", "", "-p", ""])
    if result["smbmap_anon"]:
        result["shares_anon"] = _parse_shares(result["smbmap_anon"])
        anon = _session_info(result["smbmap_anon"])
        result["session_anon"] = anon

        if anon["status"] == "authenticated" and anon["shares_with_access"]:
            log.success(
                f"[+] SMB sesión NULA con acceso en {target}:{port} "
                f"→ {', '.join(anon['shares_with_access'])}"
            )
        elif anon["status"] == "authenticated":
            log.info(f"[-] SMB sesión nula autenticada pero sin acceso útil en {target}:{port}")
        else:
            log.info(f"[-] SMB sesión nula rechazada en {target}:{port}")

    # --- 2) Guest (sin credenciales) ---
    result["smbmap"] = _run_smbmap(target, port, [])
    if result["smbmap"]:
        result["shares"] = _parse_shares(result["smbmap"])
        guest = _session_info(result["smbmap"])
        result["session_guest"] = guest

        if guest["status"] == "authenticated" and guest["shares_with_access"]:
            log.success(
                f"[+] SMB sesión GUEST con acceso en {target}:{port} "
                f"→ {', '.join(guest['shares_with_access'])}"
            )
        elif guest["status"] == "authenticated":
            log.info(f"[-] SMB guest autenticado pero sin acceso útil en {target}:{port}")
        else:
            log.info(f"[-] SMB guest rechazado en {target}:{port}")

    return result
