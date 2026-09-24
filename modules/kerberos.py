import subprocess
import re
import socket
import os
from pathlib import Path
from utils.logger import log


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Ruta al script de kerbrute (Impacket)
KERBRUTE_PATHS = [
    "/home/mksk/scripts/kerbrute/kerbrute.py",
    os.path.expanduser("~/scripts/kerbrute/kerbrute.py"),
]

# Wordlist de usuarios
DEFAULT_USER_WORDLISTS = [
    "/home/mksk/wordlists/userlist.txt",
    "/home/mksk/wordlists/top-usernames-shortlist.txt",
]

# Wordlist de contraseñas
DEFAULT_PASS_WORDLISTS = [
    "/home/mksk/wordlists/passwords.txt",
    "/home/mksk/wordlists/rockyou.txt",
]

# Dominios por defecto de Samba que hay que ignorar
EXCLUDE_REALMS = {"SAMBA.ORG", "SAMBA.LOCAL"}


def _run(cmd, timeout=300):
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


def _find_kerbrute():
    for p in KERBRUTE_PATHS:
        if os.path.isfile(p):
            return p
    return None


def _find_user_wordlist():
    for w in DEFAULT_USER_WORDLISTS:
        if Path(w).exists():
            return w
    return None


def _find_pass_wordlist():
    for w in DEFAULT_PASS_WORDLISTS:
        if Path(w).exists():
            return w
    return None


def _discover_realm(target, service, all_services=None):
    """Descubre el realm Kerberos (dominio AD)."""
    # 1. Reverse DNS
    try:
        fqdn = socket.gethostbyaddr(target)[0]
        parts = fqdn.split(".")
        if len(parts) >= 2 and not fqdn.startswith("localhost"):
            return ".".join(parts[-2:]).upper()
    except Exception:
        pass

    # 2. Recopilar servicios
    services_to_check = []
    if all_services:
        for s in all_services:
            if isinstance(s, dict):
                services_to_check.append(s)
    if isinstance(service, dict) and service not in services_to_check:
        services_to_check.append(service)

    # 3. Contar dominios
    DOMAIN_RE = re.compile(
        r'\b([a-zA-Z0-9][a-zA-Z0-9-]{1,62}\.(?:local|htb|thm|lan|internal|corp|com|net|org))\b'
    )

    counts = {}
    for svc in services_to_check:
        scripts = svc.get("scripts", {}) or {}
        for key, val in scripts.items():
            for m in DOMAIN_RE.finditer(str(val)):
                dom = m.group(1).upper()
                if dom in EXCLUDE_REALMS:
                    continue
                counts[dom] = counts.get(dom, 0) + 1

    if counts:
        return max(counts, key=counts.get)

    return None


def _kerbrute_password_spray(kerbrute_script, target, realm, users_file, passwords_file, timeout=300):
    """Ejecuta kerbrute.py de Impacket para password spraying."""
    cmd = [
        "python3", kerbrute_script,
        "-users", users_file,
        "-passwords", passwords_file,
        "-domain", realm,
        "-dc-ip", target,
        "-threads", "10",
        "-no-save-ticket",
    ]
    return _run(cmd, timeout=timeout)


def _parse_impacket_output(output):
    """Extrae usuarios y credenciales válidas de la salida de kerbrute de Impacket.

    Formatos esperados:
      [*] Valid user => jdoe
      [*] Stupendous => asmith:Passw0rd!2026
    """
    users = []
    creds = []

    for line in output.splitlines():
        line = line.strip()

        # [*] Valid user => jdoe
        m = re.search(r'\[\*\]\s+Valid user\s*=>\s*([^\s]+)', line)
        if m:
            users.append(m.group(1))
            continue

        # [*] Stupendous => user:password
        m = re.search(r'\[\*\]\s+Stupendous\s*=>\s*([^:\s]+):([^\s]+)', line)
        if m:
            creds.append(f"{m.group(1)}:{m.group(2)}")
            continue

    return users, creds


def enumerate(service, target, outdir, all_services=None):
    port = service["port"]

    result = {
        "port": port,
        "service": service["name"],
        "product": service.get("product", ""),
        "version": service.get("version", ""),
        "nmap_scripts": service.get("scripts", {}),
        "realm": None,
        "users": [],
        "credentials": [],
        "findings": [],
    }

    # --- 1. Descubrir realm ---
    result["realm"] = _discover_realm(target, service, all_services=all_services)

    if not result["realm"]:
        log.info(f"[-] Kerberos sin realm descubierto en {target}:{port}")
        result["findings"].append({
            "severity": "info",
            "title": "Kerberos detectado (realm no descubierto)",
        })
        return result

    log.success(f"[+] Kerberos realm descubierto: {result['realm']}")

    # --- 2. Solo ejecutamos en el puerto 88 ---
    if port != 88:
        result["findings"].append({
            "severity": "info",
            "title": f"Kerberos realm: {result['realm']}",
        })
        return result

    # --- 3. Buscar kerbrute ---
    kerbrute_script = _find_kerbrute()
    if not kerbrute_script:
        log.warning("[!] kerbrute.py (Impacket) no encontrado")
        result["findings"].append({
            "severity": "info",
            "title": f"Kerberos realm: {result['realm']} (kerbrute no disponible)",
        })
        return result

    # --- 4. Buscar wordlists ---
    users_file = _find_user_wordlist()
    passwords_file = _find_pass_wordlist()

    if not users_file or not passwords_file:
        log.warning("[!] Kerberos sin wordlists de usuarios o contraseñas")
        result["findings"].append({
            "severity": "info",
            "title": f"Kerberos realm: {result['realm']} (sin wordlists)",
        })
        return result

    # --- 5. Password spraying ---
    log.info(f"[*] Kerberos password spray contra {result['realm']}")
    log.info(f"    Usuarios: {users_file}")
    log.info(f"    Contraseñas: {passwords_file}")

    out = _kerbrute_password_spray(
        kerbrute_script, target, result["realm"], users_file, passwords_file
    )

    if not out:
        log.warning(f"[!] kerbrute falló contra {target}:{port}")
        result["findings"].append({
            "severity": "info",
            "title": f"Kerberos realm: {result['realm']} (kerbrute falló)",
        })
        return result

    # --- 6. Parsear resultados ---
    users, creds = _parse_impacket_output(out)
    result["users"] = users
    result["credentials"] = creds

    result["findings"].append({
        "severity": "info",
        "title": f"Kerberos realm: {result['realm']}",
    })

    # --- 7. Findings por usuarios ---
    if users:
        log.success(
            f"[+] Kerberos {len(users)} usuarios válidos en {result['realm']}"
        )
        result["findings"].append({
            "severity": "warning",
            "title": f"{len(users)} usuarios Kerberos enumerados",
            "detail": ", ".join(users[:10]),
        })

    # --- 8. Findings por credenciales ---
    if creds:
        log.success(
            f"[+] Kerberos {len(creds)} credenciales válidas en {result['realm']}"
        )
        result["findings"].append({
            "severity": "critical",
            "title": f"{len(creds)} credenciales Kerberos válidas",
            "detail": ", ".join(creds[:5]),
        })

    # --- 9. Usuarios interesantes ---
    interesting = [u for u in users
                   if any(x in u.lower() for x in
                          ("admin", "svc", "service", "backup", "krbtgt"))]
    if interesting:
        result["findings"].append({
            "severity": "warning",
            "title": f"Usuarios Kerberos interesantes: {', '.join(interesting[:5])}",
            "detail": "Candidatos a Kerberoasting o AS-REP Roasting.",
        })

    if not users and not creds:
        log.info(f"[-] Kerberos sin usuarios ni credenciales en {result['realm']}")

    return result