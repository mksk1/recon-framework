import subprocess
import re
from utils.logger import log


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Base DNs típicos que probamos si no detectamos el real
COMMON_BASE_DNS = [
    "dc=example,dc=com",
    "dc=local",
    "dc=domain,dc=local",
    "dc=corp,dc=local",
    "dc=htb",
    "dc=thm",
    "dc=internal",
]


def _run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return ANSI_RE.sub("", r.stdout).strip()
    except subprocess.TimeoutExpired:
        log.warning(f"[!] timeout: {' '.join(cmd)}")
    except FileNotFoundError:
        log.error(f"[!] comando no encontrado: {cmd[0]} (apt install ldap-utils)")
    except Exception as e:
        log.warning(f"[!] fallo {' '.join(cmd)}: {e}")
    return None


def _query_rootdse(target, port):
    """Consulta el rootDSE para sacar namingContexts."""
    out = _run(["ldapsearch", "-x", "-H", f"ldap://{target}:{port}",
                "-b", "", "-s", "base", "namingContexts"])
    if not out:
        return []
    contexts = []
    for line in out.splitlines():
        line = line.strip()
        if line.lower().startswith("namingcontexts:"):
            ctx = line.split(":", 1)[1].strip()
            if ctx:
                contexts.append(ctx)
    return contexts


def _try_base_dn(target, port, base_dn):
    """Intenta leer la raíz del Base DN con anonymous bind."""
    out = _run(["ldapsearch", "-x", "-H", f"ldap://{target}:{port}",
                "-b", base_dn, "-s", "base", "-LLL"])
    if not out:
        return None
    if "dn:" not in out:
        return None
    return out


def _search_subtree(target, port, base_dn, timeout=60):
    """Búsqueda completa del subárbol (anonymous)."""
    out = _run(["ldapsearch", "-x", "-H", f"ldap://{target}:{port}",
                "-b", base_dn, "-LLL"], timeout=timeout)
    if not out:
        return None
    # Con -LLL no hay "result: 0 Success", pero sí "dn:"
    if "dn:" not in out:
        return None
    return out


def _parse_ldif(output):
    """Parsea la salida LDIF a lista de dicts (una entrada por dict)."""
    entries = []
    current = {}
    for line in output.splitlines():
        line = line.rstrip()
        if not line:
            # fin de una entrada
            if current:
                entries.append(current)
                current = {}
            continue
        if line.startswith("#"):
            continue
        if line.startswith(" "):
            # continuación de la línea anterior (folded)
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            if key in current:
                if not isinstance(current[key], list):
                    current[key] = [current[key]]
                current[key].append(value)
            else:
                current[key] = value
    if current:
        entries.append(current)
    return entries


def _extract_users(entries):
    """Extrae usuarios (uid o cn con mail) de las entradas."""
    users = []
    for e in entries:
        uid = e.get("uid")
        cn = e.get("cn")
        mail = e.get("mail")
        if uid or (cn and mail):
            users.append({
                "uid": uid or cn,
                "cn": cn,
                "mail": mail,
                "dn": e.get("dn"),
            })
    return users


def _extract_groups(entries):
    """Extrae grupos (objectClass: groupOfNames / posixGroup)."""
    groups = []
    for e in entries:
        ocs = e.get("objectClass") or []
        if isinstance(ocs, str):
            ocs = [ocs]
        if any(oc.lower() in ("groupofnames", "posixgroup", "groupofuniquenames")
               for oc in ocs):
            groups.append({
                "cn": e.get("cn"),
                "dn": e.get("dn"),
                "members": e.get("member") or e.get("memberUid") or [],
            })
    return groups


def enumerate(service, target, outdir):
    port = service["port"]

    result = {
        "port": port,
        "service": service["name"],
        "product": service.get("product", ""),
        "version": service.get("version", ""),
        "nmap_scripts": service.get("scripts", {}),
        "base_dn": None,
        "anonymous_bind": False,
        "entries_count": 0,
        "users": [],
        "groups": [],
        "findings": [],
    }

    # --- 1. RootDSE (namingContexts) ---
    contexts = _query_rootdse(target, port)
    if contexts:
        result["base_dn"] = contexts[0]
        log.info(f"[+] LDAP namingContexts: {', '.join(contexts)}")

    # --- 2. Si no hay base_dn, probar comunes ---
    candidates = []
    if result["base_dn"]:
        candidates.append(result["base_dn"])
    candidates.extend([c for c in COMMON_BASE_DNS if c not in candidates])

    for base_dn in candidates:
        if _try_base_dn(target, port, base_dn):
            result["base_dn"] = base_dn
            result["anonymous_bind"] = True
            break

    if not result["base_dn"]:
        log.info(f"[-] LDAP sin Base DN detectado en {target}:{port}")
        result["findings"].append({
            "severity": "info",
            "title": "LDAP detectado (Base DN no descubierto)",
        })
        return result

    log.success(f"[+] LDAP Base DN: {result['base_dn']}")

    if not result["anonymous_bind"]:
        log.info(f"[-] LDAP anónimo no permitido en {target}:{port}")
        result["findings"].append({
            "severity": "info",
            "title": f"LDAP Base DN: {result['base_dn']} (anónimo no permitido)",
        })
        return result

    # --- 3. Búsqueda completa ---
    out = _search_subtree(target, port, result["base_dn"])
    if not out:
        log.info(f"[-] LDAP búsqueda vacía o denegada en {target}:{port}")
        return result

    entries = _parse_ldif(out)
    result["entries_count"] = len(entries)

    # --- 4. Extraer usuarios y grupos ---
    result["users"] = _extract_users(entries)
    result["groups"] = _extract_groups(entries)

    if result["users"]:
        log.success(
            f"[+] LDAP {len(result['users'])} usuarios encontrados "
            f"en {result['base_dn']}"
        )

    # --- 5. Findings ---
    result["findings"].append({
        "severity": "warning",
        "title": f"LDAP anonymous bind permitido ({result['base_dn']})",
        "detail": f"{len(entries)} entradas accesibles",
    })

    if result["users"]:
        uids = [u["uid"] for u in result["users"][:5] if u.get("uid")]
        result["findings"].append({
            "severity": "warning",
            "title": f"{len(result['users'])} usuarios LDAP enumerados",
            "detail": ", ".join(uids),
        })

    if result["groups"]:
        result["findings"].append({
            "severity": "info",
            "title": f"{len(result['groups'])} grupos LDAP",
        })

    return result
