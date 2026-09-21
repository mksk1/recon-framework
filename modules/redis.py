import subprocess
import re
from utils.logger import log


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Contraseñas comunes en Redis (muy frecuentes en CTFs)
COMMON_PASSWORDS = [
    "redis",
    "password",
    "admin",
    "root",
    "foobared",      # la del ejemplo por defecto de Redis
    "123456",
    "redis123",
    "default",
    "changeme",
    "toor",
    "test",
]


def _run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return ANSI_RE.sub("", r.stdout).strip()
    except subprocess.TimeoutExpired:
        log.warning(f"[!] timeout: {' '.join(cmd)}")
    except FileNotFoundError:
        log.error(f"[!] comando no encontrado: {cmd[0]} (apt install redis-tools)")
    except Exception as e:
        log.warning(f"[!] fallo {' '.join(cmd)}: {e}")
    return None


def _redis_cmd(target, port, *args, timeout=10):
    cmd = ["redis-cli", "-h", target, "-p", str(port),
           "--no-auth-warning", *args]
    return _run(cmd, timeout=timeout)


def _try_auth(target, port):
    """Devuelve (auth_required, password) o (None, None) si no responde."""
    # 1. Sin contraseña
    pong = _redis_cmd(target, port, "PING")
    if pong and "PONG" in pong.upper():
        return False, None

    # 2. Con contraseñas comunes
    if pong and "NOAUTH" in pong.upper():
        for pw in COMMON_PASSWORDS:
            out = _redis_cmd(target, port, "-a", pw, "PING")
            if out and "PONG" in out.upper():
                return True, pw
        return True, None

    return None, None


def _auth_args(password):
    if password is None:
        return []
    return ["-a", password]


def enumerate(service, target, outdir):
    port = service["port"]

    result = {
        "port": port,
        "service": service["name"],
        "product": service.get("product", ""),
        "version": service.get("version", ""),
        "nmap_scripts": service.get("scripts", {}),
        "auth_required": None,
        "auth_password": None,
        "info": {},
        "keys_sample": [],
        "findings": [],
    }

    # --- 1. Autenticación ---
    auth_required, password = _try_auth(target, port)

    if auth_required is None:
        log.info(f"[-] Redis sin respuesta en {target}:{port}")
        return result

    result["auth_required"] = auth_required
    result["auth_password"] = password

    if password:
        log.warning(
            f"[!] Redis auth con contraseña débil en {target}:{port}: '{password}'"
        )
        result["findings"].append({
            "severity": "critical",
            "title": f"Redis con contraseña débil: '{password}'",
            "detail": "Contraseña trivialmente adivinable.",
        })
    elif auth_required:
        log.info(f"[-] Redis requiere autenticación en {target}:{port}")
        result["findings"].append({
            "severity": "info",
            "title": "Redis requiere autenticación (no se encontró contraseña)",
        })
        return result
    else:
        log.success(f"[+] Redis sin autenticación en {target}:{port}")
        result["findings"].append({
            "severity": "critical",
            "title": "Redis sin autenticación",
            "detail": "Cualquiera puede ejecutar comandos.",
        })

    auth = _auth_args(password)

    # --- 2. INFO ---
    info_out = _redis_cmd(target, port, *auth, "INFO", timeout=15)
    if info_out:
        info = {}
        for line in info_out.splitlines():
            if ":" in line and not line.startswith("#"):
                k, _, v = line.partition(":")
                info[k.strip()] = v.strip()
        result["info"] = {
            "redis_version": info.get("redis_version"),
            "redis_mode": info.get("redis_mode"),
            "os": info.get("os"),
            "arch_bits": info.get("arch_bits"),
            "uptime_in_seconds": info.get("uptime_in_seconds"),
            "connected_clients": info.get("connected_clients"),
            "used_memory_human": info.get("used_memory_human"),
        }
        if info.get("redis_version"):
            log.info(f"[+] Redis versión: {info['redis_version']}")

    # --- 3. CONFIG GET dir ---
    dir_out = _redis_cmd(target, port, *auth, "CONFIG", "GET", "dir")
    if dir_out and "dir" in dir_out.lower():
        lines = dir_out.splitlines()
        if len(lines) >= 2:
            result["info"]["config_dir"] = lines[1].strip()

    # --- 4. DBSIZE + muestreo de claves ---
    dbsize = _redis_cmd(target, port, *auth, "DBSIZE")
    if dbsize and dbsize.strip().isdigit():
        n_keys = int(dbsize.strip())
        result["info"]["keys_count"] = n_keys

        if n_keys > 0:
            log.success(f"[+] Redis con {n_keys} claves en {target}:{port}")
            result["findings"].append({
                "severity": "warning",
                "title": f"Redis con {n_keys} claves accesibles",
                "detail": "Puede contener datos sensibles.",
            })

            keys_out = _redis_cmd(target, port, *auth, "KEYS", "*", timeout=15)
            if keys_out:
                keys = [k.strip() for k in keys_out.splitlines() if k.strip()]
                result["keys_sample"] = keys[:20]

                suspicious = [k for k in keys if any(
                    x in k.lower() for x in ("pass", "secret", "token", "key", "user")
                )]
                if suspicious:
                    result["findings"].append({
                        "severity": "warning",
                        "title": f"{len(suspicious)} claves sospechosas",
                        "detail": ", ".join(suspicious[:5]),
                    })
    else:
        result["info"]["keys_count"] = 0

    # --- 5. Comprobar si permite escribir ---
    test_key = "recon_framework_test"
    set_out = _redis_cmd(target, port, *auth, "SET", test_key, "test")
    if set_out and "OK" in set_out.upper():
        result["info"]["write_enabled"] = True
        result["findings"].append({
            "severity": "critical",
            "title": "Redis permite escritura",
            "detail": "Vulnerable a escritura de archivos / RCE.",
        })
        _redis_cmd(target, port, *auth, "DEL", test_key)
    else:
        result["info"]["write_enabled"] = False

    return result
