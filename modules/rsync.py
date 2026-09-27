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
        log.error(f"[!] comando no encontrado: {cmd[0]} (apt install rsync)")
    except Exception as e:
        log.warning(f"[!] fallo {' '.join(cmd)}: {e}")
    return None


def _list_modules(target, port):
    """Lista los módulos disponibles en el servidor rsync."""
    out = _run(["rsync", "--list-only", f"rsync://{target}:{port}/"])
    if not out:
        return []
    modules = []
    for line in out.splitlines():
        # Formato: "public          Directorio Público de Pruebas"
        parts = line.split(None, 1)
        if parts:
            modules.append({
                "name": parts[0],
                "comment": parts[1] if len(parts) > 1 else "",
            })
    return modules


def _list_module_contents(target, port, module):
    """Lista el contenido de un módulo específico."""
    out = _run(["rsync", "--list-only", f"rsync://{target}:{port}/{module}/"])
    if not out:
        return []
    files = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5:
            filename = parts[-1]
            # Ignora entradas del propio directorio
            if filename in (".", ".."):
                continue
            files.append(filename)
    return files


def enumerate(service, target, outdir):
    port = service["port"]

    result = {
        "port": port,
        "service": service["name"],
        "product": service.get("product", ""),
        "version": service.get("version", ""),
        "nmap_scripts": service.get("scripts", {}),
        "modules": [],
        "module_contents": {},
        "findings": [],
    }

    # --- 1. Listar módulos ---
    modules = _list_modules(target, port)
    if not modules:
        log.info(f"[-] Rsync sin módulos accesibles en {target}:{port}")
        result["findings"].append({
            "severity": "info",
            "title": "Rsync detectado (sin módulos accesibles)",
        })
        return result

    result["modules"] = modules
    log.success(f"[+] Rsync {len(modules)} módulos en {target}:{port}")

    # Singular/plural
    mod_word = "módulo" if len(modules) == 1 else "módulos"
    result["findings"].append({
        "severity": "warning",
        "title": f"Rsync con {len(modules)} {mod_word} expuestos",
        "detail": ", ".join(m["name"] for m in modules[:5]),
    })

    # --- 2. Listar contenido de cada módulo ---
    for mod in modules:
        mod_name = mod["name"]
        files = _list_module_contents(target, port, mod_name)
        if files:
            result["module_contents"][mod_name] = files
            log.info(f"[+]   Módulo '{mod_name}': {len(files)} archivos")
            # Archivos con nombres sospechosos
            suspicious = [f for f in files if any(
                x in f.lower() for x in
                (".env", "pass", "secret", "key", "backup", "db", ".sql",
                 ".conf", ".cfg", "id_rsa", ".pem", ".key")
            )]
            if suspicious:
                result["findings"].append({
                    "severity": "warning",
                    "title": f"Rsync módulo '{mod_name}' con archivos sensibles",
                    "detail": ", ".join(suspicious[:5]),
                })

    return result