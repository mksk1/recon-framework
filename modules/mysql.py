from utils.logger import log


def enumerate(service, target, outdir):
    port = service["port"]

    result = {
        "port": port,
        "service": service["name"],
        "product": service.get("product", ""),
        "version": service.get("version", ""),
        "nmap_scripts": service.get("scripts", {}),
        "findings": [],
    }

    scripts = result["nmap_scripts"]

    # --- Detección de acceso sin contraseña (solo si realmente funciona) ---
    if "mysql-empty-password" in scripts:
        out = scripts["mysql-empty-password"]
        out_l = out.lower()

        if ("account has no password" in out_l
                or ("root" in out_l and "no password" in out_l)
                or ("empty password" in out_l and "success" in out_l)):
            log.warning(f"[!] MySQL root sin password en {target}:{port}")
            result["findings"].append({
                "severity": "critical",
                "title": "MySQL root sin contraseña",
                "detail": out[:200],
            })
        elif ("not allowed to connect" in out_l
              or "access denied" in out_l
              or "connection refused" in out_l):
            log.info(f"[-] MySQL sin acceso desde este host en {target}:{port}")
            result["findings"].append({
                "severity": "info",
                "title": "MySQL sin acceso remoto (host no autorizado)",
                "detail": out[:200],
            })
        else:
            result["findings"].append({
                "severity": "info",
                "title": "MySQL script ejecutado sin confirmación de root vacío",
                "detail": out[:200],
            })

    # --- Bases de datos expuestas ---
    if "mysql-databases" in scripts:
        out = scripts["mysql-databases"]
        log.success(f"[+] MySQL bases de datos expuestas en {target}:{port}")
        result["findings"].append({
            "severity": "warning",
            "title": "MySQL bases de datos expuestas",
            "detail": out[:300],
        })

    # --- Usuarios enumerados ---
    if "mysql-users" in scripts:
        out = scripts["mysql-users"]
        result["findings"].append({
            "severity": "warning",
            "title": "MySQL usuarios enumerados",
            "detail": out[:300],
        })

    # --- Info de versión ---
    if "mysql-info" in scripts:
        out = scripts["mysql-info"]
        result["findings"].append({
            "severity": "info",
            "title": f"MySQL: {result['version'] or 'version desconocida'}",
            "detail": out[:200],
        })

    # Si no hay scripts, al menos reportar que existe
    if not result["findings"]:
        log.info(f"[-] MySQL detectado en {target}:{port}")
        result["findings"].append({
            "severity": "info",
            "title": f"MySQL detectado ({result['product']} {result['version']})",
        })

    return result