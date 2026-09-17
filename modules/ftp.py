import ftplib
from utils.logger import log


def enumerate(service, target, outdir):
    port = service["port"]
    result = {
        "port": port,
        "service": service["name"],
        "product": service.get("product", ""),
        "version": service.get("version", ""),
        "nmap_scripts": service.get("scripts", {}),
        "anon_login": False,
        "banner": None,
        "ls": [],
        "findings": [],
    }

    # --- Banner ---
    try:
        with ftplib.FTP() as ftp:
            ftp.connect(target, port, timeout=10)
            ftp.set_pasv(True)
            result["banner"] = ftp.getwelcome()
    except Exception:
        pass

    # --- Login anónimo ---
    try:
        with ftplib.FTP() as ftp:
            ftp.connect(target, port, timeout=10)
            ftp.set_pasv(True)
            ftp.login("anonymous", "anonymous")
            result["anon_login"] = True
            try:
                result["ls"] = ftp.nlst()
            except Exception:
                result["ls"] = []
            log.success(f"[+] FTP anónimo en {target}:{port}")
    except Exception:
        pass

    # --- Findings clasificados ---
    if result.get("anon_login"):
        ls = result.get("ls") or []
        if ls:
            result["findings"].append({
                "severity": "critical",
                "title": "FTP login anónimo con contenido",
                "detail": f"{len(ls)} entradas accesibles: " +
                          ", ".join(str(x) for x in ls[:5]),
            })
        else:
            result["findings"].append({
                "severity": "warning",
                "title": "FTP login anónimo permitido (sin contenido)",
            })
    if result.get("banner"):
        result["findings"].append({
            "severity": "info",
            "title": f"FTP banner: {result['banner'][:80]}",
        })

    return result