import subprocess
import json
import re
from pathlib import Path
from utils.logger import log


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def enumerate(service, target, outdir):
    port = service["port"]
    name = service["name"].lower()
    scheme = "https" if name in ("https", "ssl/http", "ftps") or port in (443, 8443) else "http"
    url = f"{scheme}://{target}:{port}"

    result = {
        "port": port,
        "service": service["name"],
        "product": service.get("product", ""),
        "version": service.get("version", ""),
        "nmap_scripts": service.get("scripts", {}),
        "url": url,
        "whatweb": None,
        "dirsearch": None,
        "findings": [],
    }

    # --- WhatWeb ---
    try:
        r = subprocess.run(
            ["whatweb", "-a", "3", "--color=never", url],
            capture_output=True, text=True, timeout=120
        )
        result["whatweb"] = ANSI_RE.sub("", r.stdout).strip()
    except Exception as e:
        log.warning(f"[!] whatweb falló en {url}: {e}")

    # --- Dirsearch (wordlist por defecto de dirsearch) ---
    out_json = outdir / f"dirsearch_{port}.json"
    try:
        subprocess.run(
            [
                "dirsearch", "-u", url,
                "-e", "php,html,js,txt,bak,zip",
                "--format=json",
                "-o", str(out_json),
                "--include-status", "200,301,401,403",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=600,
            check=False,
        )

        if out_json.exists():
            data = json.loads(out_json.read_text())
            items = data.get("results", [])

            # Filtra los soft-404 (302 que redirigen a "/")
            filtered = []
            for it in items:
                status = it.get("status")
                redirect = it.get("redirect", "")

                # Ignora 302 que redirigen a la raíz (soft-404)
                if status == 302 and redirect in ("/", ""):
                    continue
                filtered.append(it)

            by_status = {}
            for it in filtered:
                st = str(it.get("status", "?"))
                by_status[st] = by_status.get(st, 0) + 1

            result["dirsearch"] = {
                "total": len(filtered),
                "by_status": by_status,
                "top": [
                    {
                        "url": it.get("url"),
                        "status": it.get("status"),
                        "length": it.get("content-length"),
                    }
                    for it in filtered[:20]
                ],
            }

            if filtered:
                log.success(f"[+] dirsearch {url}: {len(filtered)} rutas")
        else:
            log.warning(f"[!] dirsearch no generó JSON en {url}")
            result["dirsearch"] = {"total": 0, "by_status": {}, "top": []}
    except Exception as e:
        log.warning(f"[!] dirsearch falló en {url}: {e}")

    # --- Findings clasificados ---
    ds = result.get("dirsearch") or {}
    by_status = ds.get("by_status") or {}
    total = ds.get("total", 0)

    if total:
        protected = by_status.get("401", 0) + by_status.get("403", 0)
        if protected:
            result["findings"].append({
                "severity": "warning",
                "title": f"{protected} rutas protegidas (401/403)",
                "detail": "Posible panel de admin expuesto.",
            })
        result["findings"].append({
            "severity": "info",
            "title": f"{total} rutas encontradas por dirsearch",
        })

    # Detección de title "Error"
    title = ""
    for k, v in (result.get("nmap_scripts") or {}).items():
        if k == "http-title":
            title = v
            break
    if title.lower() == "error":
        result["findings"].append({
            "severity": "warning",
            "title": "HTTP título 'Error'",
            "detail": "Posible servicio de desarrollo o interno.",
        })

    return result