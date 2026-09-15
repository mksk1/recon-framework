import subprocess
import json
import re
from pathlib import Path
from utils.logger import log

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

WORDLISTS = [
    "/home/mksk/wordlists/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirsearch/db/dicc.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
]


def _find_wordlist():
    for w in WORDLISTS:
        if Path(w).exists():
            return w
    return None


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

    # --- Dirsearch ---
    wl = _find_wordlist()
    if wl is None:
        log.warning(f"[!] sin wordlist disponible, saltando dirsearch en {url}")
        return result

    out_json = outdir / f"dirsearch_{port}.json"
    try:
        subprocess.run(
            [
                "dirsearch", "-u", url,
                "-e", "php,html,js,txt,bak,zip",
                "-w", wl,
                "--format=json",
                "-o", str(out_json),
                "-q"
            ],
            stdout=subprocess.DEVNULL,
            timeout=600,
            check=False,
        )

        if out_json.exists():
            data = json.loads(out_json.read_text())
            items = data.get("results", [])

            by_status = {}
            for it in items:
                st = str(it.get("status", "?"))
                by_status[st] = by_status.get(st, 0) + 1

            result["dirsearch"] = {
                "total": len(items),
                "by_status": by_status,
                "top": [
                    {
                        "url": it.get("url"),
                        "status": it.get("status"),
                        "length": it.get("content-length"),
                    }
                    for it in items[:20]
                ],
            }
        else:
            result["dirsearch"] = {"total": 0, "by_status": {}, "top": []}
    except Exception as e:
        log.warning(f"[!] dirsearch falló en {url}: {e}")

    return result
