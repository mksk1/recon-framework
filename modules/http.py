import subprocess
from pathlib import Path
from utils.logger import log

def enumerate(service, target, outdir):
    port = service["port"]
    scheme = "https" if service["name"] == "https" or port in (443, 8443) else "http"
    url = f"{scheme}://{target}:{port}"
    result = {"url": url, "dirsearch": None, "whatweb": None}

    # WhatWeb (tecnologías)
    try:
        r = subprocess.run(["whatweb", "-a", "3", url],
                           capture_output=True, text=True, timeout=120)
        result["whatweb"] = r.stdout.strip()
    except Exception as e:
        log.warning(f"[!] whatweb falló en {url}: {e}")

    # Dirsearch
    out_json = outdir / f"dirsearch_{port}.json"
    try:
        subprocess.run([
            "dirsearch", "-u", url,
            "-e", "php,html,js,txt,bak,zip",
            "-w", "/usr/share/wordlists/dirb/common.txt",
            "--format=json",
            "-o", str(out_json),
            "-q"
        ], timeout=600, check=False)
        result["dirsearch"] = str(out_json)
    except Exception as e:
        log.warning(f"[!] dirsearch falló en {url}: {e}")

    return result
