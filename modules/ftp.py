import subprocess, ftplib
from utils.logger import log

def enumerate(service, target, outdir):
    port = service["port"]
    result = {"anon_login": False, "banner": None}

    # Banner
    try:
        with ftplib.FTP() as ftp:
            ftp.connect(target, port, timeout=10)
            result["banner"] = ftp.getwelcome()
    except Exception:
        pass

    # Login anónimo
    try:
        with ftplib.FTP() as ftp:
            ftp.connect(target, port, timeout=10)
            ftp.login("anonymous", "anonymous")
            result["anon_login"] = True
            result["ls"] = ftp.nlst()
            log.success(f"[+] FTP anónimo en {target}:{port}")
    except Exception:
        pass

    return result
