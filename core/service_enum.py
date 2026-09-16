from modules import ftp, http, smb, smtp, ssh, generic

# Handlers por nombre de servicio (como antes)
NAME_HANDLERS = {
    "ftp":     ftp.enumerate,
    "ssh":     ssh.enumerate,
    "ftps":    ftp.enumerate,
    "http":    http.enumerate,
    "https":   http.enumerate,
    "http-alt": http.enumerate,
    "http-proxy": http.enumerate,
    "ssl/http": http.enumerate,
    "ipp":     http.enumerate,   # CUPS habla HTTP
    "smtp":  smtp.enumerate,
    "smtps": smtp.enumerate,
    "smb":     smb.enumerate,
    "netbios-ssn": smb.enumerate,
    "microsoft-ds": smb.enumerate,
}

# Handlers por puerto (por si nmap no identifica el nombre)
PORT_HANDLERS = {
    21:   ftp.enumerate,
    22:   ssh.enumerate,
    25:   smtp.enumerate,
    80:   http.enumerate,
    139:  smb.enumerate,
    443:  http.enumerate,
    445:  smb.enumerate,
    465:  smtp.enumerate,
    587:  smtp.enumerate,
    631:  http.enumerate,  # CUPS
    2222: ssh.enumerate,
    8080: http.enumerate,
    8443: http.enumerate,
}


def dispatch_enum(service, target, outdir):
    name = service.get("name", "").lower()
    port = service.get("port")

    # 1) por nombre de servicio
    handler = NAME_HANDLERS.get(name)

    # 2) si no, por puerto
    if handler is None:
        handler = PORT_HANDLERS.get(port)

    # 3) fallback genérico
    if handler is None:
        handler = generic.enumerate

    return handler(service, target, outdir)
