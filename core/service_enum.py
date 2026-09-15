from modules import ftp, http, generic

# Handlers por nombre de servicio (como antes)
NAME_HANDLERS = {
    "ftp":     ftp.enumerate,
    "ftps":    ftp.enumerate,
    "http":    http.enumerate,
    "https":   http.enumerate,
    "http-alt": http.enumerate,
    "http-proxy": http.enumerate,
    "ssl/http": http.enumerate,
    "ipp":     http.enumerate,   # CUPS habla HTTP
    # "smtp":  smtp.enumerate,   # cuando lo tengas
}

# Handlers por puerto (por si nmap no identifica el nombre)
PORT_HANDLERS = {
    21:   ftp.enumerate,
    80:   http.enumerate,
    443:  http.enumerate,
    631:  http.enumerate,  # CUPS
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
