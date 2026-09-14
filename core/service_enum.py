from modules import ftp, http, generic

HANDLERS = {
    "ftp":   ftp.enumerate,
    "http":  http.enumerate,
    "https": http.enumerate,
}

def dispatch_enum(service, target, outdir):
    handler = HANDLERS.get(service["name"], generic.enumerate)
    return handler(service, target, outdir)
