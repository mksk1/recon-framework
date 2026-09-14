from modules import ftp, ssh, smb, http, generic

HANDLERS = {
    "ftp":   ftp.enumerate,
    "ssh":   ssh.enumerate,
    "smb":   smb.enumerate,
    "http":  http.enumerate,
    "https": http.enumerate,
    "microsoft-ds": smb.enumerate,
    "netbios-ssn":  smb.enumerate,
}

def dispatch_enum(service, target, outdir):
    handler = HANDLERS.get(service["name"], generic.enumerate)
    return handler(service, target, outdir)
