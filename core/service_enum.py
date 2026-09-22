from modules import ftp, http, smb, smtp, ssh, dns, rpc, ldap, mysql, redis, mongo, snmp, generic

# Handlers por nombre de servicio
NAME_HANDLERS = {
    "ftp":        ftp.enumerate,
    "ftps":       ftp.enumerate,
    "http":       http.enumerate,
    "rpcbind":    rpc.enumerate,
    "snmp":       snmp.enumerate,
    "sunrpc":     rpc.enumerate,
    "redis":      redis.enumerate,
    "mongo":      mongo.enumerate,
    "mongodb":    mongo.enumerate,
    "mongod":     mongo.enumerate,
    "https":      http.enumerate,
    "http-alt":   http.enumerate,
    "http-proxy": http.enumerate,
    "ssl/http":   http.enumerate,
    "ipp":        http.enumerate,
    "smb":        smb.enumerate,
    "netbios-ssn": smb.enumerate,
    "microsoft-ds": smb.enumerate,
    "smtp":       smtp.enumerate,
    "smtps":      smtp.enumerate,
    "submission": smtp.enumerate,
    "ssh":        ssh.enumerate,
    "domain":     dns.enumerate,
    "dns":        dns.enumerate,
    "ldap":       ldap.enumerate,
    "ldaps":      ldap.enumerate,
    "ldapssl":    ldap.enumerate,
    "globalcatLDAP": ldap.enumerate,
    "mysql":        mysql.enumerate,
}

# Handlers por puerto (fallback si nmap no identifica el nombre)
PORT_HANDLERS = {
    21:    ftp.enumerate,
    22:    ssh.enumerate,
    25:    smtp.enumerate,
    53:    dns.enumerate,
    80:    http.enumerate,
    111:   rpc.enumerate,
    139:   smb.enumerate,
    161:   snmp.enumerate,
    162:   snmp.enumerate,
    389:   ldap.enumerate,  
    443:   http.enumerate,
    445:   smb.enumerate,
    465:   smtp.enumerate,
    587:   smtp.enumerate,
    631:   http.enumerate,
    636:   ldap.enumerate,
    2222:  ssh.enumerate,
    3268:  ldap.enumerate,
    3269:  ldap.enumerate,
    3306:  mysql.enumerate,
    6379:  redis.enumerate,
    8080:  http.enumerate,
    8443:  http.enumerate,
    27017: mongo.enumerate,
}


def dispatch_enum(service, target, outdir, all_services=None):
    name = service.get("name", "").lower()
    port = service.get("port")

    # 1) por nombre
    handler = NAME_HANDLERS.get(name)
    # 2) por puerto
    if handler is None:
        handler = PORT_HANDLERS.get(port)
    # 3) fallback
    if handler is None:
        handler = generic.enumerate

    # Handlers que necesitan contexto global (todos los servicios)
    if handler == dns.enumerate:
        return handler(service, target, outdir, all_services=all_services)

    return handler(service, target, outdir)
