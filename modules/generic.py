from utils.logger import log

def enumerate(service, target, outdir):
    """Handler por defecto: solo reporta lo que ya sabemos de nmap."""
    log.info(f"[*] Sin handler específico para '{service['name']}' "
             f"en puerto {service['port']} — usando genérico")
    return {
        "port": service["port"],
        "service": service["name"],
        "product": service.get("product"),
        "version": service.get("version"),
        "nmap_scripts": service.get("scripts", {}),
    }
