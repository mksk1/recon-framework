import re
from utils.logger import log


def enumerate(service, target, outdir):
    port = service["port"]

    result = {
        "port": port,
        "service": service["name"],
        "product": service.get("product", ""),
        "version": service.get("version", ""),
        "nmap_scripts": service.get("scripts", {}),
        "ntlm_info": None,
        "domain": None,
        "encryption": None,
        "findings": [],
    }

    scripts = service.get("scripts", {}) or {}

    # --- 1. rdp-ntlm-info (dominio/hostname) ---
    ntlm_info = scripts.get("rdp-ntlm-info", "")
    if ntlm_info:
        result["ntlm_info"] = ntlm_info.strip()
        log.info(f"[+] RDP NTLM info disponible en {target}:{port}")

        m = re.search(r"DNS_Domain_Name:\s*(\S+)", ntlm_info)
        if m:
            result["domain"] = m.group(1)
            log.info(f"    Dominio: {result['domain']}")

        m = re.search(r"DNS_Computer_Name:\s*(\S+)", ntlm_info)
        if m:
            result["computer_name"] = m.group(1)

    # --- 2. rdp-enum-encryption (niveles de seguridad) ---
    enc_info = scripts.get("rdp-enum-encryption", "")
    if enc_info:
        result["encryption"] = enc_info.strip()

        has_nla = "CredSSP (NLA): SUCCESS" in enc_info
        has_ssl = "SSL: SUCCESS" in enc_info

        if not has_nla:
            log.warning(f"[!] RDP sin NLA en {target}:{port}")
            result["findings"].append({
                "severity": "warning",
                "title": "RDP sin NLA (Network Level Authentication)",
                "detail": "Vulnerable a ataques de pre-autenticación.",
            })

        if not has_ssl:
            log.warning(f"[!] RDP sin SSL en {target}:{port}")
            result["findings"].append({
                "severity": "warning",
                "title": "RDP sin SSL/TLS",
                "detail": "El tráfico RDP viaja sin cifrado TLS.",
            })

    # --- 3. Finding informativo ---
    product = result.get("product") or "RDP"
    result["findings"].append({
        "severity": "info",
        "title": f"RDP detectado: {product}",
    })

    return result