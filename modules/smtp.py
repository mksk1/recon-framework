import smtplib
import socket
from utils.logger import log


DEFAULT_USERS = ["root", "admin", "postmaster", "webmaster", "info", "test", "user", "mail"]


def _decode(x):
    if isinstance(x, bytes):
        return x.decode("utf-8", errors="replace")
    return x


def _get_banner(target, port, timeout=10):
    """Conecta con socket crudo para leer el banner 220."""
    try:
        with socket.create_connection((target, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(1024)
            return _decode(data).strip()
    except Exception as e:
        log.warning(f"[!] SMTP banner falló en {target}:{port}: {e}")
        return None


def enumerate(service, target, outdir):
    port = service["port"]
    result = {
        "port": port,
        "service": service["name"],
        "product": service.get("product", ""),
        "version": service.get("version", ""),
        "nmap_scripts": service.get("scripts", {}),
        "banner": None,
        "ehlo_features": [],
        "starttls": False,
        "users_valid": [],
        "open_relay": None,
        "findings": [],
    }

    # --- Banner ---
    result["banner"] = _get_banner(target, port)

    # --- EHLO + features + STARTTLS ---
    try:
        with smtplib.SMTP(target, port, timeout=10) as s:
            code, msg = s.ehlo("recon.local")
            msg = _decode(msg)
            if code == 250:
                features = [line.strip() for line in msg.splitlines() if line.strip()]
                result["ehlo_features"] = features
                result["starttls"] = any("STARTTLS" in f.upper() for f in features)
            else:
                code, msg = s.helo("recon.local")
                result["ehlo_features"] = [_decode(msg)]
    except Exception as e:
        log.warning(f"[!] SMTP EHLO falló en {target}:{port}: {e}")
        return result

    # --- VRFY ---
    try:
        with smtplib.SMTP(target, port, timeout=10) as s:
            s.ehlo("recon.local")
            for user in DEFAULT_USERS:
                try:
                    code, msg = s.verify(user)
                    if code in (250, 251):
                        result["users_valid"].append(user)
                        log.success(f"[+] SMTP usuario válido: {user}@{target}")
                except Exception:
                    continue
    except Exception as e:
        log.warning(f"[!] SMTP VRFY falló en {target}:{port}: {e}")

    # --- Open relay ---
    try:
        with smtplib.SMTP(target, port, timeout=10) as s:
            s.ehlo("recon.local")
            code, _ = s.docmd("MAIL FROM:<test@recon.local>")
            if code == 250:
                code2, _ = s.docmd("RCPT TO:<test@example.com>")
                if code2 in (250, 251):
                    result["open_relay"] = True
                    log.warning(f"[!] SMTP OPEN RELAY en {target}:{port}")
                else:
                    result["open_relay"] = False
            else:
                result["open_relay"] = False
            s.docmd("RSET")
    except Exception as e:
        log.warning(f"[!] SMTP open relay check falló en {target}:{port}: {e}")

    # --- Findings clasificados ---
    if result.get("open_relay"):
        result["findings"].append({
            "severity": "critical",
            "title": "SMTP open relay",
            "detail": "Permite relay sin autenticación desde este host.",
        })
    if not result.get("starttls"):
        result["findings"].append({
            "severity": "warning",
            "title": "SMTP sin STARTTLS",
            "detail": "Las credenciales pueden viajar en claro.",
        })
    if result.get("users_valid"):
        result["findings"].append({
            "severity": "warning",
            "title": f"{len(result['users_valid'])} usuarios SMTP enumerados",
            "detail": "VRFY/EXPN expone: " +
                      ", ".join(result["users_valid"][:5]),
        })
    if result.get("banner"):
        result["findings"].append({
            "severity": "info",
            "title": f"SMTP banner: {result['banner'][:80]}",
        })

    return result