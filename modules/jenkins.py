import subprocess
import re
import json
from utils.logger import log


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return ANSI_RE.sub("", r.stdout).strip()
    except subprocess.TimeoutExpired:
        log.warning(f"[!] timeout: {' '.join(cmd)}")
    except FileNotFoundError:
        log.error(f"[!] comando no encontrado: {cmd[0]}")
    except Exception as e:
        log.warning(f"[!] fallo {' '.join(cmd)}: {e}")
    return None


def _curl(target, port, path, timeout=10):
    """Hace GET a http://target:port/path y devuelve el body."""
    url = f"http://{target}:{port}/{path.lstrip('/')}"
    return _run(["curl", "-s", "--max-time", str(timeout), url], timeout=timeout + 5)


def _curl_headers(target, port, timeout=10):
    """Hace HEAD a http://target:port/ y devuelve los headers."""
    url = f"http://{target}:{port}/"
    return _run(["curl", "-sI", "--max-time", str(timeout), url], timeout=timeout + 5)


def is_jenkins(target, port, timeout=10):
    """Detecta activamente si el target:port es Jenkins.

    Prueba varios endpoints característicos:
      1. /api/json         → {"_class":"hudson.model.Hudson",...}
      2. /whoAmI/api/json  → {"name":...,"authenticated":...}
      3. /login            → HTML con "Sign in [Jenkins]"
      4. /                 → header X-Jenkins
    """
    # 1. /api/json → _class con "hudson"
    out = _curl(target, port, "api/json", timeout)
    if out and "_class" in out and "hudson" in out.lower():
        return True

    # 2. /whoAmI/api/json → authenticated
    out = _curl(target, port, "whoAmI/api/json", timeout)
    if out and "authenticated" in out.lower():
        return True

    # 3. /login → "Sign in" + "Jenkins"
    out = _curl(target, port, "login", timeout)
    if out:
        low = out.lower()
        if "sign in" in low and "jenkins" in low:
            return True

    # 4. Headers de / → X-Jenkins
    headers = _curl_headers(target, port, timeout)
    if headers and "x-jenkins" in headers.lower():
        return True

    return False


def enumerate(service, target, outdir):
    port = service["port"]

    result = {
        "port": port,
        "service": "jenkins",
        "product": service.get("product", ""),
        "version": service.get("version", ""),
        "nmap_scripts": service.get("scripts", {}),
        "jenkins_version": None,
        "auth_required": None,
        "jobs": [],
        "script_console": False,
        "findings": [],
    }

    # --- 1. Versión desde header X-Jenkins ---
    headers = _curl_headers(target, port)
    if headers:
        m = re.search(r"X-Jenkins:\s*([\d.]+)", headers, re.I)
        if m:
            result["jenkins_version"] = m.group(1)
            log.success(f"[+] Jenkins versión: {result['jenkins_version']}")

    # --- 2. Check de autenticación ---
    body = _curl(target, port, "")
    if body:
        low = body.lower()
        is_login_page = (
            "authentication required" in low
            or "sign in" in low
            or "j_username" in low
            or "j_password" in low
            or ("login" in low and ("password" in low or "http-equiv" in low))
        )

        if is_login_page:
            result["auth_required"] = True
            log.info(f"[-] Jenkins requiere autenticación en {target}:{port}")
        else:
            result["auth_required"] = False
            log.warning(f"[!] Jenkins SIN autenticación en {target}:{port}")

    if result["auth_required"] is None:
        log.info(f"[-] Jenkins sin respuesta en {target}:{port}")
        result["findings"].append({
            "severity": "info",
            "title": "Jenkins detectado (sin respuesta HTTP)",
        })
        return result

    # --- 3. Listar jobs vía API (solo si no requiere auth) ---
    if not result["auth_required"]:
        api_out = _curl(target, port, "api/json")
        if api_out:
            try:
                data = json.loads(api_out)
                jobs = data.get("jobs", [])
                result["jobs"] = [
                    {
                        "name": j.get("name"),
                        "url": j.get("url"),
                        "color": j.get("color"),
                    }
                    for j in jobs
                ]
                if result["jobs"]:
                    log.success(f"[+] Jenkins {len(result['jobs'])} jobs accesibles")
            except Exception:
                pass

    # --- 4. Comprobar consola de script ---
    script_body = _curl(target, port, "script")
    if script_body and "Groovy" in script_body:
        result["script_console"] = True
        log.warning(f"[!] Jenkins script console EXPUESTA en {target}:{port}")

    # --- 5. Findings ---
    if result["jenkins_version"]:
        result["findings"].append({
            "severity": "info",
            "title": f"Jenkins {result['jenkins_version']}",
        })

    if result["auth_required"] is False:
        result["findings"].append({
            "severity": "critical",
            "title": "Jenkins sin autenticación",
            "detail": "El dashboard es accesible sin credenciales.",
        })

    if result["jobs"]:
        result["findings"].append({
            "severity": "warning",
            "title": f"{len(result['jobs'])} jobs Jenkins expuestos",
            "detail": ", ".join(j["name"] for j in result["jobs"][:5]),
        })

    if result["script_console"]:
        result["findings"].append({
            "severity": "critical",
            "title": "Jenkins script console accesible",
            "detail": "RCE potencial vía Groovy console.",
        })

    return result