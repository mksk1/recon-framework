import subprocess
import json
import re
from utils.logger import log


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Nombres de colecciones/campos que suelen contener secretos
SUSPICIOUS_KEYS = ["password", "passwd", "pwd", "secret", "token", "apikey",
                   "api_key", "auth", "credential", "private"]


def _run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return ANSI_RE.sub("", r.stdout).strip()
    except subprocess.TimeoutExpired:
        log.warning(f"[!] timeout: {' '.join(cmd)}")
    except FileNotFoundError:
        log.error(f"[!] mongosh no encontrado (apt install mongodb-mongosh)")
    except Exception as e:
        log.warning(f"[!] fallo {' '.join(cmd)}: {e}")
    return None


def _mongosh(target, port, js_code, timeout=15):
    """Ejecuta código JS en mongosh contra el target."""
    cmd = [
        "mongosh",
        f"mongodb://{target}:{port}/test",
        "--quiet",
        "--eval", js_code,
    ]
    return _run(cmd, timeout=timeout)


def _try_list_databases(target, port):
    """Intenta listDatabases sin auth. Devuelve (ok, dbs) o (None, [])."""
    out = _mongosh(
        target, port,
        "JSON.stringify(db.adminCommand('listDatabases'))"
    )
    if not out:
        return None, []

    if "requires authentication" in out.lower() or "not authorized" in out.lower():
        return False, []

    try:
        data = json.loads(out)
        dbs = [d["name"] for d in data.get("databases", [])]
        return True, dbs
    except Exception:
        return None, []


def _get_collections(target, port, db_name):
    out = _mongosh(
        target, port,
        f"JSON.stringify(db.getSiblingDB('{db_name}').getCollectionNames())"
    )
    if not out:
        return []
    try:
        return json.loads(out)
    except Exception:
        return []


def _sample_document(target, port, db_name, col_name):
    """Coge 1 documento de muestra para ver su estructura."""
    out = _mongosh(
        target, port,
        f"JSON.stringify(db.getSiblingDB('{db_name}').getCollection('{col_name}').findOne())"
    )
    if not out or out == "null":
        return None
    try:
        return json.loads(out)
    except Exception:
        return None


def _find_suspicious_fields(doc):
    """Busca campos con nombres sospechosos en un documento."""
    found = []
    if not isinstance(doc, dict):
        return found
    for key in doc.keys():
        k_lower = key.lower()
        if any(s in k_lower for s in SUSPICIOUS_KEYS):
            found.append(key)
    return found


def enumerate(service, target, outdir):
    port = service["port"]

    result = {
        "port": port,
        "service": service["name"],
        "product": service.get("product", ""),
        "version": service.get("version", ""),
        "nmap_scripts": service.get("scripts", {}),
        "auth_required": None,
        "databases": [],
        "collections": {},
        "sample_docs": {},
        "suspicious_fields": [],
        "config": {},
        "findings": [],
    }

    # --- 1. listDatabases sin auth ---
    ok, dbs = _try_list_databases(target, port)

    if ok is None:
        log.info(f"[-] MongoDB sin respuesta en {target}:{port}")
        return result

    if ok is False:
        result["auth_required"] = True
        log.info(f"[-] MongoDB requiere autenticación en {target}:{port}")
        result["findings"].append({
            "severity": "info",
            "title": "MongoDB requiere autenticación",
        })
        return result

    # Sin auth → CRÍTICO
    result["auth_required"] = False
    result["databases"] = dbs
    log.warning(f"[!] MongoDB SIN AUTENTICACIÓN en {target}:{port}")
    log.success(f"[+] MongoDB {len(dbs)} bases de datos accesibles")

    result["findings"].append({
        "severity": "critical",
        "title": "MongoDB sin autenticación",
        "detail": f"{len(dbs)} bases de datos accesibles sin credenciales",
    })

    # --- 2. Enumerar colecciones de cada base (excepto internas) ---
    for db_name in dbs:
        if db_name in ("admin", "local", "config"):
            continue
        cols = _get_collections(target, port, db_name)
        result["collections"][db_name] = cols

        if not cols:
            continue

        log.info(f"[+] MongoDB {db_name}: {len(cols)} colecciones")

        # --- 3. Muestrear documentos y buscar campos sospechosos ---
        for col_name in cols:
            doc = _sample_document(target, port, db_name, col_name)
            if not doc:
                continue

            result["sample_docs"][f"{db_name}.{col_name}"] = doc

            fields = _find_suspicious_fields(doc)
            if fields:
                result["suspicious_fields"].append({
                    "db": db_name,
                    "collection": col_name,
                    "fields": fields,
                })

    # --- 4. Findings adicionales ---
    total_cols = sum(len(c) for c in result["collections"].values())
    if total_cols:
        result["findings"].append({
            "severity": "warning",
            "title": f"{total_cols} colecciones accesibles en {len(result['collections'])} bases",
            "detail": ", ".join(
                f"{db}({len(cols)})"
                for db, cols in result["collections"].items()
            ),
        })

    if result["suspicious_fields"]:
        # Aplana los campos sospechosos
        all_fields = set()
        for item in result["suspicious_fields"]:
            all_fields.update(item["fields"])
        result["findings"].append({
            "severity": "warning",
            "title": f"Campos sospechosos en MongoDB: {', '.join(sorted(all_fields))}",
            "detail": f"En {len(result['suspicious_fields'])} colecciones",
        })

    # --- 5. Versión y config ---
    build_out = _mongosh(target, port, "JSON.stringify(db.adminCommand('buildInfo'))")
    if build_out:
        try:
            build = json.loads(build_out)
            if build.get("version"):
                result["version"] = build["version"]
            result["config"]["version"] = build.get("version")
            result["config"]["allocator"] = build.get("allocator")
            result["config"]["javascriptEngine"] = build.get("javascriptEngine")
        except Exception:
            pass

    return result
