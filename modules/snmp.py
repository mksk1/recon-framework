import subprocess
import re
from utils.logger import log


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Communities más comunes
COMMON_COMMUNITIES = [
    "public",
    "private",
    "manager",
    "admin",
    "cisco",
    "community",
    "snmp",
    "default",
    "monitor",
]


def _run(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return ANSI_RE.sub("", r.stdout).strip()
    except subprocess.TimeoutExpired:
        log.warning(f"[!] timeout: {' '.join(cmd)}")
    except FileNotFoundError:
        log.error(f"[!] comando no encontrado: {cmd[0]} (apt install snmp)")
    except Exception as e:
        log.warning(f"[!] fallo {' '.join(cmd)}: {e}")
    return None


def _snmpwalk(target, community, oid, timeout=30):
    """Ejecuta snmpwalk contra un OID."""
    cmd = ["snmpwalk", "-v2c", "-c", community, "-t", "5", target, oid]
    return _run(cmd, timeout=timeout)


def _snmpget(target, community, oid, timeout=10):
    """Ejecuta snmpget para un OID concreto."""
    cmd = ["snmpget", "-v2c", "-c", community, "-t", "5", "-Ovq", target, oid]
    return _run(cmd, timeout=timeout)


def _try_community(target, community):
    """Prueba si una community responde."""
    out = _snmpget(target, community, "1.3.6.1.2.1.1.1.0")
    if out and "No Such" not in out and "Timeout" not in out and out.strip():
        return out.strip()
    return None


def _parse_system(target, community):
    """Extrae info del sistema (sysDescr, sysName, sysContact, sysLocation, uptime)."""
    info = {}
    oids = {
        "sysDescr":    "1.3.6.1.2.1.1.1.0",
        "sysObjectID": "1.3.6.1.2.1.1.2.0",
        "sysUpTime":   "1.3.6.1.2.1.1.3.0",
        "sysContact":  "1.3.6.1.2.1.1.4.0",
        "sysName":     "1.3.6.1.2.1.1.5.0",
        "sysLocation": "1.3.6.1.2.1.1.6.0",
    }
    for key, oid in oids.items():
        val = _snmpget(target, community, oid)
        if val:
            info[key] = val
    return info


def _parse_interfaces(target, community):
    """Extrae interfaces de red (descripción y MAC)."""
    interfaces = []
    descrs = _snmpwalk(target, community, "1.3.6.1.2.1.2.2.1.2")
    macs = _snmpwalk(target, community, "1.3.6.1.2.1.2.2.1.6")
    if not descrs:
        return interfaces

    # Parseo de "iso.3.6.1.2.1.2.2.1.2.1 = STRING: lo"
    mac_map = {}
    if macs:
        for line in macs.splitlines():
            m = re.search(r'\.(\d+)\s*=\s*(?:Hex-STRING|STRING):\s*(.*)$', line)
            if m:
                idx = m.group(1)
                val = m.group(2).strip().strip('"')
                mac_map[idx] = val

    for line in descrs.splitlines():
        m = re.search(r'\.(\d+)\s*=\s*(?:STRING|Hex-STRING):\s*(.*)$', line)
        if not m:
            continue
        idx = m.group(1)
        name = m.group(2).strip().strip('"')
        interfaces.append({
            "index": int(idx),
            "name": name,
            "mac": mac_map.get(idx, ""),
        })
    return interfaces


def _parse_processes(target, community, limit=20):
    """Extrae procesos en ejecución."""
    out = _snmpwalk(target, community, "1.3.6.1.2.1.25.4.2.1.2", timeout=45)
    if not out:
        return []
    procs = []
    for line in out.splitlines():
        m = re.search(r'=\s*STRING:\s*"?(.*?)"?\s*$', line)
        if m and m.group(1):
            procs.append(m.group(1).strip().strip('"'))
    # Filtra procesos del kernel (kworker, kthreadd, rcu_...)
    user_procs = [p for p in procs if not p.startswith(("kworker", "kthreadd",
                                                         "rcu_", "ksoftirqd",
                                                         "migration/", "idle_inject",
                                                         "kprobe", "pool_workqueue",
                                                         "kswapd", "kcompactd"))]
    return user_procs[:limit]


def _parse_software(target, community, limit=20):
    """Extrae software instalado (hrSWInstalledName)."""
    out = _snmpwalk(target, community, "1.3.6.1.2.1.25.6.3.1.2", timeout=45)
    if not out:
        return []
    sw = []
    for line in out.splitlines():
        m = re.search(r'=\s*STRING:\s*"?(.*?)"?\s*$', line)
        if m and m.group(1):
            sw.append(m.group(1).strip().strip('"'))
    return sw[:limit]


def enumerate(service, target, outdir):
    port = service["port"]

    result = {
        "port": port,
        "service": service["name"],
        "product": service.get("product", ""),
        "version": service.get("version", ""),
        "nmap_scripts": service.get("scripts", {}),
        "community": None,
        "system": {},
        "interfaces": [],
        "processes": [],
        "software": [],
        "findings": [],
    }

    # --- 1. Buscar community válida ---
    for comm in COMMON_COMMUNITIES:
        sysdescr = _try_community(target, comm)
        if sysdescr:
            result["community"] = comm
            log.success(f"[+] SNMP community '{comm}' válida en {target}:{port}")
            break

    if not result["community"]:
        log.info(f"[-] SNMP sin community válida en {target}:{port}")
        result["findings"].append({
            "severity": "info",
            "title": "SNMP detectado (community no descubierta)",
        })
        return result

    comm = result["community"]

    # --- 2. System info ---
    result["system"] = _parse_system(target, comm)

    # --- 3. Interfaces ---
    result["interfaces"] = _parse_interfaces(target, comm)

    # --- 4. Procesos ---
    result["processes"] = _parse_processes(target, comm)

    # --- 5. Software instalado ---
    result["software"] = _parse_software(target, comm)

    # --- 6. Findings ---
    result["findings"].append({
        "severity": "critical" if comm == "public" else "warning",
        "title": f"SNMP community '{comm}' válida",
        "detail": f"Acceso de solo lectura al sistema {result['system'].get('sysName', 'desconocido')}",
    })

    if result["system"].get("sysDescr"):
        result["findings"].append({
            "severity": "info",
            "title": f"SNMP sysDescr: {result['system']['sysDescr'][:80]}",
        })

    if result["system"].get("sysContact"):
        result["findings"].append({
            "severity": "info",
            "title": f"SNMP sysContact: {result['system']['sysContact']}",
        })

    if result["processes"]:
        result["findings"].append({
            "severity": "warning",
            "title": f"{len(result['processes'])} procesos expuestos vía SNMP",
            "detail": ", ".join(result["processes"][:5]),
        })

    if result["software"]:
        result["findings"].append({
            "severity": "warning",
            "title": f"{len(result['software'])} paquetes de software expuestos",
            "detail": ", ".join(result["software"][:5]),
        })

    return result
