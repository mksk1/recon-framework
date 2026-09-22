import argparse, json, os, time
import signal, subprocess, sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.nmap_scanner import NmapScanner
from core.service_enum import dispatch_enum
from core.exploit_search import search_exploits
from core.report import build_report
from utils.logger import log


# Servicios UDP conocidos (nmap no los detecta bien con -sV)
UDP_SERVICE_NAMES = {
    53:   "domain",
    67:   "dhcp",
    69:   "tftp",
    111:  "rpcbind",
    123:  "ntp",
    137:  "netbios-ns",
    138:  "netbios-dgm",
    161:  "snmp",
    162:  "snmptrap",
    500:  "isakmp",
    514:  "syslog",
    520:  "route",
    623:  "ipmi",
    1900: "upnp",
    4500: "ipsec-nat-t",
    5353: "mdns",
}


def _cleanup(sig, frame):
    """Mata todos los procesos hijos al recibir SIGINT/SIGTERM."""
    log.warning("Interrupción recibida, matando subprocess hijos...")
    try:
        subprocess.run(
            ["pkill", "-TERM", "-P", str(os.getpid())],
            timeout=5, check=False,
        )
    except Exception:
        pass
    sys.exit(130)


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


def _add_synthetic_udp_services(services, udp_ports):
    """Añade servicios UDP sintéticos para que el dispatcher los enrute."""
    existing_ports = {s["port"] for s in services}
    added = []
    for up in udp_ports:
        if up in existing_ports:
            continue
        if up in UDP_SERVICE_NAMES:
            services.append({
                "port": up,
                "proto": "udp",
                "name": UDP_SERVICE_NAMES[up],
                "product": "",
                "version": "",
                "extrainfo": "",
                "scripts": {},
            })
            added.append((up, UDP_SERVICE_NAMES[up]))
    return added


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("-o", "--output", default="results")
    ap.add_argument("--skip-full", action="store_true",
                    help="Saltar nmap -p- (usar top 1000)")
    ap.add_argument("--skip-udp", action="store_true",
                    help="Saltar escaneo UDP")
    ap.add_argument("--threads", type=int, default=10)
    args = ap.parse_args()

    outdir = Path(args.output) / f"{args.target}_{int(time.time())}"
    outdir.mkdir(parents=True, exist_ok=True)
    log.info(f"[*] Target: {args.target}  →  {outdir}")

    # 1. Descubrimiento de puertos TCP
    scanner = NmapScanner(args.target, outdir)
    ports = scanner.discover(full=not args.skip_full)
    log.success(f"[+] Puertos TCP abiertos: {ports}")

    # 1b. Descubrimiento de puertos UDP
    udp_ports = []
    if not args.skip_udp:
        log.info("[*] Escaneando puertos UDP comunes (requiere sudo)...")
        udp_ports = scanner.discover_udp()
        if udp_ports:
            log.success(f"[+] Puertos UDP abiertos: {udp_ports}")
        else:
            log.info("[-] Sin puertos UDP abiertos (o sin permisos para escanear)")

    # Combina TCP + UDP sin duplicados (para el escaneo -sVC)
    all_ports = sorted(set(ports) | set(udp_ports))
    if not all_ports:
        log.error("[-] No se han detectado puertos abiertos. Abortando.")
        return

    log.info(f"[*] Puertos totales: {all_ports}")

    # 2. Detección de servicios y versiones (solo TCP)
    services = scanner.detect_services(ports)

    # 2b. Añadir servicios UDP sintéticos
    if udp_ports:
        added = _add_synthetic_udp_services(services, udp_ports)
        for up, name in added:
            log.info(f"[+] Puerto UDP {up} → {name} (sintético)")

    (outdir / "services.json").write_text(json.dumps(services, indent=2))

    # 3. Enumeración específica por servicio (paralelo)
    enum_results = {}
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {
            ex.submit(dispatch_enum, svc, args.target, outdir, services): svc
            for svc in services
        }
        for fut in as_completed(futures):
            svc = futures[fut]
            try:
                enum_results[svc["port"]] = fut.result()
            except Exception as e:
                log.error(f"[-] Enum puerto {svc['port']}: {e}")

    # 4. Búsqueda de exploits
    exploits = search_exploits(services)
    (outdir / "exploits.json").write_text(json.dumps(exploits, indent=2))

    # 5. Reporte
    build_report(outdir, args.target, services, enum_results, exploits)
    log.success(f"[+] Listo → {outdir}/report.md")


if __name__ == "__main__":
    main()