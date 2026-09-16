import argparse, json, os, time
import signal, subprocess, sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.nmap_scanner import NmapScanner
from core.service_enum import dispatch_enum
from core.exploit_search import search_exploits
from core.report import build_report
from utils.logger import log


def _cleanup(sig, frame):
    """Mata todos los procesos hijos al recibir SIGINT/SIGTERM."""
    log.warning("[!] Interrupción recibida, matando subprocess hijos...")
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("-o", "--output", default="results")
    ap.add_argument("--skip-full", action="store_true",
                    help="Saltar nmap -p- (usar top 1000)")
    ap.add_argument("--threads", type=int, default=10)
    args = ap.parse_args()

    outdir = Path(args.output) / f"{args.target}_{int(time.time())}"
    outdir.mkdir(parents=True, exist_ok=True)
    log.info(f"[*] Target: {args.target}  →  {outdir}")

    # 1. Descubrimiento de puertos
    scanner = NmapScanner(args.target, outdir)
    ports = scanner.discover(full=not args.skip_full)
    log.success(f"[+] Puertos abiertos: {ports}")

    # 2. Detección de servicios y versiones
    services = scanner.detect_services(ports)
    (outdir / "services.json").write_text(json.dumps(services, indent=2))

    # 3. Enumeración específica por servicio (paralelo)
    enum_results = {}
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {
            ex.submit(dispatch_enum, svc, args.target, outdir): svc
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
