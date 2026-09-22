import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from utils.logger import log


# Scripts NSE específicos por puerto TCP
NSE_SCRIPTS_BY_PORT = {
    53:   "dns-nsid",
    88:   "krb5-enum-users",
    111:  "rpcinfo",
    139:  "smb-os-discovery,smb-enum-shares,smb-enum-users,smb-security-mode",
    389:  "ldap-rootdse,ldap-search",
    445:  "smb-os-discovery,smb-enum-shares,smb-enum-users,smb-security-mode",
    636:  "ssl-cert",
    1433: "ms-sql-info,ms-sql-empty-password",
    2049: "nfs-showmount,nfs-ls",
    3306: "mysql-info,mysql-databases,mysql-users,mysql-variables,mysql-empty-password",
    3389: "rdp-enum-encryption,rdp-ntlm-info",
    5432: "pgsql-brute",
    5900: "vnc-info",
    6379: "redis-info,redis-brute",
    8080: "http-title,http-headers",
    27017: "mongodb-info,mongodb-databases",
}

# Puertos UDP comunes a escanear
UDP_PORTS = "53,67,69,111,123,137,138,161,162,500,514,520,623,1900,4500,5353"


class NmapScanner:
    def __init__(self, target, outdir: Path):
        self.target = target
        self.outdir = outdir

    def _run(self, args, xmlfile, sudo=False):
        cmd = ["nmap", *args, "-oX", str(xmlfile), self.target]
        if sudo:
            cmd = ["sudo"] + cmd
        log.info(f"[*] {' '.join(cmd)}")
        subprocess.run(cmd, check=True, capture_output=True)

    def discover(self, full=True):
        xml = self.outdir / "nmap_ports.xml"
        args = ["-p-", "-T4", "--min-rate", "1000", "-Pn"]
        if not full:
            args = ["--top-ports", "1000", "-T4", "-Pn"]
        self._run(args, xml)
        return self._parse_ports(xml)

    def discover_udp(self):
        """Escaneo UDP de puertos comunes (necesita sudo)."""
        xml = self.outdir / "nmap_udp.xml"
        try:
            self._run(
                ["-sU", "-p", UDP_PORTS, "-Pn", "-T4", "--max-retries", "1"],
                xml,
                sudo=True,
            )
            return self._parse_ports(xml)
        except subprocess.CalledProcessError as e:
            log.warning(f"[!] escaneo UDP falló (¿sudo?): {e}")
            return []
        except Exception as e:
            log.warning(f"[!] escaneo UDP falló: {e}")
            return []

    def detect_services(self, ports):
        xml = self.outdir / "nmap_services.xml"

        # Construye lista de scripts según los puertos detectados
        scripts = set()
        for p in ports:
            if p in NSE_SCRIPTS_BY_PORT:
                for s in NSE_SCRIPTS_BY_PORT[p].split(","):
                    scripts.add(s.strip())

        pstr = ",".join(str(p) for p in ports)
        args = ["-sVC", "-p", pstr, "-Pn"]
        if scripts:
            script_str = ",".join(sorted(scripts))
            log.info(f"[*] scripts NSE: {script_str}")
            args.extend(["--script", script_str])

        self._run(args, xml)
        return self._parse_services(xml)

    @staticmethod
    def _parse_ports(xmlfile):
        tree = ET.parse(xmlfile)
        ports = []
        for p in tree.findall(".//port"):
            state = p.find("state")
            if state is not None and state.get("state") == "open":
                ports.append(int(p.get("portid")))
        return ports

    @staticmethod
    def _parse_services(xmlfile):
        tree = ET.parse(xmlfile)
        services = []
        for p in tree.findall(".//port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue

            svc = p.find("service")
            if svc is None:
                continue

            name = svc.get("name", "unknown")
            product = svc.get("product", "")
            version = svc.get("version", "")

            # Descarta listeners internos no identificados (containerd, etc.)
            if name in ("unknown", "tcpwrapped") and not product and not version:
                continue

            services.append({
                "port": int(p.get("portid")),
                "proto": p.get("protocol"),
                "name": name,
                "product": product,
                "version": version,
                "extrainfo": svc.get("extrainfo", ""),
                "scripts": {
                    s.get("id"): s.get("output", "")
                    for s in p.findall("script")
                },
            })
        return services