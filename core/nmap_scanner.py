import subprocess, xml.etree.ElementTree as ET
from pathlib import Path
from utils.logger import log


# Scripts NSE específicos por puerto/servicio
# Se añaden al nmap -sVC si el puerto está en la lista
PORT_SCRIPTS = {
    21:   "ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor",
    22:   "ssh-auth-methods,ssh-hostkey,ssh2-enum-algos",
    25:   "smtp-commands,smtp-enum-users,smtp-open-relay,smtp-vuln-cve2010-4344",
    53:   "dns-zone-transfer,dns-nsid,dns-service-discovery",
    80:   "http-title,http-headers,http-methods,http-robots.txt,http-enum",
    110:  "pop3-capabilities,pop3-ntlm-info",
    111:  "rpcinfo",
    139:  "smb-os-discovery,smb-enum-shares,smb-enum-users,smb-security-mode,smb2-security-mode",
    143:  "imap-capabilities,imap-ntlm-info",
    389:  "ldap-rootdse,ldap-search,ldap-novell-getpass",
    443:  "http-title,http-headers,http-methods,ssl-cert,ssl-enum-ciphers",
    445:  "smb-os-discovery,smb-enum-shares,smb-enum-users,smb-security-mode,smb2-security-mode,smb2-capabilities",
    631:  "http-title,http-headers,http-methods",
    1433: "ms-sql-info,ms-sql-config,ms-sql-empty-password,ms-sql-dac,ms-sql-tables",
    1521: "oracle-tns-version,oracle-sid-brute",
    3306: "mysql-info,mysql-databases,mysql-users,mysql-variables,mysql-empty-password",
    3389: "rdp-enum-encryption,rdp-ntlm-info,rdp-vuln-ms12-020",
    5432: "pgsql-brute",
    5900: "vnc-info,vnc-brute,realvnc-auth-bypass",
    5985: "http-title,http-headers",
    5986: "http-title,http-headers,ssl-cert",
    6379: "redis-info,redis-brute",
    8080: "http-title,http-headers,http-methods,http-enum",
    8443: "http-title,http-headers,ssl-cert,ssl-enum-ciphers",
    27017: "mongodb-info,mongodb-databases",
}


class NmapScanner:
    def __init__(self, target, outdir: Path):
        self.target = target
        self.outdir = outdir

    def _run(self, args, xmlfile):
        cmd = ["nmap", *args, "-oX", str(xmlfile), self.target]
        log.info(f"[*] {' '.join(cmd)}")
        subprocess.run(cmd, check=True, capture_output=True)

    def discover(self, full=True):
        xml = self.outdir / "nmap_ports.xml"
        args = ["-p-", "-T4", "--min-rate", "1000", "-Pn"]
        if not full:
            args = ["--top-ports", "1000", "-T4", "-Pn"]
        self._run(args, xml)
        return self._parse_ports(xml)

    def detect_services(self, ports):
        xml = self.outdir / "nmap_services.xml"
        pstr = ",".join(str(p) for p in ports)

        # Recoge scripts específicos para los puertos detectados
        scripts_to_run = []
        for p in ports:
            if p in PORT_SCRIPTS:
                scripts_to_run.append(PORT_SCRIPTS[p])

        args = ["-sVC", "-p", pstr, "-Pn"]
        if scripts_to_run:
            # Une todos los scripts con coma, sin duplicados
            unique_scripts = ",".join(sorted(set(
                s for group in scripts_to_run for s in group.split(",")
            )))
            args.extend(["--script", unique_scripts])
            log.info(f"[*] scripts NSE: {unique_scripts}")

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