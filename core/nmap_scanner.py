import subprocess, xml.etree.ElementTree as ET
from pathlib import Path
from utils.logger import log

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
        self._run(["-sVC", "-p", pstr, "-Pn"], xml)
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
            services.append({
                "port": int(p.get("portid")),
                "proto": p.get("protocol"),
                "name": svc.get("name", "unknown"),
                "product": svc.get("product", ""),
                "version": svc.get("version", ""),
                "extrainfo": svc.get("extrainfo", ""),
                "scripts": {
                    s.get("id"): s.get("output", "")
                    for s in p.findall("script")
                },
            })
        return services