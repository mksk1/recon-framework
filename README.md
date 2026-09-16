# recon-framework

Framework de enumeración inicial para CTFs y laboratorios de pentesting.

## Flujo

1. Descubrimiento de puertos con `nmap -p-`
2. Detección de servicios y versiones con `nmap -sVC`
3. Enumeración específica por servicio (FTP anónimo, dirsearch en web, smbmap, smtp, ssh-audit, etc.)
4. Búsqueda automática de exploits con `searchsploit`
5. Reporte consolidado en Markdown + export JSON

## Requisitos

- Python 3.10+
- `nmap`
- `searchsploit` (paquete `exploitdb`)
- `dirsearch`
- `whatweb` (opcional)
- `smbmap` (opcional, para SMB)
- `ssh-audit` (opcional, para SSH)

Wordlists (al menos una):

```
/usr/share/wordlists/dirb/common.txt
/usr/share/dirsearch/db/dicc.txt
/usr/share/seclists/Discovery/Web-Content/common.txt
```

## Uso

```bash
python3 recon.py <target> [-o results] [--skip-full] [--threads N]
```

### Flags

| Flag | Descripción |
|------|-------------|
| `target` | IP o hostname a escanear (obligatorio) |
| `-o, --output` | Directorio base de salida (default: `results`) |
| `--skip-full` | Saltar `nmap -p-`, usar top 1000 |
| `--threads N` | Hilos para enumeración paralela (default: 10) |

### Ejemplos

```bash
# Escaneo completo
python3 recon.py 127.0.0.1

# Escaneo rápido
python3 recon.py 127.0.0.1 --skip-full

# Directorio personalizado
python3 recon.py 10.10.10.5 -o /tmp/scans
```

## Estructura

```
recon-framework/
├── recon.py                  # Punto de entrada + CLI
├── core/
│   ├── nmap_scanner.py       # Escaneo y parseo de nmap
│   ├── service_enum.py       # Dispatcher de handlers por nombre/puerto
│   ├── exploit_search.py     # Búsqueda en searchsploit
│   └── report.py             # Generación del reporte Markdown
├── modules/
│   ├── ftp.py                # FTP: banner + login anónimo
│   ├── http.py               # HTTP: whatweb + dirsearch
│   ├── smb.py                # SMB: smbmap + shares + anon/guest
│   ├── smtp.py               # SMTP: banner + EHLO + STARTTLS + VRFY + open relay
│   ├── ssh.py                # SSH: ssh-audit (banner, fingerprints, algoritmos débiles)
│   └── generic.py            # Fallback
├── utils/
│   └── logger.py             # Logger centralizado
└── results/                  # Salidas (gitignored)
    └── <target>_<timestamp>/
        ├── nmap_ports.xml
        ├── nmap_services.xml
        ├── services.json
        ├── exploits.json
        ├── dirsearch_<port>.json
        └── report.md
```

## Handlers implementados

| Servicio | Módulo | Qué enumera |
|----------|--------|-------------|
| FTP | `ftp.py` | Banner + login anónimo + listado |
| HTTP/HTTPS | `http.py` | whatweb + dirsearch + resumen de rutas |
| SMB | `smb.py` | smbmap, shares, sesión nula y guest |
| SMTP | `smtp.py` | Banner, EHLO, STARTTLS, VRFY, open relay |
| SSH | `ssh.py` | ssh-audit: banner, fingerprints SHA256, algoritmos débiles, recomendaciones |

El dispatcher (`core/service_enum.py`) elige el handler por **nombre de servicio** y, si no, por **puerto conocido**. Si no hay handler específico, cae en `generic.py`.

## Añadir un handler nuevo

1. Crea `modules/<servicio>.py` con `enumerate(service, target, outdir) -> dict`.
2. Regístralo en `core/service_enum.py`:

```python
from modules import ftp, http, smb, smtp, ssh, mío, generic

NAME_HANDLERS = {
    "ftp": ftp.enumerate,
    # ...
    "mío": mío.enumerate,
}

PORT_HANDLERS = {
    21: ftp.enumerate,
    # ...
    9999: mío.enumerate,
}
```

## Ejemplo de salida

```markdown
# Reporte de reconocimiento — 127.0.0.1

## Puertos y servicios

| Puerto | Servicio | Versión |
|--------|----------|---------|
| 22 | ssh | OpenSSH 9.6p1 Ubuntu 3ubuntu13.19 |
| 111 | rpcbind | 2-4 |
| 631 | ipp | CUPS 2.4 |

## Enumeración por servicio

### Puerto 22
{
  "banner": "SSH-2.0-OpenSSH_9.6p1...",
  "critical_findings": [...],
  "warnings": [...]
}

## Exploits potenciales

- **OpenSSH 9.6p1**: sin vulnerabilidades conocidas en ExploitDB.
```

## Aviso

Framework pensado para **laboratorios, CTFs y entornos controlados** con autorización explícita. No lo uses contra sistemas sin permiso.