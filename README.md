# recon-framework

Framework de enumeración inicial para CTFs y laboratorios de pentesting.

## Flujo

1. Descubrimiento de puertos con `nmap -p-` (TCP) + `nmap -sU` (UDP comunes)
2. Detección de servicios y versiones con `nmap -sVC` + scripts NSE específicos
3. Enumeración específica por servicio (FTP, HTTP, SMB, SMTP, SSH, DNS, rpcbind, LDAP, Redis, MySQL, MongoDB, SNMP, Kerberos, Rsync, NFS, RDP)
4. Búsqueda automática de exploits con `searchsploit`
5. Reporte consolidado en Markdown + export JSON

## Handlers implementados

| Servicio | Módulo | Qué enumera |
|----------|--------|-------------|
| **FTP** | `ftp.py` | Banner + login anónimo + listado |
| **HTTP/HTTPS** | `http.py` | whatweb + dirsearch + filtro de soft-404 |
| **SMB** | `smb.py` | smbmap + shares + sesión nula/guest |
| **SMTP** | `smtp.py` | Banner + EHLO + STARTTLS + VRFY + open relay |
| **SSH** | `ssh.py` | ssh-audit: banner, fingerprints, algoritmos débiles |
| **DNS** | `dns.py` | Reverse lookup + AXFR + subdominios (dnsrecon) ⚠️ |
| **rpcbind** | `rpc.py` | rpcinfo -p + detección de NFS/NIS |
| **LDAP** | `ldap.py` | Anonymous bind + Base DN + usuarios/grupos |
| **Redis** | `redis.py` | Auth + INFO + claves + escritura |
| **MySQL** | `mysql.py` | Acceso remoto + credenciales |
| **MongoDB** | `mongo.py` | listDatabases sin auth + colecciones + docs |
| **SNMP** | `snmp.py` | Community public + system + interfaces + procesos + software |
| **Kerberos** | `kerberos.py` | Realm discovery + password spray (kerbrute) |
| **Rsync** | `rsync.py` | Módulos + contenido + archivos sensibles |
| **NFS** | `nfs.py` | Exports + wildcard (*) |
| **RDP** | `rdp.py` | NTLM info + encryption + checks de NLA/SSL |

El dispatcher (`core/service_enum.py`) elige el handler por **nombre de servicio** y, si no, por **puerto conocido**. Si no hay handler específico, cae en `generic.py`.

## Requisitos

- Python 3.10+
- `nmap`, `searchsploit` (paquete `exploitdb`)
- `dirsearch`, `whatweb`
- `smbmap`, `ldap-utils`, `redis-tools`, `default-mysql-client`
- `snmp`, `nfs-common`, `rpcbind`, `rsync`
- `ssh-audit`, `dnsrecon`, `mongosh`
- `kerbrute` (Impacket) → instalado por `install.sh` en `~/scripts/kerbrute/`

Wordlists (se crean automáticamente con `install.sh`):

```
~/wordlists/common.txt
~/wordlists/subdomains-top1million-5000.txt
~/wordlists/userlist.txt
~/wordlists/passwords.txt
```

## Instalación

```bash
git clone https://github.com/mksk1/recon-framework.git
cd recon-framework
chmod +x install.sh
./install.sh --yes
```

El `install.sh`:
- Instala todos los paquetes del sistema vía apt
- Instala `searchsploit`, `dirsearch`, `ssh-audit`, `dnsrecon`, `mongosh`, `kerbrute`
- Descarga wordlists básicas
- Crea el alias `enumini` en `~/.bashrc`

**Flags disponibles:**

| Flag | Descripción |
|------|-------------|
| `-y, --yes` | No preguntar, instalar todo |
| `--skip-wordlists` | No descargar wordlists extra |
| `--no-alias` | No crear el alias `enumini` |
| `-h, --help` | Mostrar ayuda |

## Uso

```bash
enumini <target> [-o results] [--skip-full] [--skip-udp] [--threads N]
```

O sin alias:

```bash
python3 recon.py <target> [-o results] [--skip-full] [--skip-udp] [--threads N]
```

### Flags

| Flag | Descripción |
|------|-------------|
| `target` | IP o hostname a escanear (obligatorio) |
| `-o, --output` | Directorio base de salida (default: `results`) |
| `--skip-full` | Saltar `nmap -p-`, usar top 1000 |
| `--skip-udp` | Saltar escaneo UDP |
| `--threads N` | Hilos para enumeración paralela (default: 10) |

### Ejemplos

```bash
# Escaneo completo
enumini 10.10.10.5

# Escaneo rápido (sin UDP, top 1000)
enumini 10.10.10.5 --skip-full --skip-udp

# Directorio personalizado
enumini 192.168.1.95 -o /tmp/scans
```

## Estructura

```
recon-framework/
├── recon.py                  # Punto de entrada + CLI + Ctrl+C limpio
├── core/
│   ├── nmap_scanner.py       # Escaneo TCP + UDP, scripts NSE por puerto
│   ├── service_enum.py       # Dispatcher de handlers (nombre + puerto)
│   ├── exploit_search.py     # Búsqueda en searchsploit + filtros
│   └── report.py             # Reporte Markdown + resumen de hallazgos
├── modules/
│   ├── ftp.py                # Handler FTP
│   ├── http.py               # Handler HTTP/HTTPS
│   ├── smb.py                # Handler SMB
│   ├── smtp.py               # Handler SMTP
│   ├── ssh.py                # Handler SSH (ssh-audit)
│   ├── dns.py                # Handler DNS (AXFR + dnsrecon)
│   ├── rpc.py                # Handler rpcbind (rpcinfo)
│   ├── ldap.py               # Handler LDAP
│   ├── redis.py              # Handler Redis
│   ├── mysql.py              # Handler MySQL
│   ├── mongo.py              # Handler MongoDB
│   ├── snmp.py               # Handler SNMP
│   ├── kerberos.py           # Handler Kerberos (Impacket)
│   ├── rsync.py              # Handler Rsync
│   ├── nfs.py                # Handler NFS
│   ├── rdp.py                # Handler RDP
│   └── generic.py            # Fallback
├── utils/
│   ├── logger.py             # Logger centralizado
│   └── severity.py           # Clasificación de hallazgos (critical/warning/info)
├── install.sh                # Script de instalación
├── requirements.txt
└── results/                  # Salidas (gitignored)
    └── <target>_<timestamp>/
        ├── nmap_ports.xml
        ├── nmap_udp.xml
        ├── nmap_services.xml
        ├── services.json
        ├── exploits.json
        ├── dirsearch_<port>.json
        └── report.md
```

## Ejemplo de salida

```markdown
# Reporte de reconocimiento — 192.168.1.95

## Resumen de hallazgos

### 🔴 Críticos (5)

- **kerberos-sec :88** — 6 credenciales Kerberos válidas. administrator:P@ssw0rd, ...
- **snmp :161** — SNMP community 'public' válida. Acceso de solo lectura al sistema ubunturecon
- **nfs_acl :2049** — 1 exports NFS con acceso desde cualquier IP (*). /srv/nfs/public
- **redis :6379** — Redis con contraseña débil: 'foobared'
- **redis :6379** — Redis permite escritura. Vulnerable a escritura de archivos / RCE.

### 🟡 Warnings (9)

- **kerberos-sec :88** — 5 usuarios Kerberos enumerados
- **rpcbind :111** — Servicios RPC expuestos: mountd, nfs, nfs_acl, nlockmgr, status
- **snmp :161** — 20 procesos expuestos vía SNMP
- **nfs_acl :2049** — NFS con 1 export accesibles
- ...

### 🔵 Info (10)

- **kerberos-sec :88** — Kerberos realm: ENUM.LOCAL
- **ms-wbt-server :3389** — RDP detectado: xrdp
- ...

## Puertos y servicios

| Puerto | Servicio | Versión |
|--------|----------|---------|
| 22 | ssh | OpenSSH 9.6p1 |
| 88 | kerberos-sec | - |
| 111 | rpcbind | 2-4 |
| 445 | netbios-ssn | Samba smbd 4.6.2 |
| 631 | ipp | CUPS 2.4 |
| 873 | rsync | - |
| 2049 | nfs_acl | 3 |
| 3389 | ms-wbt-server | xrdp |
| 6379 | redis | Redis key-value store |
...

## Enumeración por servicio

### Puerto 88
```json
{
  "realm": "ENUM.LOCAL",
  "users": ["administrator", "jdoe", "asmith", "svc_backup", "testuser"],
  "credentials": ["administrator:P@ssw0rd", "jdoe:Passw0rd!2026", ...],
  "findings": [...]
}
```
...

## Exploits potenciales

### MySQL — 10 resultado(s)
- `...`
### xrdp — 1 resultado(s)
- `XRDP 0.4.1 - Remote Buffer Overflow (PoC)`
...
```

## Añadir un handler nuevo

1. Crea `modules/<servicio>.py` con `enumerate(service, target, outdir) -> dict`.
2. Regístralo en `core/service_enum.py`:

```python
from modules import ftp, http, ..., mío, generic

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

3. Cada handler debe devolver un `dict` con al menos:
   - `port`, `service`, `product`, `version`, `nmap_scripts`
   - `findings`: lista de `{"severity": "critical|warning|info", "title": "...", "detail": "..."}`

## Clasificación de hallazgos

Los hallazgos se clasifican en tres niveles (`utils/severity.py`):

| Nivel | Icono | Significado |
|-------|-------|-------------|
| `critical` | 🔴 | Requiere acción inmediata (credenciales, RCE) |
| `warning` | 🟡 | Revisar, potencial problema |
| `info` | 🔵 | Informativo, sin riesgo directo |

## Dependencias Python

- `requests` (para futuras integraciones CVE/NVD)
- `tqdm` (barra de progreso)

Se instalan con `install.sh` (paquetes `python3-requests`, `python3-tqdm`).

## Aviso

Framework pensado para **laboratorios, CTFs y entornos controlados** con autorización explícita. No lo uses contra sistemas sin permiso.