# recon-framework

Framework de enumeración inicial para CTFs y laboratorios de pentesting.

## Flujo

1. Descubrimiento de puertos con `nmap -p-`
2. Detección de servicios y versiones con `nmap -sVC`
3. Enumeración específica por servicio (FTP anónimo, dirsearch en web, etc.)
4. Búsqueda automática de exploits con `searchsploit`
5. Reporte consolidado en Markdown

## Requisitos

- Python 3.10+
- `nmap`
- `searchsploit` (paquete `exploitdb`)
- `dirsearch`
- `whatweb` (opcional)

## Uso

```bash
python recon.py <target> [-o results] [--skip-full] [--threads N]
