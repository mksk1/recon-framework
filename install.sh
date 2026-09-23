#!/usr/bin/env bash
# install.sh — Instalador de recon-framework
# Uso: ./install.sh [--yes] [--skip-wordlists]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ASSUME_YES=0
SKIP_WORDLISTS=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[*]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[+]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_err()   { echo -e "${RED}[-]${NC} $*" >&2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes|-y)          ASSUME_YES=1 ;;
        --skip-wordlists)  SKIP_WORDLISTS=1 ;;
        -h|--help)
            cat <<EOF
Uso: $0 [opciones]

Opciones:
  -y, --yes              No preguntar, instalar todo
  --skip-wordlists       No descargar wordlists extra
  -h, --help             Mostrar esta ayuda
EOF
            exit 0
            ;;
        *)
            log_err "Opción desconocida: $1"
            exit 1
            ;;
    esac
    shift
done

if [[ "$EUID" -eq 0 ]]; then
    log_warn "Estás ejecutando como root. Se recomienda usuario normal con sudo."
fi

if ! command -v sudo >/dev/null && [[ "$EUID" -ne 0 ]]; then
    log_err "Se necesita sudo o ser root para instalar paquetes."
    exit 1
fi

if [[ ! -f /etc/os-release ]]; then
    log_err "No puedo detectar el SO."
    exit 1
fi

. /etc/os-release
if [[ "$ID" != "ubuntu" && "$ID" != "debian" && "$ID_LIKE" != *"debian"* ]]; then
    log_warn "SO no soportado oficialmente: $ID. Continuando bajo tu responsabilidad."
fi

log_ok "Detectado: $PRETTY_NAME"

# --- Actualizar repos ---
log_info "Actualizando repositorios..."
sudo apt update -qq

# --- Paquetes del sistema (TODOS los handlers actuales) ---
SYSTEM_PKGS=(
    # Core
    nmap
    git
    curl
    wget
    python3
    python3-pip
    python3-venv

    # DNS
    dnsutils

    # FTP
    ftp

    # HTTP
    whatweb
    dirsearch

    # SMB
    smbmap

    # LDAP
    ldap-utils

    # Redis
    redis-tools

    # MySQL
    default-mysql-client

    # SNMP
    snmp

    # Utilidades varias
    rsync
    nfs-common
    snmpd
)

log_info "Instalando paquetes del sistema..."
sudo apt install -y "${SYSTEM_PKGS[@]}"

# --- searchsploit (exploitdb) ---
if ! command -v searchsploit >/dev/null; then
    log_info "Instalando exploitdb (searchsploit)..."
    if apt-cache show exploitdb >/dev/null 2>&1; then
        sudo apt install -y exploitdb
    else
        log_warn "exploitdb no está en apt. Instalando desde GitLab..."
        if [[ ! -d /opt/exploitdb ]]; then
            sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
        fi
        sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
    fi
else
    log_ok "searchsploit ya instalado"
fi

# --- dirsearch ---
if ! command -v dirsearch >/dev/null; then
    log_info "Instalando dirsearch..."
    sudo apt install -y dirsearch || {
        log_warn "dirsearch no está en apt. Instalando con pipx..."
        if ! command -v pipx >/dev/null; then
            sudo apt install -y pipx
            pipx ensurepath
        fi
        pipx install dirsearch
    }
else
    log_ok "dirsearch ya instalado"
fi

# --- ssh-audit ---
if ! command -v ssh-audit >/dev/null; then
    log_info "Instalando ssh-audit..."
    pip3 install --user ssh-audit 2>/dev/null || \
        pipx install ssh-audit 2>/dev/null || \
        log_warn "No pude instalar ssh-audit. Prueba manualmente: pipx install ssh-audit"
else
    log_ok "ssh-audit ya instalado"
fi

# --- dnsrecon ---
if ! command -v dnsrecon >/dev/null; then
    log_info "Instalando dnsrecon..."
    if apt-cache show dnsrecon >/dev/null 2>&1; then
        sudo apt install -y dnsrecon
    else
        pip3 install --user dnsrecon 2>/dev/null || \
            pipx install dnsrecon 2>/dev/null || \
            log_warn "No pude instalar dnsrecon."
    fi
else
    log_ok "dnsrecon ya instalado"
fi

# --- mongosh (MongoDB Shell) ---
if ! command -v mongosh >/dev/null; then
    log_info "Instalando mongosh (MongoDB Shell)..."
    if apt-cache show mongodb-mongosh >/dev/null 2>&1; then
        sudo apt install -y mongodb-mongosh
    else
        # Añade repo oficial de MongoDB
        log_info "Añadiendo repo oficial de MongoDB..."
        curl -fsSL https://pgp.mongodb.com/server-8.0.asc | \
            sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor
        echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse" | \
            sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list > /dev/null
        sudo apt update -qq
        sudo apt install -y mongodb-mongosh
    fi
else
    log_ok "mongosh ya instalado"
fi

# --- Wordlists ---
if [[ "$SKIP_WORDLISTS" -eq 0 ]]; then
    WL_DIR="$HOME/wordlists"
    mkdir -p "$WL_DIR"

    if [[ ! -f "$WL_DIR/common.txt" ]]; then
        log_info "Descargando wordlist 'common.txt'..."
        curl -sSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
             -o "$WL_DIR/common.txt" || log_warn "Fallo al descargar common.txt"
    fi

    if [[ ! -f "$WL_DIR/subdomains-top1million-5000.txt" ]]; then
        log_info "Descargando wordlist de subdominios..."
        curl -sSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
             -o "$WL_DIR/subdomains-top1million-5000.txt" || log_warn "Fallo al descargar subdominios"
    fi

    log_ok "Wordlists en $WL_DIR"
fi

# --- Verificación final ---
log_info "Verificando instalación..."

declare -A TOOLS=(
    ["nmap"]="escaneo de puertos"
    ["searchsploit"]="búsqueda de exploits"
    ["dirsearch"]="fuzzing web"
    ["whatweb"]="fingerprinting web"
    ["smbmap"]="enumeración SMB"
    ["ldapsearch"]="enumeración LDAP"
    ["redis-cli"]="cliente Redis"
    ["mysql"]="cliente MySQL"
    ["mongosh"]="cliente MongoDB"
    ["snmpwalk"]="cliente SNMP"
    ["ssh-audit"]="auditoría SSH"
    ["dnsrecon"]="enumeración DNS"
    ["dig"]="consultas DNS"
    ["rsync"]="sincronización de ficheros"
)

MISSING=()
for cmd in "${!TOOLS[@]}"; do
    if command -v "$cmd" >/dev/null; then
        log_ok "$cmd → ${TOOLS[$cmd]}"
    else
        log_warn "Falta: $cmd (${TOOLS[$cmd]})"
        MISSING+=("$cmd")
    fi
done

echo
if [[ ${#MISSING[@]} -eq 0 ]]; then
    log_ok "Instalación completa. Todo listo."
else
    log_warn "Faltan herramientas: ${MISSING[*]}"
    log_warn "Instálalas manualmente o revisa la salida anterior."
fi

echo
log_info "Prueba con: python3 recon.py 127.0.0.1"