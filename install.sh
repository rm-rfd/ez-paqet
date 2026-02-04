#!/bin/bash

###############################################################################
# Paqet Unified Installer (Server/Client)
# This script asks the user which role to install, then fetches and runs
# the corresponding installer script from GitHub.
###############################################################################

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# GitHub raw URLs (update these to your repo/branch)
CLIENT_SCRIPT_URL="https://raw.githubusercontent.com/rm-rfd/ez-paqet/main/install-client.sh"
SERVER_SCRIPT_URL="https://raw.githubusercontent.com/rm-rfd/ez-paqet/main/install-server.sh"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_dependencies() {
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        log_error "This script requires curl or wget. Please install one of them."
        exit 1
    fi
}

setup_proxy() {
    log_info "Some network environments may restrict direct access to external resources."
    log_info "If you are in a restricted network, you might need an HTTP/HTTPS"
    log_info "proxy to download the child installation scripts successfully."
    
    read -p "HTTP/HTTPS Proxy (e.g., http://10.10.1.1:8080, leave empty if none): " input_proxy
    if [ -n "$input_proxy" ]; then
        export http_proxy="$input_proxy"
        export https_proxy="$input_proxy"
        export HTTP_PROXY="$input_proxy"
        export HTTPS_PROXY="$input_proxy"
        log_success "Proxy environment variables set"
    fi
}

select_role() {
    echo "=========================================="
    echo "Paqet Unified Installer"
    echo "=========================================="
    echo ""
    echo "Please choose what to install:"
    echo "  1) Server"
    echo "  2) Client"
    echo ""

    while true; do
        read -p "Enter choice [1-2]: " choice
        case "$choice" in
            1)
                ROLE="server"
                SCRIPT_URL="$SERVER_SCRIPT_URL"
                break
                ;;
            2)
                ROLE="client"
                SCRIPT_URL="$CLIENT_SCRIPT_URL"
                break
                ;;
            *)
                log_warning "Invalid choice. Please enter 1 or 2."
                ;;
        esac
    done

    log_success "Selected: $ROLE"
}

download_and_run() {
    local tmp_dir
    tmp_dir=$(mktemp -d)
    # Ensure cleanup on exit
    trap 'rm -rf "$tmp_dir"' EXIT
    
    local script_path="$tmp_dir/paqet-install-$ROLE.sh"

    log_info "Downloading installer from: $SCRIPT_URL"

    if command -v curl >/dev/null 2>&1; then
        if ! curl -fsSL "$SCRIPT_URL" -o "$script_path"; then
            log_error "Failed to download installer script"
            exit 1
        fi
    elif command -v wget >/dev/null 2>&1; then
        if ! wget -q "$SCRIPT_URL" -O "$script_path"; then
            log_error "Failed to download installer script"
            exit 1
        fi
    else
        log_error "Neither curl nor wget is available"
        exit 1
    fi

    chmod +x "$script_path"
    log_info "Running installer..."
    "$script_path"
}

main() {
    check_root
    check_dependencies
    setup_proxy
    select_role
    download_and_run
}

main "$@"
