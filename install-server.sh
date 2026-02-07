#!/bin/bash

###############################################################################
# Paqet Server Automated Installation Script
# This script automates the setup of paqet server on Linux
###############################################################################

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VERSION="1.0.0-alpha.15"
INSTALL_DIR="/opt/paqet"
PAQET_PORT="54321"
PAQET_KEY="your-secret-key-here"
BINARY_URL=""  # Will be set based on OS/arch detection
BINARY_NAME=""  # Will be set based on OS/arch detection

###############################################################################
# Helper Functions
###############################################################################

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

# Detect OS and architecture
detect_platform() {
    log_info "Detecting platform..."
    
    # Detect OS
    OS_TYPE="$(uname -s)"
    if [ "${OS_TYPE}" != "Linux" ]; then
        log_error "Unsupported operating system: ${OS_TYPE}. This script only supports Linux."
        exit 1
    fi
    
    # Detect architecture
    ARCH="$(uname -m)"
    case "${ARCH}" in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        *)
            log_error "Unsupported architecture: ${ARCH}"
            exit 1
            ;;
    esac
    
    # Construct binary URL and name
    BINARY_URL="https://github.com/hanselime/paqet/releases/download/v${VERSION}/paqet-linux-${ARCH}-v${VERSION}.tar.gz"
    BINARY_NAME="paqet_linux_${ARCH}"
    
    log_success "Detected platform: linux-${ARCH}"
    log_info "Binary URL: ${BINARY_URL}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Install prerequisites
install_prerequisites() {
    log_info "Checking and installing prerequisites..."
    
    # Detect Linux distribution
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_DIST=$ID
    else
        log_error "Cannot detect Linux distribution"
        exit 1
    fi
    
    # Install libpcap-dev based on distribution
    case $OS_DIST in
        debian|ubuntu)
            log_info "Detected Debian/Ubuntu system"
            apt update
            DEBIAN_FRONTEND=noninteractive apt install -y libpcap-dev iptables-persistent curl wget openssl
            ;;
        rhel|centos|fedora)
            log_info "Detected RHEL/CentOS/Fedora system"
            yum install -y libpcap-devel iptables-services curl wget openssl
            ;;
        *)
            log_warning "Unknown distribution, attempting to install libpcap-dev"
            apt update && apt install -y libpcap-dev || yum install -y libpcap-devel
            ;;
    esac
    
    log_success "Prerequisites installed"
}

# Detect network interface and IP
detect_network_info() {
    log_info "Detecting network information..."
    
    # Get default interface
    INTERFACE=$(ip route show default | awk '{print $5}' | head -n1)
    if [ -z "$INTERFACE" ]; then
        log_error "Could not detect network interface"
        exit 1
    fi
    log_success "Network interface: $INTERFACE"
    
    # Get local IP address
    LOCAL_IP=$(ip -4 addr show $INTERFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
    if [ -z "$LOCAL_IP" ]; then
        log_error "Could not detect local IP address"
        exit 1
    fi
    log_success "Local IP address: $LOCAL_IP"
    
    # Get gateway IP
    GATEWAY_IP=$(ip route show default | awk '{print $3}')
    if [ -z "$GATEWAY_IP" ]; then
        log_error "Could not detect gateway IP"
        exit 1
    fi
    log_success "Gateway IP: $GATEWAY_IP"
    
    # Ping gateway to populate ARP cache
    log_info "Pinging gateway to populate ARP cache..."
    ping -c 4 $GATEWAY_IP > /dev/null 2>&1 || true
    
    # Get gateway MAC address
    GATEWAY_MAC=$(ip neigh show $GATEWAY_IP | awk '{print $5}' | head -n1)
    if [ -z "$GATEWAY_MAC" ]; then
        log_error "Could not detect gateway MAC address. Please ensure gateway is reachable"
        exit 1
    fi
    log_success "Gateway MAC address: $GATEWAY_MAC"
}

# Get user input for configuration
get_user_input() {
    log_info "Getting configuration details from user..."
    
    # Server IP (allow override of detected IP)
    read -p "Server IP address [$LOCAL_IP]: " input_ip
    SERVER_IP="${input_ip:-$LOCAL_IP}"
    log_success "Server IP set to: $SERVER_IP"
    
    # Server port
    read -p "Server port [$PAQET_PORT]: " input_port
    PAQET_PORT="${input_port:-$PAQET_PORT}"
    log_success "Server port set to: $PAQET_PORT"
    
    # KCP encryption key
    read -p "KCP encryption key [generate random]: " input_key
    if [ -z "$input_key" ]; then
        # Generate random key
        PAQET_KEY=$(openssl rand -hex 16)
        log_success "Generated random key: $PAQET_KEY"
    else
        PAQET_KEY="$input_key"
        log_success "Using provided key: $PAQET_KEY"
    fi
    
    # Confirm settings
    echo ""
    log_info "Configuration Summary:"
    echo "  Interface: $INTERFACE"
    echo "  Local IP: $SERVER_IP"
    echo "  Port: $PAQET_PORT"
    echo "  Gateway IP: $GATEWAY_IP"
    echo "  Gateway MAC: $GATEWAY_MAC"
    echo "  KCP Key: $PAQET_KEY"
    echo ""
    
    read -p "Continue with these settings? (y/n): " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        log_error "Installation cancelled"
        exit 1
    fi
}

# Create installation directory
setup_directories() {
    log_info "Setting up installation directories..."
    
    mkdir -p $INSTALL_DIR
    log_success "Created directory: $INSTALL_DIR"
}

# Download and extract paqet binary
download_paqet() {
    log_info "Downloading paqet binary..."
    
    cd /tmp
    log_info "Downloading from: $BINARY_URL"
    
    if ! wget -q "$BINARY_URL" -O paqet-latest.tar.gz; then
        log_error "Failed to download paqet binary"
        exit 1
    fi
    
    log_success "Download completed"
    
    log_info "Extracting binary..."
    tar -xzf paqet-latest.tar.gz
    
    if [ ! -f "${BINARY_NAME}" ]; then
        log_error "Could not find ${BINARY_NAME} in archive"
        exit 1
    fi
    
    log_info "Moving binary to installation directory..."
    mv "${BINARY_NAME}" $INSTALL_DIR/paqet
    chmod +x $INSTALL_DIR/paqet
    
    log_success "Binary installed at: $INSTALL_DIR/paqet"
    
    # Cleanup
    rm -f paqet-latest.tar.gz
}

# Create configuration file
create_config() {
    log_info "Creating configuration file..."
    
    CONFIG_FILE="$INSTALL_DIR/config.yaml"
    
    cat > "$CONFIG_FILE" << EOF
role: "server"

log:
  level: "info"

listen:
  addr: ":$PAQET_PORT"

network:
  interface: "$INTERFACE"
  ipv4:
    addr: "$SERVER_IP:$PAQET_PORT"
    router_mac: "$GATEWAY_MAC"
  tcp:
    local_flag: ["SA"]

transport:
  protocol: "kcp"
  conn: 2
  kcp:
    mode: "manual"
    nodelay: 1
    interval: 10
    resend: 2
    nocongestion: 1
    acknodelay: true
    wdelay: false
    mtu: 1350
    rcvwnd: 2048
    sndwnd: 2048
    block: "aes"
    key: "$PAQET_KEY"
    smuxbuf: 8388608
    streambuf: 4194304
EOF
    
    chmod 600 "$CONFIG_FILE"
    log_success "Configuration file created: $CONFIG_FILE"
}

# Configure iptables rules
configure_iptables() {
    log_info "Configuring iptables rules..."
    
    # Disable connection tracking for the port
    log_info "Setting up NOTRACK rules..."
    iptables -t raw -A PREROUTING -p tcp --dport $PAQET_PORT -j NOTRACK
    iptables -t raw -A OUTPUT -p tcp --sport $PAQET_PORT -j NOTRACK
    
    # Drop RST packets from kernel
    log_info "Setting up RST drop rules..."
    iptables -t mangle -A OUTPUT -p tcp --sport $PAQET_PORT --tcp-flags RST RST -j DROP
    
    # Make rules persistent
    log_info "Making iptables rules persistent..."
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
    
    log_success "iptables rules configured"
}

# Disable network offloading
disable_offloading() {
    log_info "Disabling network offloading features..."
    
    if command -v ethtool &> /dev/null; then
        ethtool -K $INTERFACE gro off gso off tso off 2>/dev/null || true
        log_success "Network offloading disabled"
    else
        log_warning "ethtool not found, skipping offloading configuration"
    fi
}

# Create systemd service file
create_systemd_service() {
    log_info "Creating systemd service file..."
    
    SERVICE_FILE="/etc/systemd/system/paqet.service"
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Paqet Tunnel Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/paqet run -c $INSTALL_DIR/config.yaml
Restart=always
RestartSec=3
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    chmod 644 "$SERVICE_FILE"
    log_success "Systemd service file created: $SERVICE_FILE"
}

# Enable and start service
enable_start_service() {
    log_info "Enabling and starting paqet service..."
    
    systemctl daemon-reload
    systemctl enable paqet
    systemctl start paqet
    
    # Give service time to start
    sleep 2
    
    # Check service status
    if systemctl is-active --quiet paqet; then
        log_success "Paqet service is running"
    else
        log_error "Paqet service failed to start"
        log_error "Check logs with: journalctl -u paqet -n 50"
        exit 1
    fi
}

# Display service logs
show_logs() {
    log_info "Recent service logs:"
    journalctl -u paqet -n 20 --no-pager
}

# Show final instructions
show_instructions() {
    echo ""
    echo "=========================================="
    log_success "Installation completed successfully!"
    echo "=========================================="
    echo ""
    log_info "Configuration Details:"
    echo "  Installation Directory: $INSTALL_DIR"
    echo "  Binary Path: $INSTALL_DIR/paqet"
    echo "  Config File: $INSTALL_DIR/config.yaml"
    echo "  Service Name: paqet"
    echo "  Server IP: $SERVER_IP"
    echo "  Listen Port: $PAQET_PORT"
    echo "  Server Address: $SERVER_IP:$PAQET_PORT"
    echo "  Encryption Key: $PAQET_KEY"
    echo ""
    log_info "Useful Commands:"
    echo "  Check status:    systemctl status paqet"
    echo "  View logs:       journalctl -u paqet -f"
    echo "  Stop service:    systemctl stop paqet"
    echo "  Start service:   systemctl start paqet"
    echo "  Restart service: systemctl restart paqet"
    echo ""
    log_info "Test Connection:"
    echo "  On client: paqet ping -c config.yaml"
    echo "  On server: paqet dump -p $PAQET_PORT"
    echo ""
    log_warning "IMPORTANT: Save the encryption key in a safe place!"
    echo "  Clients must use: key: \"$PAQET_KEY\""
    echo ""
}

###############################################################################
# Main Execution
###############################################################################

main() {
    echo "=========================================="
    echo "Paqet Server Installation Script v$VERSION"
    echo "=========================================="
    echo ""
    
    check_root
    detect_platform
    install_prerequisites
    detect_network_info
    get_user_input
    setup_directories
    download_paqet
    create_config
    configure_iptables
    disable_offloading
    create_systemd_service
    enable_start_service
    show_logs
    show_instructions
}

main "$@"
