#!/bin/bash

###############################################################################
# Paqet Client Automated Installation Script
# This script automates the setup of paqet client on Linux
###############################################################################

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VERSION="1.0.0-alpha.13"
INSTALL_DIR="/opt/paqet-client"
PAQET_SOCKS_PORT="1080"
PAQET_KEY="your-secret-key-here"
SERVER_ADDR="10.0.0.1:54321"  # Default server address, will be overridden by user input
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

# Setup Proxy
setup_proxy() {
    log_info "Some network environments may restrict direct access to external resources."
    log_info "If you are in a restricted network (like Iran or China), you might need an HTTP/HTTPS"
    log_info "proxy to download the Paqet binary and its dependencies successfully."
    
    read -p "HTTP/HTTPS Proxy (e.g., http://10.10.1.1:8080, leave empty if none): " input_proxy
    if [ -n "$input_proxy" ]; then
        export http_proxy="$input_proxy"
        export https_proxy="$input_proxy"
        export HTTP_PROXY="$input_proxy"
        export HTTPS_PROXY="$input_proxy"
        log_success "Proxy environment variables set"
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
            yum install -y libpcap-devel curl wget openssl
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
    
    # Server address
    read -p "Paqet server address (IP:PORT) [$SERVER_ADDR]: " input_server
    SERVER_ADDR="${input_server:-$SERVER_ADDR}"
    log_success "Server address set to: $SERVER_ADDR"
    
    # SOCKS5 port
    read -p "SOCKS5 proxy listen port [$PAQET_SOCKS_PORT]: " input_port
    PAQET_SOCKS_PORT="${input_port:-$PAQET_SOCKS_PORT}"
    log_success "SOCKS5 port set to: $PAQET_SOCKS_PORT"
    
    # KCP encryption key
    read -p "KCP encryption key (must match server): " input_key
    if [ -z "$input_key" ]; then
        log_error "Encryption key is required"
        exit 1
    fi
    PAQET_KEY="$input_key"
    log_success "Using key: $PAQET_KEY"

    # Confirm settings
    echo ""
    log_info "Configuration Summary:"
    echo "  Interface: $INTERFACE"
    echo "  Local IP: $LOCAL_IP"
    echo "  Gateway IP: $GATEWAY_IP"
    echo "  Gateway MAC: $GATEWAY_MAC"
    echo "  Server Address: $SERVER_ADDR"
    echo "  SOCKS5 Port: $PAQET_SOCKS_PORT"
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
    
    if ! curl -L -o paqet-latest.tar.gz "$BINARY_URL"; then
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
role: "client"

log:
  level: "info"

socks5:
  - listen: "127.0.0.1:$PAQET_SOCKS_PORT"

network:
  interface: "$INTERFACE"
  ipv4:
    addr: "$LOCAL_IP:0"
    router_mac: "$GATEWAY_MAC"
  tcp:
    local_flag: ["S"]
    remote_flag: ["SA"]

server:
  addr: "$SERVER_ADDR"

transport:
  protocol: "kcp"
  conn: 1
  kcp:
    mode: "manual"
    nodelay: 0
    interval: 30
    resend: 0
    nocongestion: 0
    acknodelay: false
    wdelay: true
    mtu: 1350
    rcvwnd: 512
    sndwnd: 512
    block: "aes"
    key: "$PAQET_KEY"
    smuxbuf: 4194304
    streambuf: 2097152
EOF
    
    chmod 600 "$CONFIG_FILE"
    log_success "Configuration file created: $CONFIG_FILE"
}

# Configure iptables rules
configure_iptables() {
    log_info "Configuring iptables rules..."
    
    # Extract Server IP from SERVER_ADDR
    SERVER_IP=$(echo $SERVER_ADDR | cut -d: -f1)
    
    log_info "Setting up iptables rules for communication with $SERVER_IP..."
    
    # Prevent connection tracking for traffic to/from server
    iptables -t raw -A PREROUTING -s $SERVER_IP -p tcp -j NOTRACK
    iptables -t raw -A OUTPUT -d $SERVER_IP -p tcp -j NOTRACK
    
    # Drop RST packets to server (crucial for client)
    iptables -t mangle -A OUTPUT -d $SERVER_IP -p tcp --tcp-flags RST RST -j DROP
    
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
    
    SERVICE_FILE="/etc/systemd/system/paqet-client.service"
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Paqet Tunnel Client
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
    log_info "Enabling and starting paqet-client service..."
    
    systemctl daemon-reload
    systemctl enable paqet-client
    systemctl start paqet-client
    
    # Give service time to start
    sleep 2
    
    # Check service status
    if systemctl is-active --quiet paqet-client; then
        log_success "Paqet client service is running"
    else
        log_error "Paqet client service failed to start"
        log_error "Check logs with: journalctl -u paqet-client -n 50"
        exit 1
    fi
}

# Display service logs
show_logs() {
    log_info "Recent service logs:"
    journalctl -u paqet-client -n 20 --no-pager
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
    echo "  Service Name: paqet-client"
    echo "  SOCKS5 Listen: 127.0.0.1:$PAQET_SOCKS_PORT"
    echo "  Server Address: $SERVER_ADDR"
    echo ""
    log_info "Useful Commands:"
    echo "  Check status:    systemctl status paqet-client"
    echo "  View logs:       journalctl -u paqet-client -f"
    echo "  Stop service:    systemctl stop paqet-client"
    echo "  Start service:   systemctl start paqet-client"
    echo "  Restart service: systemctl restart paqet-client"
    echo ""
    log_info "Test Proxy Connection:"
    echo "  curl -v https://httpbin.org/ip --proxy socks5h://127.0.0.1:$PAQET_SOCKS_PORT"
    echo ""
    log_warning "Note: The SOCKS5 proxy is only accessible from localhost (127.0.0.1)"
    echo ""
}

###############################################################################
# Main Execution
###############################################################################

main() {
    echo "=========================================="
    echo "Paqet Client Installation Script v$VERSION"
    echo "=========================================="
    echo ""
    
    check_root
    detect_platform
    setup_proxy
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
