#!/bin/bash
# MK Script Manager v4.0 - Installation Script
# Compatible with Ubuntu 20.04 - 24.04 LTS

if [[ "$EUID" -ne 0 ]]; then
  echo "Please run this installer as root (using sudo)."
  exit 1
fi

clear
echo "==========================================="
echo "    MK Script Manager v4.0 Installer"
echo "==========================================="
echo ""
echo "[*] Installing system dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null 2>&1

# Install basic dependencies including net-tools for netstat command
apt-get install -y openssl screen wget curl net-tools iproute2 systemd >/dev/null 2>&1

# Install latest stunnel with proper configuration for newer Ubuntu versions
echo "[*] Installing and configuring latest stunnel..."

# Install build dependencies first (includes BadVPN dependencies)
apt-get install -y build-essential libssl-dev zlib1g-dev wget tar cmake >/dev/null 2>&1

# Try to install latest stunnel from source
cd /tmp
echo "[*] Downloading stunnel 5.75 (latest)..."
if wget -q https://www.stunnel.org/downloads/stunnel-5.75.tar.gz; then
    echo "[*] Compiling latest stunnel..."
    tar -xzf stunnel-5.75.tar.gz
    cd stunnel-5.75
    ./configure --prefix=/usr/local --enable-ipv6 >/dev/null 2>&1
    make >/dev/null 2>&1
    make install >/dev/null 2>&1
    
    # Create symlinks for compatibility
    ln -sf /usr/local/bin/stunnel /usr/bin/stunnel4 2>/dev/null
    ln -sf /usr/local/bin/stunnel /usr/bin/stunnel 2>/dev/null
    
    # Create proper systemd service for compiled stunnel
    cat > /etc/systemd/system/stunnel4.service << 'EOF'
[Unit]
Description=Stunnel TLS tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStart=/usr/local/bin/stunnel /etc/stunnel/stunnel.conf
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/var/run/stunnel4/stunnel.pid
User=root
Group=root
RuntimeDirectory=stunnel4
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
EOF
    
    # Clean up
    cd /
    rm -rf /tmp/stunnel-5.75*
    
    echo "[*] Latest stunnel 5.75 installed successfully with systemd service"
else
    echo "[*] Fallback: Installing stunnel4 from Ubuntu repository..."
    apt-get install -y stunnel4 >/dev/null 2>&1
fi

# Fix stunnel4 configuration for Ubuntu 22.04/24.04
if [[ -f /etc/default/stunnel4 ]]; then
    sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4 2>/dev/null
    echo 'ENABLED=1' >> /etc/default/stunnel4 2>/dev/null
else
    echo 'ENABLED=1' > /etc/default/stunnel4
fi

# Clean up old systemd overrides and reload daemon
rm -rf /etc/systemd/system/stunnel4.service.d 2>/dev/null
systemctl daemon-reload >/dev/null 2>&1

echo "[*] Configuring stunnel service..."
if [[ -f /etc/default/stunnel4 ]]; then
  if grep -qs "ENABLED=0" /etc/default/stunnel4; then
    sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4
  fi
else
  echo 'ENABLED=1' > /etc/default/stunnel4
fi

mkdir -p /etc/stunnel
STUNNEL_CERT="/etc/stunnel/stunnel.pem"

# Certificate setup with Let's Encrypt option
echo ""
echo "==========================================="
echo "    SSL Certificate Configuration"
echo "==========================================="
echo ""
echo "Choose certificate type:"
echo "1) Let's Encrypt (Recommended - Trusted CA certificate)"
echo "2) Self-signed (Basic - May be detected by ISPs)"
echo ""
read -p "Enter your choice [1-2]: " cert_choice

case $cert_choice in
    1)
        echo ""
        echo "[*] Setting up Let's Encrypt certificate..."
        echo ""
        echo "IMPORTANT: Before proceeding, make sure:"
        echo "1. You own a domain name"
        echo "2. Domain DNS A record points to this server's IP: $(curl -s ifconfig.me 2>/dev/null || echo 'YOUR_SERVER_IP')"
        echo "3. Port 80 is accessible (for domain validation)"
        echo ""
        read -p "Have you pointed your domain to this server? (y/n): " domain_ready
        
        if [[ "$domain_ready" =~ ^[Yy]$ ]]; then
            read -p "Enter your domain (e.g., yourdomain.com): " DOMAIN
            read -p "Enter your email for Let's Encrypt notifications: " EMAIL
            
            if [[ -z "$DOMAIN" || -z "$EMAIL" ]]; then
                echo "[ERROR] Domain and email are required for Let's Encrypt"
                echo "[*] Falling back to self-signed certificate..."
                cert_choice=2
            else
                echo "[*] Installing certbot and nginx..."
                apt-get install -y certbot nginx >/dev/null 2>&1
                
                # Stop stunnel4 temporarily to free port 80
                systemctl stop stunnel4 2>/dev/null
                
                # Configure nginx for domain validation
                mkdir -p /var/www/html
                cat > /etc/nginx/sites-available/default << EOF
server {
    listen 80;
    server_name $DOMAIN;
    root /var/www/html;
    
    location /.well-known/acme-challenge/ {
        root /var/www/html;
        try_files \$uri =404;
    }
    
    location / {
        return 200 'Domain validation in progress...';
        add_header Content-Type text/plain;
    }
}
EOF
                
                # Create basic index page for validation
                cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Server Setup - Professional Services</title>
    <meta name="description" content="Professional server and IT infrastructure services">
</head>
<body>
    <h1>Professional Server Solutions</h1>
    <p>Enterprise-grade server infrastructure and consulting services.</p>
    <p>Secure, reliable, and optimized for business needs.</p>
</body>
</html>
EOF
                
                systemctl restart nginx
                
                echo "[*] Obtaining Let's Encrypt certificate for $DOMAIN..."
                if certbot certonly --webroot -w /var/www/html -d "$DOMAIN" --non-interactive --agree-tos --email "$EMAIL" >/dev/null 2>&1; then
                    echo "[*] Let's Encrypt certificate obtained successfully!"
                    
                    # Convert for stunnel format (private key + certificate chain)
                    cat /etc/letsencrypt/live/"$DOMAIN"/privkey.pem /etc/letsencrypt/live/"$DOMAIN"/fullchain.pem > "$STUNNEL_CERT"
                    
                    # Set proper permissions
                    chown stunnel4:stunnel4 "$STUNNEL_CERT" 2>/dev/null || chown root:stunnel4 "$STUNNEL_CERT"
                    chmod 640 "$STUNNEL_CERT"
                    
                    # Setup auto-renewal
                    echo "[*] Setting up automatic certificate renewal..."
                    cat > /etc/cron.d/letsencrypt-renewal << EOF
# Auto-renew Let's Encrypt certificates and update stunnel
0 3 * * * root certbot renew --quiet && cat /etc/letsencrypt/live/$DOMAIN/privkey.pem /etc/letsencrypt/live/$DOMAIN/fullchain.pem > /etc/stunnel/stunnel.pem && systemctl reload stunnel4
EOF
                    
                    # Stop nginx to free port 443 for stunnel
                    systemctl stop nginx
                    systemctl disable nginx
                    
                    echo "[*] Let's Encrypt certificate configured successfully!"
                    CERT_TYPE="Let's Encrypt"
                else
                    echo "[ERROR] Failed to obtain Let's Encrypt certificate"
                    echo "[*] Falling back to self-signed certificate..."
                    systemctl stop nginx
                    cert_choice=2
                fi
            fi
        else
            echo "[*] Please point your domain to this server first, then run the installer again."
            echo "[*] For now, using self-signed certificate..."
            cert_choice=2
        fi
        ;;
    2)
        echo "[*] Using self-signed certificate..."
        ;;
    *)
        echo "[*] Invalid choice. Using self-signed certificate..."
        cert_choice=2
        ;;
esac

# Generate self-signed certificate if Let's Encrypt failed or not chosen
if [[ "$cert_choice" == "2" ]] && [[ ! -f "$STUNNEL_CERT" ]]; then
  echo "[*] Generating self-signed SSL certificate for stunnel..."
  
  # Create certificate with stronger parameters
  openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes \
    -subj "/C=US/ST=State/L=City/O=MK-Script/OU=IT/CN=$(hostname)" \
    -keyout /etc/stunnel/key.pem -out /etc/stunnel/cert.pem >/dev/null 2>&1
  
  # Combine certificate and key
  cat /etc/stunnel/key.pem /etc/stunnel/cert.pem > "$STUNNEL_CERT"
  
  # Set proper ownership and permissions for stunnel4 user
  chown stunnel4:stunnel4 "$STUNNEL_CERT" 2>/dev/null || chown root:stunnel4 "$STUNNEL_CERT"
  chmod 640 "$STUNNEL_CERT"
  
  # Fix directory permissions
  chown -R stunnel4:stunnel4 /etc/stunnel 2>/dev/null || chown -R root:stunnel4 /etc/stunnel
  chmod 755 /etc/stunnel
  
  # Clean up individual files
  rm -f /etc/stunnel/key.pem /etc/stunnel/cert.pem
  
  CERT_TYPE="Self-signed"
fi

STUNNEL_CONF="/etc/stunnel/stunnel.conf"
if [[ ! -f "$STUNNEL_CONF" ]]; then
  echo "[*] Setting up enhanced stunnel configuration..."
  cat > "$STUNNEL_CONF" << 'EOC'
# Enhanced stunnel configuration for ISP bypass
cert = /etc/stunnel/stunnel.pem
pid = /var/run/stunnel4/stunnel.pid

# Reduced logging for stealth (change to 7 for debugging)
debug = 4
output = /var/log/stunnel4/stunnel.log

# Connection limits and timeouts
TIMEOUTbusy = 300
TIMEOUTclose = 60
TIMEOUTconnect = 30
TIMEOUTidle = 43200

[ssh-tunnel]
accept = 443
connect = 127.0.0.1:22

# Enhanced cipher suite for better compatibility and stealth
# Includes multiple strong ciphers to mimic real HTTPS traffic
ciphersuites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256

# TLS 1.3 with fallback for better compatibility
sslVersion = TLSv1.2
sslVersionMax = TLSv1.3

# Security options
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1_1

# Session resumption for realistic HTTPS behavior
sessionCacheSize = 1000
sessionCacheTimeout = 300

# Mimic real web server behavior
renegotiation = yes

# Connection optimization
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
EOC
fi

echo "[*] Starting stunnel service..."
systemctl restart stunnel4
systemctl enable stunnel4

echo "[*] Applying maximum performance TCP optimizations..."
# Remove existing entries to prevent duplicates
sed -i '/net.core.rmem_max/d' /etc/sysctl.conf 2>/dev/null
sed -i '/net.core.wmem_max/d' /etc/sysctl.conf 2>/dev/null
sed -i '/net.ipv4.tcp_rmem/d' /etc/sysctl.conf 2>/dev/null
sed -i '/net.ipv4.tcp_wmem/d' /etc/sysctl.conf 2>/dev/null
sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf 2>/dev/null
sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf 2>/dev/null

# Add maximum performance network settings
echo '# MK Script Manager - Maximum Performance Network Settings' >> /etc/sysctl.conf
echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf        # 128MB receive buffer
echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf        # 128MB send buffer
echo 'net.ipv4.tcp_rmem = 4096 87380 134217728' >> /etc/sysctl.conf  # TCP receive window
echo 'net.ipv4.tcp_wmem = 4096 65536 134217728' >> /etc/sysctl.conf  # TCP send window
echo 'net.ipv4.tcp_congestion_control = bbr' >> /etc/sysctl.conf     # Best congestion control
echo 'net.core.netdev_max_backlog = 5000' >> /etc/sysctl.conf       # Handle more packets
echo 'net.ipv4.tcp_window_scaling = 1' >> /etc/sysctl.conf          # Enable window scaling
echo 'net.ipv4.tcp_timestamps = 1' >> /etc/sysctl.conf              # Enable timestamps
echo 'net.ipv4.tcp_sack = 1' >> /etc/sysctl.conf                    # Enable selective ACK
echo 'net.ipv4.tcp_no_metrics_save = 1' >> /etc/sysctl.conf         # Don't cache metrics
echo 'net.ipv4.tcp_moderate_rcvbuf = 1' >> /etc/sysctl.conf         # Auto-tune receive buffer

# Apply settings immediately
sysctl -p >/dev/null 2>&1

echo "[*] Installing menu system..."
INSTALL_DIR="/usr/local/bin"

# Always download the latest version from GitHub for consistency
echo "[*] Downloading menu script..."
if wget -q https://raw.githubusercontent.com/mkkelati/script4/main/menu.sh -O "${INSTALL_DIR}/menu"; then
  chmod +x "${INSTALL_DIR}/menu"
  echo "[*] Menu system installed successfully"
else
  echo "[ERROR] Failed to download menu script. Check internet connection."
  exit 1
fi

echo "[*] Setting up configuration..."
mkdir -p /etc/mk-script
touch /etc/mk-script/users.txt

# Create password storage directory
mkdir -p /etc/mk-script/senha

echo "[*] Verifying installation..."
if [[ -x "${INSTALL_DIR}/menu" ]]; then
  clear
  sleep 1
  
  # Professional welcome message with colors
  echo ""
  echo ""
  echo -e "\033[1;34m╔══════════════════════════════════════════════════════════════════════════════╗\033[0m"
  echo -e "\033[1;34m║\033[1;32m                          🎉 INSTALLATION SUCCESSFUL! 🎉                        \033[1;34m║\033[0m"
  echo -e "\033[1;34m╠══════════════════════════════════════════════════════════════════════════════╣\033[0m"
  echo -e "\033[1;34m║\033[1;36m                                                                              \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;33m    ███╗   ███╗██╗  ██╗    ███████╗ ██████╗██████╗ ██╗██████╗ ████████╗    \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;33m    ████╗ ████║██║ ██╔╝    ██╔════╝██╔════╝██╔══██╗██║██╔══██╗╚══██╔══╝    \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;33m    ██╔████╔██║█████╔╝     ███████╗██║     ██████╔╝██║██████╔╝   ██║       \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;33m    ██║╚██╔╝██║██╔═██╗     ╚════██║██║     ██╔══██╗██║██╔═══╝    ██║       \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;33m    ██║ ╚═╝ ██║██║  ██╗    ███████║╚██████╗██║  ██║██║██║        ██║       \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;33m    ╚═╝     ╚═╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═╝        ╚═╝       \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;36m                                                                              \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;35m                        🚀 MANAGER v4.0 - READY TO USE! 🚀                   \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;36m                                                                              \033[1;34m║\033[0m"
  echo -e "\033[1;34m╠══════════════════════════════════════════════════════════════════════════════╣\033[0m"
  echo -e "\033[1;34m║\033[1;37m 🎯 WELCOME TO THE MOST ADVANCED SSH MANAGEMENT SYSTEM!                      \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;36m                                                                              \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;32m ✅ Latest stunnel 5.75 with ${CERT_TYPE:-Self-signed} certificate            \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;32m ✅ Professional dashboard with real-time system monitoring                  \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;32m ✅ Advanced user limiter with connection enforcement                         \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;32m ✅ Server optimization with automated performance tuning                    \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;32m ✅ 11 comprehensive management options for complete control                 \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;36m                                                                              \033[1;34m║\033[0m"
  echo -e "\033[1;34m╠══════════════════════════════════════════════════════════════════════════════╣\033[0m"
  echo -e "\033[1;34m║\033[1;33m 🚀 GET STARTED:                                                             \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;37m                                                                              \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;36m    Just type: \033[1;31mmenu\033[1;36m                                                         \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;37m                                                                              \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;32m    Then enjoy the professional dashboard and 11 powerful options!          \033[1;34m║\033[0m"
  if [[ "$CERT_TYPE" == "Let's Encrypt" ]]; then
  echo -e "\033[1;34m║\033[1;36m                                                                              \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;35m 🔒 CERTIFICATE: \033[1;32mTrusted CA certificate active - ISP bypass enabled!     \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;35m 🔄 AUTO-RENEWAL: \033[1;32mCertificate will auto-renew every 90 days             \033[1;34m║\033[0m"
  fi
  echo -e "\033[1;34m║\033[1;36m                                                                              \033[1;34m║\033[0m"
  echo -e "\033[1;34m╠══════════════════════════════════════════════════════════════════════════════╣\033[0m"
  echo -e "\033[1;34m║\033[1;35m 💡 SUPPORT: \033[1;37mhttps://github.com/mkkelati/script4                           \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;35m 📧 VERSION: \033[1;37mv4.1 - Maximum Performance Edition                            \033[1;34m║\033[0m"
  echo -e "\033[1;34m║\033[1;35m 🌟 STATUS:  \033[1;32mFully Optimized & Ready for Production                        \033[1;34m║\033[0m"
  echo -e "\033[1;34m╚══════════════════════════════════════════════════════════════════════════════╝\033[0m"
  echo ""
  echo -e "\033[1;33m⭐ Thank you for choosing MK Script Manager v4.1 - Maximum Performance! ⭐\033[0m"
  echo ""
else
  echo "[ERROR] Installation failed. Menu command not found."
  exit 1
fi
