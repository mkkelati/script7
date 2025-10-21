# MK Script Manager v4.2 - Maximum Performance + Proxy Edition 🚀

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-20.04%20|%2022.04%20|%2024.04-orange.svg)](https://ubuntu.com/)
[![Stunnel](https://img.shields.io/badge/Stunnel-5.75-blue.svg)](https://www.stunnel.org/)
[![Let's Encrypt](https://img.shields.io/badge/Let's%20Encrypt-Supported-green.svg)](https://letsencrypt.org/)
[![Squid](https://img.shields.io/badge/Squid-Proxy-blue.svg)](http://www.squid-cache.org/)
[![Shadowsocks](https://img.shields.io/badge/Shadowsocks-libev-purple.svg)](https://shadowsocks.org/)

🚀 **The most advanced SSH management system with ISP bypass, proxy services, and professional-grade security.**

Advanced SSH user management system with comprehensive monitoring, SSL tunneling, Squid Proxy, Shadowsocks, and Let's Encrypt integration for Ubuntu 20.04–24.04.

## ✨ Features

### 🔐 User Management
- **Create Users** - Advanced user creation with validation and expiration dates
- **Delete Users** - Comprehensive user removal with session management
- **Change Password** - Secure password management with dual storage
- **User Limits** - Connection limit management with PAM integration

### 📊 Monitoring & Reports
- **Online Users** - Real-time user monitoring (SSH, Dropbear, OpenVPN)
- **Network Traffic** - Live network monitoring with nload integration
- **User Report** - Comprehensive user status with expiration tracking
- **User Limiter** - Advanced connection enforcement with automatic violation handling
- **Professional Interface** - Boxed displays with timestamps and status icons
- **Connection Statistics** - Live connection counting with auto-refresh

### 🛡️ Security & Connectivity
- **SSH-SSL Tunneling** - Secure stunnel configuration on port 443
- **Let's Encrypt Integration** - Trusted CA certificates for ISP bypass
- **TLS 1.3 Encryption** - Advanced cipher suites (AES-256-GCM, ChaCha20-Poly1305)
- **Enhanced Stealth Mode** - Multiple ciphers to avoid fingerprinting
- **Connection Limits** - Per-user simultaneous connection control
- **Session Management** - Active session detection and control
- **Auto-Certificate Renewal** - Automatic 90-day certificate updates
- **Squid Proxy** - HTTP/HTTPS proxy with SSL bumping and authentication
- **Shadowsocks** - Secure SOCKS5 proxy with obfuscation and TLS disguise

### 🌐 ISP Bypass Features
- **Trusted CA Certificates** - Let's Encrypt for maximum compatibility
- **Traffic Pattern Mimicking** - Appears as legitimate HTTPS traffic
- **Universal Server Support** - Works with any hosting provider
- **Advanced Obfuscation** - Session resumption and realistic behavior

## 🚀 Quick Install

### ⚡ One-Line Installation (Recommended)
```bash
sudo bash -c "$(wget -qO- https://raw.githubusercontent.com/mkkelati/script7/main/install.sh)"
```

### 📥 Alternative Installation
```bash
# Download the installer
wget https://raw.githubusercontent.com/mkkelati/script7/main/install.sh

# Make it executable
chmod +x install.sh

# Run the installer
sudo ./install.sh
```

### 🎯 What Gets Installed
- **Latest stunnel 5.75** compiled from source with TLS 1.3 encryption
- **Let's Encrypt certificate support** for ISP bypass (optional)
- **SSH-SSL tunnel** on port 443 with enhanced stealth mode
- **Menu system** at `/usr/local/bin/menu`
- **User management database** at `/etc/mk-script/users.txt`
- **Auto-renewal system** for certificates
- **Performance optimizations** (BBR, TCP tuning)
- **Squid Proxy** (optional - HTTP/HTTPS proxy with SSL/TLS)
- **Shadowsocks** (optional - Secure SOCKS5 with obfuscation)
- **Required directories** and permissions

### 🔐 Certificate Setup
During installation, you'll choose between:

**Option 1: Let's Encrypt (Recommended)**
- Provides trusted CA certificates for maximum ISP bypass
- Requires a domain name pointed to your server
- Auto-renews every 90 days
- Works with any server provider

**Option 2: Self-signed Certificate**
- Basic SSL encryption (may be detected by ISPs)
- No domain required
- Instant setup

### 🌐 Let's Encrypt Setup Process
```bash
# Before installation, ensure:
1. You own a domain name (e.g., from Namecheap, Porkbun)
2. Domain A record points to your server IP
3. Port 80 is accessible for validation

# During installation:
- Choose option 1 for Let's Encrypt
- Enter your domain (e.g., yourdomain.com)
- Enter your email for notifications
- Automatic certificate generation and setup
```

### 🔧 Operation
After installation, run:
```bash
menu
```

## 📱 Menu Options
```
1)  Create User          - Add SSH users with limits
2)  Delete User          - Remove users + cleanup
3)  Limit User           - Set connection limits
4)  Connection Mode      - Configure SSH-SSL tunnel
5)  Online Users         - Real-time monitoring
6)  Network Traffic      - Live network stats
7)  User Report          - User status overview
8)  Change Password      - Update user passwords
9)  User Limiter         - Advanced connection enforcement
10) Server Optimization  - System performance tuning
11) Uninstall           - Complete removal
12) BadVPN Manager      - UDP Gateway for VoIP/OpenVPN
13) Banner Creator      - SSH login banner designer
14) Squid Proxy         - HTTP/HTTPS proxy with SSL/TLS
15) Shadowsocks         - Secure SOCKS5 proxy with obfuscation
```

## 🔐 Key Features
- **TLS 1.3** with ChaCha20-Poly1305 encryption + **MAXIMUM PERFORMANCE** optimizations
- **Multi-protocol support**: SSH (22), SSL (443), Squid (3128/3129), Shadowsocks (8388)
- **Connection limiting** via PAM with **25 connections per user**
- **Real-time monitoring** with auto-refresh every 3 seconds
- **Advanced User Limiter** with automatic enforcement and violation logging  
- **BadVPN UDP Gateway** optimized for **4,000 users × 25 connections = 100,000 total**
- **Banner Creator** with 5 ASCII art styles and system info templates
- **Squid Proxy** with SSL bumping, authentication, and 256MB cache
- **Shadowsocks** with AEAD encryption and simple-obfs TLS plugin
- **TCP Performance Tuning**: BBR congestion control, 128MB network buffers
- **Professional UI** with boxed interfaces and status icons
- **Safe arithmetic operations** with error handling

## ⚡ BadVPN UDP Gateway Manager
The integrated BadVPN Manager provides UDP forwarding capabilities for improved connectivity:

### Features:
- **VoIP Quality Enhancement** - Reduces packet loss for voice calls
- **UDP Traffic Forwarding** - Essential for OpenVPN and other UDP applications
- **Port Management** - Easy port configuration with conflict detection
- **Performance Monitoring** - Real-time connection stats and resource usage
- **Auto-Installation** - Compiles latest BadVPN from source automatically
- **Screen Session Management** - Background process with log access
- **Autostart Integration** - Persistent across reboots

### Configuration:
- **Default Port**: 7300 (configurable)
- **Max Clients**: 4,000 (optimized for 2GB RAM)
- **Max Connections per Client**: 25 (maximum user capacity)
- **Socket Buffer**: 15,000 bytes (enhanced performance)
- **Total Capacity**: 100,000 concurrent connections

## 🎨 Banner Creator
The integrated Banner Creator allows you to design professional SSH login banners:

### Features:
- **5 ASCII Art Styles**: Basic Lines, Stars, Double Lines, Diamonds, Fire Emojis
- **System Info Banner**: Dynamic server information display
- **Custom Text Banners**: Personalized welcome messages
- **Manual Editor**: Direct banner editing with nano
- **Live Preview**: See banners before applying
- **SSH Integration**: Automatic application to SSH login

### Banner Styles:
- **Basic Lines**: Simple professional borders
- **Stars**: Eye-catching star decorations
- **Double Lines**: Elegant Unicode box drawing
- **Diamonds**: Stylish diamond patterns
- **Fire Emojis**: Modern emoji-based designs

### System Integration:
- **MOTD Support**: Message of the Day integration
- **SSH Banner**: Pre-login banner display
- **Issue.net**: Network login banner
- **Auto-restart**: SSH service restart for immediate effect

## 🌐 Squid Proxy Manager
The integrated Squid Proxy provides HTTP/HTTPS proxy capabilities with SSL/TLS support:

### Features:
- **SSL/TLS Encryption**: Secure HTTPS proxy with SSL bumping
- **Authentication Support**: Optional username/password protection
- **High Performance**: Optimized caching with 256MB memory cache
- **Privacy Features**: Header stripping for anonymity
- **SSL Certificate**: Reuses stunnel certificate or creates new one
- **Access Control**: Comprehensive ACL management
- **Real-time Monitoring**: Connection tracking and statistics

### Configuration:
- **Default HTTP Port**: 3128 (configurable)
- **Default HTTPS Port**: 3129 (configurable)
- **Cache Size**: 2GB disk cache
- **Memory Cache**: 256MB
- **Authentication**: Optional (htpasswd-based)
- **SSL Bumping**: Full HTTPS inspection capability

### Management Options:
- **Install Squid**: One-click installation with guided setup
- **View Status**: Real-time connection stats and cache info
- **Start/Stop**: Service control
- **Uninstall**: Complete removal

### Client Configuration:
```
Proxy Type: HTTP/HTTPS
Server: your-server-ip
HTTP Port: 3128
HTTPS Port: 3129
Authentication: Optional (username/password if enabled)
```

## 🔐 Shadowsocks Manager
The integrated Shadowsocks provides secure SOCKS5 proxy with advanced obfuscation:

### Features:
- **Modern Encryption**: AEAD ciphers (AES-256-GCM, ChaCha20-Poly1305)
- **Obfuscation Plugin**: Simple-obfs for traffic disguising
- **TLS Mode**: Makes traffic appear as HTTPS
- **TCP & UDP Support**: Full protocol support
- **Fast Open**: TCP Fast Open for lower latency
- **QR Code**: Easy mobile client configuration
- **Connection URL**: Standard ss:// format for easy sharing

### Encryption Methods:
- **aes-256-gcm**: Recommended - Fast & Secure
- **chacha20-ietf-poly1305**: Mobile Optimized
- **xchacha20-ietf-poly1305**: Maximum Security

### Obfuscation:
- **obfs=tls**: Disguises traffic as HTTPS
- **obfs=http**: Disguises traffic as HTTP
- **Fast Open**: Reduces connection latency

### Management Options:
- **Install Shadowsocks**: Guided installation with encryption selection
- **View Status**: Service status and active connections
- **Connection Info**: Display configuration and ss:// URL
- **Start/Stop**: Service control
- **Uninstall**: Complete removal with cleanup

### Client Configuration:
Configuration is automatically saved to `/root/shadowsocks-info.txt`:
```
Server: your-server-ip
Port: 8388 (or custom)
Password: your-password
Encryption: aes-256-gcm (or selected method)
Plugin: obfs-server (if enabled)
Mode: TLS obfuscation
```

### Mobile Clients:
- **Android**: Shadowsocks Android + Simple Obfuscation
- **iOS**: Shadowrocket, Quantumult
- **Windows**: Shadowsocks-Windows
- **Linux/Mac**: shadowsocks-libev

### Connection URL Format:
The system generates a standard `ss://` URL for easy client configuration:
```
ss://base64(method:password@server:port)
```

## 🛡️ Advanced User Limiter
The integrated User Limiter provides comprehensive connection monitoring and enforcement:

### Features:
- **Multi-protocol Monitoring**: SSH and OpenVPN connection tracking
- **Automatic Enforcement**: Kills excess connections when limits are exceeded
- **Background Operation**: Runs as screen session with configurable intervals
- **Violation Logging**: Detailed logs with timestamps for all violations
- **Database Management**: Separate database for limiter-specific user limits
- **Real-time Status**: Live connection monitoring with violation detection
- **Autostart Support**: Automatic startup on system boot

### User Limiter Database:
```
/root/usuarios.db        # Format: username limit
user1 2                  # Allows 2 simultaneous connections
user2 1                  # Allows 1 connection only
admin 5                  # Allows 5 connections
```

### Management Interface:
- **Start/Stop Service**: Toggle limiter with loading animations
- **Status Monitoring**: Real-time connection tracking display
- **Log Viewing**: Connect to live logs via screen session
- **Database Setup**: Interactive database management tools

## 📊 File Structure
```
/etc/mk-script/users.txt                # User database
/etc/mk-script/senha/                   # Password storage
/etc/VPSManager/Exp                     # Expiration dates
/etc/stunnel/stunnel.conf               # TLS configuration
/root/usuarios.db                       # User Limiter database
/etc/squid/squid.conf                   # Squid proxy configuration
/etc/squid/squid.pem                    # Squid SSL certificate
/etc/shadowsocks-libev/config.json      # Shadowsocks configuration
/root/shadowsocks-info.txt              # Shadowsocks connection details
/usr/local/bin/menu                     # Main script
```

## ⚙️ Technical Notes
- Uses **main branch** from `github.com/mkkelati/script7`
- **TLS cipher**: `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256`
- **SSL tunnel**: Port 443 → SSH port 22
- **Certificate**: Let's Encrypt or self-signed (4096-bit RSA)
- **Auto-renewal**: Certificates renew automatically via cron
- **User limits**: Stored in `/etc/security/limits.d/`
- **Database format**: `username:connection_limit`

## 🔧 System Requirements

- **OS**: Ubuntu 20.04 - 24.04 LTS
- **RAM**: Minimum 512MB
- **Storage**: 100MB free space
- **Network**: Internet connection for installation
- **Permissions**: Root access required

## 📱 Mobile Integration

**For HTTP Injector (SSH-SSL):**
- Protocol: **Stunnel**
- Server Port: **443**
- SSL/TLS: **Enabled**

**For HTTP Injector (Squid Proxy):**
- Proxy Type: **HTTP/HTTPS**
- Proxy Server: **Your Server IP**
- Proxy Port: **3128** (HTTP) or **3129** (HTTPS)
- Authentication: **Enable if configured**

**For Shadowsocks Apps:**
- Use the generated `ss://` URL or manual configuration
- Android: Shadowsocks Android
- iOS: Shadowrocket, Quantumult X
- Enable Simple Obfuscation plugin if configured

## 🎨 Professional Interface

### Real-Time Monitoring Display:
```
┌─────────────────────────────────────────────────────────────┐
│                    REAL-TIME CONNECTIONS                    │
├─────────────────────────────────────────────────────────────┤
│ USERNAME     │ SSH      │ DROPBEAR │ OPENVPN  │ TOTAL    │ STATUS │
├─────────────────────────────────────────────────────────────┤
│ user1        │ 2        │ 0        │ 1        │ 3        │ 🟢     │
│ user2        │ 0        │ 0        │ 0        │ 0        │ 🔴     │
├─────────────────────────────────────────────────────────────┤
│ Total Users Online: 1                                       │
└─────────────────────────────────────────────────────────────┘

🟢 Online  🔴 Offline  ⏰ Expired
```

## 🔧 Key Technical Concepts

### Proven Working Connection Detection:
```bash
# SSH Detection - Simple and reliable
get_ssh_connections() {
    local user="$1"
    if grep -q "^$user:" /etc/passwd 2>/dev/null; then
        ps -u "$user" 2>/dev/null | grep -c sshd || echo "0"
    else
        echo "0"
    fi
}
```

### Safe Arithmetic Operations:
```bash
safe_number() {
    local value="$1"
    if [[ "$value" =~ ^[0-9]+$ ]]; then
        echo "$value"
    else
        echo "0"
    fi
}
```

### Real-Time Monitoring Loop:
```bash
# Auto-refresh every 3 seconds
while true; do
    clear
    display_header_with_timestamp
    monitor_all_users
    sleep 3
done
```

## 🔄 Updates & Support

- **Repository**: [https://github.com/mkkelati/script7](https://github.com/mkkelati/script7)
- **Issues**: Report bugs and feature requests
- **Releases**: Check for updates and new features
- **Documentation**: This README and inline help

## 🆘 Getting Help
- 📧 **Issues**: [GitHub Issues](https://github.com/mkkelati/script7/issues)
- 📖 **Documentation**: This README and inline help
- 🔧 **Troubleshooting**: Built-in diagnostic tools

## 🔄 Uninstall
```bash
menu  # Select option 6
```

This removes all users, configurations, and services completely.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Stunnel Project** - For the excellent SSL tunneling software
- **Let's Encrypt** - For free, trusted SSL certificates
- **Ubuntu Community** - For the stable Linux foundation
- **Contributors** - Everyone who helps improve this project

---

## 🚀 Ready to Get Started?

```bash
# Install now with one command:
sudo bash -c "$(wget -qO- https://raw.githubusercontent.com/mkkelati/script7/main/install.sh)"

# Then access the management dashboard:
menu
```

**Experience the most advanced SSH management system with professional-grade security and ISP bypass capabilities!**

---

⭐ **Star this repository if you find it helpful!** ⭐

© 2025 MK Script Manager v4.2 - Maximum Performance + Proxy Edition 🚀