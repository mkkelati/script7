# 🚀 Proxy Setup Guide - MK Script Manager v4.2

Complete guide for setting up and using Squid Proxy and Shadowsocks on your server.

---

## 📋 Table of Contents

1. [Quick Start](#quick-start)
2. [Squid Proxy Setup](#squid-proxy-setup)
3. [Shadowsocks Setup](#shadowsocks-setup)
4. [Client Configuration](#client-configuration)
5. [Troubleshooting](#troubleshooting)

---

## 🎯 Quick Start

### Installation

```bash
# Install MK Script Manager v4.2
sudo bash -c "$(wget -qO- https://raw.githubusercontent.com/mkkelati/script7/main/install.sh)"

# During installation, choose proxy option:
# 1 = Squid only
# 2 = Shadowsocks only  
# 3 = Both
# 4 = Skip (install later)
```

### Access Menu

```bash
menu
```

Then select:
- **Option 14** for Squid Proxy
- **Option 15** for Shadowsocks

---

## 🌐 Squid Proxy Setup

### Step-by-Step Installation

1. **Open Menu**
   ```bash
   menu
   ```

2. **Select Option 14** - Squid Proxy

3. **Choose Option 1** - Install Squid Proxy

4. **Configuration Prompts**
   ```
   Enter Squid proxy port (default: 3128): [Press Enter or type custom]
   Enter SSL/TLS proxy port (default: 3129): [Press Enter or type custom]
   Enable authentication? (y/n): [y for password protection, n for open]
   ```

5. **If Authentication Enabled**
   ```
   Enter proxy username: myuser
   Enter proxy password: [type password]
   ```

6. **Wait for Installation**
   - Downloads and installs Squid
   - Configures SSL/TLS support
   - Sets up cache directories
   - Starts the service

### What You Get

After successful installation:

```
✓ SQUID PROXY INSTALLED SUCCESSFULLY!

Configuration Details:
• HTTP Proxy Port: 3128
• HTTPS/SSL Port: 3129
• Authentication: Enabled/Disabled
• SSL/TLS: Enabled with certificate
• Status: Running

Client Configuration:
Proxy Server: your.server.ip
HTTP Port: 3128
HTTPS Port: 3129
```

### Testing Squid

**Test with curl:**
```bash
# Test HTTP proxy
curl -x http://your-server-ip:3128 http://example.com

# Test with authentication
curl -x http://username:password@your-server-ip:3128 http://example.com
```

**Test with browser:**
1. Open browser proxy settings
2. Set HTTP Proxy: `your-server-ip:3128`
3. Set HTTPS Proxy: `your-server-ip:3129`
4. If authentication enabled, enter username/password
5. Visit any website

### Squid Management

**View Status:**
- Menu → 14 → 2 (View Status & Stats)
- Shows: Active connections, cache size, recent logs

**Start/Stop Service:**
- Menu → 14 → 3 (Start/Stop Service)

**Uninstall:**
- Menu → 14 → 4 (Uninstall Squid)
- Removes all configurations and data

---

## 🔐 Shadowsocks Setup

### Step-by-Step Installation

1. **Open Menu**
   ```bash
   menu
   ```

2. **Select Option 15** - Shadowsocks

3. **Choose Option 1** - Install Shadowsocks

4. **Configuration Prompts**
   ```
   Enter Shadowsocks port (default: 8388): [Press Enter or type custom]
   Enter password: [type strong password or leave blank for auto-generated]
   ```

5. **Select Encryption Method**
   ```
   1) aes-256-gcm (Recommended - Fast & Secure)
   2) chacha20-ietf-poly1305 (Mobile Optimized)
   3) xchacha20-ietf-poly1305 (Maximum Security)
   
   Choice [1-3]: 1
   ```

6. **Enable Obfuscation**
   ```
   Enable simple-obfs plugin? (y/n): y
   ```
   - Recommended for bypassing DPI
   - Makes traffic look like HTTPS

7. **Wait for Installation**
   - Downloads and installs shadowsocks-libev
   - Configures encryption and obfuscation
   - Creates systemd service
   - Starts the server

### What You Get

After successful installation:

```
✓ SHADOWSOCKS INSTALLED SUCCESSFULLY!

Configuration Details:
• Server: your.server.ip
• Port: 8388
• Password: your-password
• Encryption: aes-256-gcm
• Plugin: obfs-server (TLS mode)
• Protocol: TCP & UDP
• Status: Running

Connection URL:
ss://[base64-encoded-config]

✓ Configuration saved to: /root/shadowsocks-info.txt
```

### Connection Info File

Check `/root/shadowsocks-info.txt` for:
- Server details
- Connection parameters
- ss:// URL for easy client setup

```bash
cat /root/shadowsocks-info.txt
```

### Testing Shadowsocks

**Using shadowsocks client:**
```bash
# Install client
apt-get install shadowsocks-libev

# Test connection
ss-local -s your-server-ip -p 8388 -k your-password -m aes-256-gcm -l 1080
```

### Shadowsocks Management

**View Status:**
- Menu → 15 → 2 (View Status & Config)
- Shows: Service status, encryption, active connections

**View Connection Info:**
- Menu → 15 → 4 (View Connection Info)
- Displays configuration and ss:// URL

**Start/Stop Service:**
- Menu → 15 → 3 (Start/Stop Service)

**Uninstall:**
- Menu → 15 → 5 (Uninstall Shadowsocks)

---

## 📱 Client Configuration

### Squid Proxy Clients

#### Windows

1. **Internet Explorer/Edge:**
   - Settings → Network & Internet → Proxy
   - Manual proxy setup:
     - Address: `your-server-ip`
     - Port: `3128`

2. **Chrome/Firefox:**
   - Install proxy extension (FoxyProxy, SwitchyOmega)
   - Add new proxy profile
   - Type: HTTP
   - Server: `your-server-ip:3128`

#### Android

1. **HTTP Injector:**
   - Connection Type: Proxy
   - Proxy Server: `your-server-ip`
   - Proxy Port: `3128`
   - Authentication: Enable if configured

2. **Every Proxy:**
   - Type: HTTP/HTTPS
   - Host: `your-server-ip`
   - Port: `3128`

#### iOS

1. **Settings → Wi-Fi → [Your Network] → Configure Proxy**
   - Manual
   - Server: `your-server-ip`
   - Port: `3128`
   - Authentication: If enabled

### Shadowsocks Clients

#### Android

1. **Download:** Shadowsocks Android from Play Store
2. **Setup:**
   - Tap + icon
   - Choose "Scan QR Code" or "Manual Settings"
   
   **Manual Settings:**
   - Server: `your-server-ip`
   - Remote Port: `8388`
   - Password: `your-password`
   - Encrypt Method: `aes-256-gcm`
   - Plugin: `simple-obfs`
   - Plugin Options: `obfs=tls;obfs-host=cloudfront.net`

3. **Or use ss:// URL:**
   - Copy URL from server
   - Tap + → Import from Clipboard

#### iOS

1. **Download:** Shadowrocket or Quantumult X
2. **Shadowrocket:**
   - Add Server
   - Type: Shadowsocks
   - Enter server details
   - Plugin: simple-obfs with obfs=tls

#### Windows

1. **Download:** Shadowsocks-Windows
2. **Setup:**
   - Right-click tray icon → Servers → New Server
   - Enter server details
   - Enable plugin if using obfuscation

#### Linux/Mac

```bash
# Install client
sudo apt-get install shadowsocks-libev

# Create config
cat > /etc/shadowsocks-libev/config.json << EOF
{
    "server": "your-server-ip",
    "server_port": 8388,
    "local_port": 1080,
    "password": "your-password",
    "timeout": 300,
    "method": "aes-256-gcm"
}
EOF

# Start client
ss-local -c /etc/shadowsocks-libev/config.json
```

---

## 🔧 Advanced Configuration

### Squid - Custom Ports

To change ports after installation:

1. Edit config:
   ```bash
   nano /etc/squid/squid.conf
   ```

2. Modify:
   ```
   http_port 3128  → http_port YOUR_PORT
   https_port 3129 → https_port YOUR_PORT
   ```

3. Restart:
   ```bash
   systemctl restart squid
   ```

### Squid - Add Authentication Later

```bash
# Create password file
htpasswd -c /etc/squid/passwd username

# Edit squid.conf
nano /etc/squid/squid.conf

# Add these lines before "http_access allow all":
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic children 5
auth_param basic realm Squid Proxy Server
acl authenticated proxy_auth REQUIRED
http_access allow authenticated

# Remove or comment:
# http_access allow all

# Restart
systemctl restart squid
```

### Shadowsocks - Change Password

1. Edit config:
   ```bash
   nano /etc/shadowsocks-libev/config.json
   ```

2. Change password field:
   ```json
   "password": "your-new-password"
   ```

3. Restart:
   ```bash
   systemctl restart shadowsocks
   ```

### Shadowsocks - Multiple Ports

Run multiple instances on different ports:

```bash
# Copy config
cp /etc/shadowsocks-libev/config.json /etc/shadowsocks-libev/config2.json

# Edit new config with different port
nano /etc/shadowsocks-libev/config2.json

# Create new systemd service
cp /etc/systemd/system/shadowsocks.service /etc/systemd/system/shadowsocks2.service

# Edit service to use config2.json
nano /etc/systemd/system/shadowsocks2.service

# Start
systemctl daemon-reload
systemctl start shadowsocks2
systemctl enable shadowsocks2
```

---

## 🛡️ Security Best Practices

### For Squid

1. **Always use authentication** for public servers
2. **Limit access by IP** if possible (ACLs)
3. **Monitor logs** regularly:
   ```bash
   tail -f /var/log/squid/access.log
   ```
4. **Update regularly:**
   ```bash
   apt-get update && apt-get upgrade squid
   ```

### For Shadowsocks

1. **Use strong passwords** (16+ characters)
2. **Enable obfuscation** for better privacy
3. **Use AEAD ciphers** (aes-256-gcm, chacha20)
4. **Change default port** from 8388
5. **Monitor connections:**
   ```bash
   netstat -tn | grep :8388
   ```

---

## 🐛 Troubleshooting

### Squid Issues

**Service won't start:**
```bash
# Check logs
journalctl -u squid -n 50

# Common fixes:
squid -z  # Rebuild cache
squid -k check  # Check config syntax
```

**Permission errors:**
```bash
chown -R proxy:proxy /etc/squid
chown -R proxy:proxy /var/spool/squid
chown -R proxy:proxy /var/log/squid
```

**Can't connect:**
```bash
# Check if running
systemctl status squid

# Check firewall
ufw allow 3128/tcp
ufw allow 3129/tcp

# Test locally
curl -x http://127.0.0.1:3128 http://example.com
```

### Shadowsocks Issues

**Service won't start:**
```bash
# Check logs
journalctl -u shadowsocks -n 50

# Validate config
ss-server -c /etc/shadowsocks-libev/config.json -t
```

**Connection refused:**
```bash
# Check if running
systemctl status shadowsocks

# Check port binding
netstat -tulpn | grep ss-server

# Check firewall
ufw allow 8388/tcp
ufw allow 8388/udp
```

**Obfuscation not working:**
```bash
# Verify plugin installed
which obfs-server

# Reinstall if needed
apt-get install --reinstall simple-obfs
```

### Performance Issues

**Squid slow:**
```bash
# Increase cache memory
nano /etc/squid/squid.conf
# Change: cache_mem 256 MB → cache_mem 512 MB

systemctl restart squid
```

**Shadowsocks slow:**
```bash
# Try different encryption:
# chacha20-ietf-poly1305 is often faster than aes-256-gcm
# Edit config and restart
```

---

## 📊 Monitoring & Logs

### Squid

**Real-time access log:**
```bash
tail -f /var/log/squid/access.log
```

**Cache statistics:**
```bash
squidclient mgr:info
```

**Active connections:**
```bash
netstat -tn | grep :3128 | wc -l
```

### Shadowsocks

**Service logs:**
```bash
journalctl -u shadowsocks -f
```

**Active connections:**
```bash
netstat -tn | grep :8388 | wc -l
```

**Connection details:**
```bash
ss -tn | grep :8388
```

---

## 🎓 Additional Resources

### Squid Documentation
- Official Wiki: http://wiki.squid-cache.org/
- Configuration Reference: http://www.squid-cache.org/Doc/config/

### Shadowsocks Documentation
- Official Site: https://shadowsocks.org/
- GitHub: https://github.com/shadowsocks/shadowsocks-libev

### Client Downloads
- **Shadowsocks Android:** [Play Store](https://play.google.com/store/apps/details?id=com.github.shadowsocks)
- **Shadowrocket (iOS):** [App Store](https://apps.apple.com/app/shadowrocket/id932747118)
- **Shadowsocks Windows:** [GitHub](https://github.com/shadowsocks/shadowsocks-windows/releases)

---

## 💡 Tips & Tricks

### Combine with SSH Tunnel

Use Squid/Shadowsocks together with the existing SSH-SSL tunnel:
- SSH-SSL (port 443) for SSH connections
- Squid (port 3128/3129) for HTTP/HTTPS browsing
- Shadowsocks (port 8388) for all-purpose proxy

### Use Different Ports

To avoid detection:
```bash
# Squid on 8080/8443
# Shadowsocks on 443 (HTTPS port)
```

### Backup Configurations

```bash
# Backup Squid
tar -czf squid-backup.tar.gz /etc/squid /var/spool/squid

# Backup Shadowsocks
cp /etc/shadowsocks-libev/config.json ~/shadowsocks-backup.json
```

---

## 🆘 Getting Help

If you encounter issues:

1. Check this guide's troubleshooting section
2. Review logs (journalctl)
3. Open issue on GitHub: https://github.com/mkkelati/script7/issues
4. Provide:
   - Ubuntu version
   - Error messages
   - Relevant logs

---

**🎉 Happy Proxying with MK Script Manager v4.2!**

© 2025 MK Script Manager Team

