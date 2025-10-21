# 🚀 Quick Start Guide - MK Script Manager v4.2

## 📦 Installation (5 minutes)

### Step 1: Install Script
```bash
sudo bash -c "$(wget -qO- https://raw.githubusercontent.com/mkkelati/script7/main/install.sh)"
```

### Step 2: Choose Certificate Type
During installation, you'll be asked:

**Option 1: Let's Encrypt (Recommended)**
- Requires: Domain name pointing to your server
- Benefits: Trusted CA certificate, ISP bypass
- Auto-renews every 90 days

**Option 2: Self-signed**
- No domain needed
- Instant setup
- May be detected by ISPs

### Step 3: Wait for Installation
- Stunnel will be configured
- System will be optimized
- Menu system will be installed

### Step 4: Access Menu
```bash
menu
```

---

## 🎯 First-Time Setup

### 1. Create Your First User
```
menu → Option 1 (Create User)
```
- Enter username
- Set password (or auto-generate)
- Set connection limit (e.g., 2)
- Set expiration days (e.g., 30)

### 2. Verify SSL Tunnel
```
menu → Option 4 (Connection Mode)
```
- Should show stunnel running on port 443
- If not running, reconfigure from this menu

### 3. Test Connection
Connect using SSH-SSL on port 443:
- Use HTTP Injector or similar app
- Server: Your server IP
- Port: 443
- SSL/TLS: Enabled

---

## 🌐 Adding Proxies (Optional)

### Install Squid Proxy
```
menu → Option 14 (Squid Proxy) → Option 1 (Install)
```
**Configuration prompts:**
- HTTP Port: 3128 (default)
- HTTPS Port: 3129 (default)
- Authentication: y/n
- Username & Password (if enabled)

**Usage:**
- Set browser proxy to: `your-server-ip:3128`
- Or use HTTP Injector with proxy mode

### Install Shadowsocks
```
menu → Option 15 (Shadowsocks) → Option 1 (Install)
```
**Configuration prompts:**
- Port: 8388 (default)
- Password: (auto-generated or custom)
- Encryption: 1 (aes-256-gcm recommended)
- Obfuscation: y (recommended)

**Usage:**
- Check connection info: Menu → 15 → 4
- Copy ss:// URL to Shadowsocks client
- Or enter details manually

---

## 📱 Menu Options Quick Reference

```
1)  Create User          - Add new SSH users
2)  Delete User          - Remove users
3)  Limit User           - Change connection limits
4)  Connection Mode      - Configure SSL tunnel ⭐
5)  Online Users         - See active connections
6)  Network Traffic      - Monitor bandwidth
7)  User Report          - View all users status
8)  Change Password      - Update user passwords
9)  User Limiter         - Auto-enforce limits
10) Server Optimization  - Tune performance
11) Uninstall           - Remove everything
12) BadVPN Manager      - UDP gateway
13) Banner Creator      - SSH welcome banners
14) Squid Proxy         - HTTP/HTTPS proxy ⭐
15) Shadowsocks         - Secure SOCKS5 proxy ⭐
00) Exit
```

⭐ = Popular features

---

## 🔧 Common Tasks

### Check Server Status
```bash
menu → Option 5 (Online Users)
```
Shows all active connections in real-time

### View User List
```bash
menu → Option 7 (User Report)
```
Shows all users, expiration dates, and status

### Monitor Traffic
```bash
menu → Option 6 (Network Traffic)
```
Real-time network usage (requires nload)

### Change User Password
```bash
menu → Option 8 (Change Password)
```
Select user and enter new password

### Optimize Server
```bash
menu → Option 10 (Server Optimization)
```
Automatic performance tuning

---

## 🛡️ Security Best Practices

### For SSH Users
1. ✅ Set reasonable connection limits (2-5)
2. ✅ Set expiration dates (30-90 days)
3. ✅ Use strong passwords (8+ characters)
4. ✅ Monitor active users regularly
5. ✅ Enable User Limiter (option 9)

### For Proxy Services
1. ✅ Always enable authentication on Squid
2. ✅ Use strong passwords for Shadowsocks
3. ✅ Enable obfuscation on Shadowsocks
4. ✅ Change default ports if needed
5. ✅ Monitor connection logs

### For Server
1. ✅ Use Let's Encrypt certificates
2. ✅ Keep system updated
3. ✅ Enable firewall (UFW)
4. ✅ Regular backups
5. ✅ Monitor disk space

---

## 📱 Mobile Client Setup

### For SSH-SSL (Port 443)
**HTTP Injector:**
1. Connection Type: Stunnel/SSL
2. Server: Your server IP
3. Port: 443
4. Enable SSL/TLS
5. Connect

### For Squid Proxy
**HTTP Injector:**
1. Connection Type: Proxy
2. Proxy Server: Your server IP
3. Proxy Port: 3128
4. Authentication: (if enabled)
5. Connect

### For Shadowsocks
**Shadowsocks Android:**
1. Open app
2. Tap + icon
3. Scan QR or enter details
4. Use connection info from: menu → 15 → 4
5. Connect

---

## 🐛 Troubleshooting

### Stunnel Not Working
```bash
# Check status
systemctl status stunnel4

# Restart
systemctl restart stunnel4

# Check logs
journalctl -u stunnel4 -n 50

# From menu
menu → Option 4 → Reconfigure
```

### Proxy Won't Install
**Error:** "SSL/TLS TUNNEL NOT CONFIGURED"

**Solution:**
```bash
menu → Option 4 (Connection Mode)
# Configure SSL tunnel first
# Then try proxy installation again
```

### User Can't Connect
1. Check if user exists: `menu → Option 7`
2. Check if user expired
3. Check connection limit not exceeded
4. Verify stunnel running: `systemctl status stunnel4`
5. Check port 443 open: `netstat -tlnp | grep :443`

### Out of Disk Space
```bash
# Check space
df -h

# Clean logs
menu → Option 10 (Server Optimization)

# Or manually
apt-get clean
apt-get autoremove
```

---

## 💡 Pro Tips

### Tip 1: Use Let's Encrypt
- Much better ISP bypass
- Appears as legitimate HTTPS
- Free and auto-renewing

### Tip 2: Enable User Limiter
```
menu → Option 9 → Start Limiter
```
Automatically enforces connection limits

### Tip 3: Combine Services
- SSH-SSL on port 443 (for SSH)
- Squid on 3128 (for browsing)
- Shadowsocks on 8388 (for apps)

### Tip 4: Regular Maintenance
```bash
# Weekly
menu → Option 7  # Check user status
menu → Option 5  # Check connections

# Monthly
menu → Option 10 # Optimize server
# Update users as needed
```

### Tip 5: Backup Configuration
```bash
# Backup important files
tar -czf mk-backup.tar.gz \
  /etc/mk-script \
  /etc/stunnel \
  /etc/squid/squid.conf \
  /etc/shadowsocks-libev/config.json \
  /root/shadowsocks-info.txt
```

---

## 🔗 Useful Commands

### Quick Status Check
```bash
# All in one
systemctl status stunnel4 squid shadowsocks | grep Active
```

### Connection Count
```bash
# SSH connections
netstat -tn | grep :22 | wc -l

# Stunnel connections
netstat -tn | grep :443 | wc -l

# Squid connections
netstat -tn | grep :3128 | wc -l

# Shadowsocks connections
netstat -tn | grep :8388 | wc -l
```

### View Logs
```bash
# Stunnel
journalctl -u stunnel4 -f

# Squid
tail -f /var/log/squid/access.log

# Shadowsocks
journalctl -u shadowsocks -f
```

### Quick Restart All Services
```bash
systemctl restart stunnel4 squid shadowsocks
```

---

## 📚 Learn More

- **Full Documentation:** README.MD
- **Proxy Setup:** PROXY_SETUP_GUIDE.md
- **Changelog:** CHANGELOG_v4.2.md
- **Fixes:** FIXES_v4.2.1.md

---

## 🆘 Getting Help

### Common Questions

**Q: Can I change stunnel port from 443?**
A: Yes, edit `/etc/stunnel/stunnel.conf` and change `accept = 443`

**Q: How many users can I create?**
A: Unlimited, but consider server resources

**Q: Can I use both Let's Encrypt and self-signed?**
A: No, choose one during installation

**Q: Do proxies work without stunnel?**
A: The script requires SSL tunnel for security

**Q: Can I install on other Linux distros?**
A: Tested on Ubuntu 20.04-24.04 LTS only

### Need Help?

1. **Check documentation** (this guide, README.MD)
2. **Check logs** (journalctl commands above)
3. **Open issue:** https://github.com/mkkelati/script7/issues

---

## ✅ Quick Checklist

- [ ] Script installed successfully
- [ ] SSL certificate configured
- [ ] Stunnel running on port 443
- [ ] First user created
- [ ] Tested SSH-SSL connection
- [ ] (Optional) Squid installed and tested
- [ ] (Optional) Shadowsocks installed and tested
- [ ] Firewall configured (if using)
- [ ] Backup created

---

**🎉 You're all set! Enjoy MK Script Manager v4.2!**

For advanced features and configurations, check the full documentation.

© 2025 MK Script Manager Team

