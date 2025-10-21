# MK Script Manager v4.2 - Changelog

## 🚀 What's New in v4.2

### Major New Features

#### 1. 🌐 Squid Proxy Manager (Menu Option 14)
Complete HTTP/HTTPS proxy solution with SSL/TLS support:

**Features:**
- ✅ SSL/TLS encryption with SSL bumping capability
- ✅ Optional HTTP authentication (htpasswd-based)
- ✅ High-performance caching (256MB memory + 2GB disk)
- ✅ Privacy features (header stripping)
- ✅ Automatic SSL certificate integration with stunnel
- ✅ Real-time connection monitoring
- ✅ Comprehensive access control lists (ACLs)

**Default Configuration:**
- HTTP Port: 3128
- HTTPS Port: 3129
- Cache: 256MB memory / 2GB disk
- Authentication: Optional

**Management Options:**
- Install with guided setup
- View status and statistics
- Start/Stop service control
- Complete uninstall with cleanup

---

#### 2. 🔐 Shadowsocks Manager (Menu Option 15)
Secure SOCKS5 proxy with advanced obfuscation:

**Features:**
- ✅ Modern AEAD encryption (AES-256-GCM, ChaCha20-Poly1305, XChaCha20)
- ✅ Simple-obfs plugin for traffic obfuscation
- ✅ TLS mode to disguise traffic as HTTPS
- ✅ TCP & UDP support
- ✅ TCP Fast Open for lower latency
- ✅ Auto-generated ss:// URLs for easy client setup
- ✅ Configuration saved to /root/shadowsocks-info.txt

**Encryption Methods:**
1. aes-256-gcm (Recommended - Fast & Secure)
2. chacha20-ietf-poly1305 (Mobile Optimized)
3. xchacha20-ietf-poly1305 (Maximum Security)

**Obfuscation:**
- obfs=tls: Makes traffic appear as HTTPS
- obfs=http: Makes traffic appear as HTTP
- Fast Open enabled for performance

**Management Options:**
- Install with encryption selection
- View status and active connections
- Display connection info with QR-compatible URL
- Start/Stop service control
- Complete uninstall

---

### Installation Updates

#### Optional Proxy Installation During Setup
The installer now prompts for optional proxy services:

```
Would you like to install additional proxy services?

1) Squid Proxy (HTTP/HTTPS proxy with SSL/TLS)
2) Shadowsocks (Secure SOCKS5 proxy with obfuscation)
3) Both Squid and Shadowsocks
4) Skip (install later from menu)
```

**Benefits:**
- One-time setup during initial installation
- Can also be installed later from menu options 14 & 15
- Packages are downloaded but not configured (allows custom setup)
- Zero impact if skipped

---

### Menu Structure Changes

**Updated Menu Layout:**
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
14) Squid Proxy         - HTTP/HTTPS proxy with SSL/TLS (NEW)
15) Shadowsocks         - Secure SOCKS5 proxy with obfuscation (NEW)
```

---

### Documentation Updates

#### README.MD Enhancements

**New Sections Added:**
1. **Squid Proxy Manager** - Complete feature documentation
2. **Shadowsocks Manager** - Comprehensive setup guide
3. **Updated Mobile Integration** - Client configuration examples
4. **Enhanced File Structure** - Includes proxy config paths

**Updated Badges:**
- Added Squid Proxy badge
- Added Shadowsocks badge
- Updated version to v4.2

**Key Features Section:**
- Added proxy service descriptions
- Updated port listings
- Enhanced security feature list

---

### Technical Implementation

#### New Files Created:
- `/etc/squid/squid.conf` - Squid configuration
- `/etc/squid/squid.pem` - SSL certificate (reuses stunnel or creates new)
- `/etc/squid/passwd` - Authentication file (if enabled)
- `/etc/shadowsocks-libev/config.json` - Shadowsocks configuration
- `/root/shadowsocks-info.txt` - Connection details for easy reference

#### New Functions in menu.sh:
```bash
# Squid Management
- is_squid_installed()
- is_squid_running()
- install_squid()
- uninstall_squid()
- show_squid_status()
- manage_squid()

# Shadowsocks Management
- is_shadowsocks_installed()
- is_shadowsocks_running()
- install_shadowsocks()
- uninstall_shadowsocks()
- show_shadowsocks_status()
- manage_shadowsocks()
```

---

### Client Configuration Examples

#### Squid Proxy
```
Proxy Type: HTTP/HTTPS
Server: your-server-ip
HTTP Port: 3128
HTTPS Port: 3129
Authentication: username/password (if enabled)
```

#### Shadowsocks
```
Server: your-server-ip
Port: 8388 (default, configurable)
Password: auto-generated or custom
Encryption: aes-256-gcm / chacha20-ietf-poly1305 / xchacha20-ietf-poly1305
Plugin: simple-obfs
Plugin Options: obfs=tls
```

**Mobile Clients:**
- **Android:** Shadowsocks Android + Simple Obfuscation
- **iOS:** Shadowrocket, Quantumult X
- **Windows:** Shadowsocks-Windows
- **Linux/Mac:** shadowsocks-libev

---

### Version Changes

**All version references updated from v4.1 to v4.2:**
- ✅ install.sh header and messages
- ✅ menu.sh header and all prompts
- ✅ README.MD title and badges
- ✅ Success messages and exit texts

---

### Security Enhancements

#### SSL/TLS Integration
- Both proxies support SSL/TLS encryption
- Squid can reuse existing stunnel certificates
- SSL bumping for HTTPS inspection (optional)
- Certificate auto-management

#### Privacy Features
- Header stripping in Squid (removes identifying headers)
- Traffic obfuscation in Shadowsocks
- TLS disguise makes traffic appear as legitimate HTTPS
- No logging of sensitive data

---

### Performance Optimizations

#### Squid Proxy
- 256MB memory cache
- 2GB disk cache with optimized swap thresholds
- TCP connection pooling
- Fast CGI support for dynamic content

#### Shadowsocks
- TCP Fast Open enabled
- Port reuse optimization
- No-delay socket option
- Efficient AEAD encryption

---

## 📦 Package Dependencies

### New Required Packages:

**For Squid:**
- squid
- squid-openssl
- apache2-utils (for htpasswd)

**For Shadowsocks:**
- shadowsocks-libev
- simple-obfs

**Installation:** All packages are available in Ubuntu 20.04-24.04 repositories.

---

## 🔄 Migration from v4.1

**No breaking changes!** v4.2 is fully backward compatible:

1. ✅ All existing features remain unchanged
2. ✅ Existing configurations are preserved
3. ✅ New features are optional additions
4. ✅ Menu options 1-13 work identically
5. ✅ Options 14 & 15 are new additions

**To upgrade:**
```bash
# Simply reinstall - won't affect existing users
sudo bash -c "$(wget -qO- https://raw.githubusercontent.com/mkkelati/script7/main/install.sh)"
```

---

## 🎯 Use Cases

### When to Use Squid Proxy:
- ✅ Need HTTP/HTTPS proxy for browsers
- ✅ Want caching for faster repeated requests
- ✅ Require authentication for access control
- ✅ Need to inspect/filter HTTPS traffic
- ✅ Corporate/organizational use

### When to Use Shadowsocks:
- ✅ Need to bypass deep packet inspection
- ✅ Want mobile-optimized encryption
- ✅ Require UDP support (gaming, VoIP)
- ✅ Need traffic obfuscation
- ✅ Personal privacy-focused use

### When to Use Both:
- ✅ Maximum flexibility for different use cases
- ✅ Redundancy if one service is blocked
- ✅ Different users prefer different protocols
- ✅ Testing and comparison purposes

---

## 🐛 Known Issues & Limitations

### Squid Proxy:
- SSL bumping requires clients to trust the certificate
- Cache directory needs sufficient disk space (2GB+)
- May require firewall rules for ports 3128/3129

### Shadowsocks:
- Simple-obfs adds slight latency overhead
- UDP mode may not work with all ISPs
- QR code generation requires external tools (URL provided for manual scanning)

---

## 📊 Testing Checklist

- [x] Squid installation and configuration
- [x] Squid SSL/TLS support
- [x] Squid authentication
- [x] Squid status monitoring
- [x] Squid uninstallation
- [x] Shadowsocks installation
- [x] Shadowsocks encryption methods
- [x] Shadowsocks obfuscation plugin
- [x] Shadowsocks connection URL generation
- [x] Shadowsocks uninstallation
- [x] Menu integration
- [x] Install script proxy option
- [x] Documentation updates
- [x] Version updates across all files
- [x] No linting errors

---

## 🙏 Credits

**Proxy Software:**
- [Squid Cache](http://www.squid-cache.org/) - High-performance HTTP proxy
- [Shadowsocks](https://shadowsocks.org/) - Secure socks5 proxy
- [simple-obfs](https://github.com/shadowsocks/simple-obfs) - Traffic obfuscation

**Maintained by:** MK Script Manager Team

---

## 📝 License

Same as main project - MIT License

---

**🎉 Enjoy the enhanced MK Script Manager v4.2 with full proxy support!**

For issues, feature requests, or contributions:
👉 https://github.com/mkkelati/script7/issues

