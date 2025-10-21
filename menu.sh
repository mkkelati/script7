#!/bin/bash
# MK Script Manager v4.2 - Advanced SSH Management System + Proxy Support
# Compatible with Ubuntu 20.04 - 24.04 LTS
# Repository: https://github.com/mkkelati/script7

# Configuration
USER_LIST_FILE="/etc/mk-script/users.txt"
PASSWORD_DIR="/etc/mk-script/senha"
LEGACY_PASSWORD_DIR="/etc/VPSManager/senha"
LEGACY_EXP_FILE="/etc/VPSManager/Exp"

# User Limiter Configuration
LIMITER_DATABASE="/root/usuarios.db"
OPENVPN_STATUS="/etc/openvpn/openvpn-status.log"
OPENVPN_MANAGEMENT_PORT="7505"
CHECK_INTERVAL=15
AUTOSTART_FILE="/etc/autostart"
LIMITER_NAME="user_limiter"

# Ensure required files exist
[[ -f "$USER_LIST_FILE" ]] || { echo "User list missing at $USER_LIST_FILE"; exit 1; }

# Colors
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;36m'
WHITE='\033[1;37m'
RESET='\033[0m'

# Utility functions
generate_password() { < /dev/urandom tr -dc 'A-Za-z0-9' | head -c8; }
list_users() { nl -w2 -s ') ' "$USER_LIST_FILE"; }

safe_number() {
    local value="$1"
    if [[ "$value" =~ ^[0-9]+$ ]]; then
        echo "$value"
    else
        echo "0"
    fi
}

# Count total connections for all users (not unique users)
count_online_users() {
    local total_connections=0
    
    if [[ -s "$USER_LIST_FILE" ]]; then
        while IFS=: read -r username limit; do
            [[ -z "$username" ]] && continue
            
            local ssh_count=$(safe_number $(get_ssh_connections "$username"))
            local dropbear_count=$(safe_number $(get_dropbear_connections "$username"))
            local openvpn_count=$(safe_number $(get_openvpn_connections "$username"))
            local total_conn=$((ssh_count + dropbear_count + openvpn_count))
            
            # Add all connections for this user to total
            total_connections=$((total_connections + total_conn))
            
        done < "$USER_LIST_FILE"
    fi
    
    echo "$total_connections"
}

# Disconnect all active connections for a specific user
disconnect_user_connections() {
    local username="$1"
    [[ -z "$username" ]] && return 1
    
    echo -e "${YELLOW}Disconnecting all active connections for user: $username${RESET}"
    
    local disconnected=0
    
    # Kill SSH connections
    local ssh_pids=$(ps aux | grep "sshd.*$username" | grep -v grep | awk '{print $2}')
    if [[ -n "$ssh_pids" ]]; then
        echo "$ssh_pids" | while read -r pid; do
            if [[ -n "$pid" ]]; then
                kill -9 "$pid" 2>/dev/null && ((disconnected++))
            fi
        done
        echo -e "${GREEN}✓ Killed SSH connections${RESET}"
    fi
    
    # Kill Dropbear connections
    if command -v dropbear >/dev/null 2>&1; then
        local dropbear_pids=$(ps -u "$username" 2>/dev/null | grep dropbear | awk '{print $1}')
        if [[ -n "$dropbear_pids" ]]; then
            echo "$dropbear_pids" | while read -r pid; do
                if [[ -n "$pid" ]]; then
                    kill -9 "$pid" 2>/dev/null && ((disconnected++))
                fi
            done
            echo -e "${GREEN}✓ Killed Dropbear connections${RESET}"
        fi
    fi
    
    # Kill OpenVPN connections
    if [[ -f "/etc/openvpn/openvpn-status.log" ]]; then
        grep "^$username," /etc/openvpn/openvpn-status.log 2>/dev/null | while IFS=',' read -r user endpoint _ _; do
            if [[ -n "$endpoint" ]]; then
                echo "kill $endpoint" | nc localhost "7505" 2>/dev/null
                echo -e "${GREEN}✓ Killed OpenVPN connection from $endpoint${RESET}"
                ((disconnected++))
            fi
        done
    fi
    
    # Force kill any remaining user processes
    pkill -u "$username" 2>/dev/null
    
    echo -e "${GREEN}✓ All connections for user '$username' have been terminated${RESET}"
}

# Display professional system dashboard (elegant design)
display_professional_dashboard() {
    clear
    
    # Get system information (following the guide format)
    local system=""
    if [[ "$(grep -c "Ubuntu" /etc/issue.net 2>/dev/null)" = "1" ]]; then
        system=$(cut -d' ' -f1 /etc/issue.net 2>/dev/null)
        system+=" "
        system+=$(cut -d' ' -f2 /etc/issue.net 2>/dev/null | awk -F "." '{print $1}')
    elif [[ "$(grep -c "Debian" /etc/issue.net 2>/dev/null)" = "1" ]]; then
        system=$(cut -d' ' -f1 /etc/issue.net 2>/dev/null)
        system+=" "
        system+=$(cut -d' ' -f3 /etc/issue.net 2>/dev/null)
    else
        system=$(uname -s 2>/dev/null || echo "Linux")
    fi
    
    local _tuser=$(wc -l < "$USER_LIST_FILE" 2>/dev/null || echo "0")
    local _onlin=$(count_online_users)
    local _ram=$(free -h 2>/dev/null | grep -i mem | awk '{print $2}' || echo "N/A")
    local _usor=$(free -m 2>/dev/null | awk 'NR==2{printf "%.1f%%", $3*100/$2 }' || echo "N/A")
    local _usop=$(top -bn1 2>/dev/null | awk '/Cpu/ { cpu = "" 100 - $8 "%" }; END { print cpu }' || echo "N/A")
    local _core=$(grep -c cpu[0-9] /proc/stat 2>/dev/null || echo "N/A")
    local _hora=$(date '+%H:%M:%S')
    # Count active users (users with at least one connection)
    local _active_users=0
    if [[ -s "$USER_LIST_FILE" ]]; then
        while IFS=: read -r username limit; do
            [[ -z "$username" ]] && continue
            local ssh_count=$(safe_number $(get_ssh_connections "$username"))
            local dropbear_count=$(safe_number $(get_dropbear_connections "$username"))
            local openvpn_count=$(safe_number $(get_openvpn_connections "$username"))
            local total_conn=$((ssh_count + dropbear_count + openvpn_count))
            
            # Count user as active if they have any connections
            if [[ $total_conn -gt 0 ]]; then
                _active_users=$((_active_users + 1))
            fi
        done < "$USER_LIST_FILE"
    fi
    
    # Format variables for consistent width
    local _system=$(printf '%-14s' "$system")
    local _onlin_fmt=$(printf '%-5s' "$_onlin")
    local _tuser_fmt=$(printf '%-5s' "$_tuser")
    
    # Elegant Dashboard Header
    echo -e "\033[0;34m◇───────────────────────────────────────────────◇${RESET}"
    echo -e "\E[42;1;37m           •ㅤ⚡ㅤMK SCRIPT MANAGERㅤ⚡ㅤ•        \E[0m"
    echo -e "\033[0;34m◇───────────────────────────────────────────────◇${RESET}"
    
    # System Information Section
    echo -e "${GREEN}◇ㅤSYSTEM          ◇ㅤRAM MEMORY    ◇ㅤPROCESSOR ${RESET}"
    echo -e "${RED}OS: ${WHITE}$_system ${RED}Total:${WHITE} $_ram  ${RED}CPU cores: ${WHITE}$_core${RESET}"
    echo -e "${RED}Up Time: ${WHITE}$_hora  ${RED}In use: ${WHITE}$_usor ${RED}In use: ${WHITE}$_usop${RESET}"
    echo -e "\033[0;34m◇───────────────────────────────────────────────◇${RESET}"
    
    # User Statistics Section
    echo -e "${GREEN}◇ㅤOnline:${WHITE} $_onlin_fmt   ${YELLOW}◇ㅤTotal Users: ${WHITE}$_tuser_fmt   ${BLUE}◇ㅤActive Users: ${WHITE}$_active_users${RESET}"
    echo -e "\033[0;34m◇───────────────────────────────────────────────◇${RESET}"
    echo ""
}

# Professional header with timestamp
display_header_with_timestamp() {
    local title="$1"
    local current_time=$(date '+%Y-%m-%d %H:%M:%S')
    tput setaf 7 ; tput setab 4 ; tput bold
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' ' '
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" "🚀 MK SCRIPT MANAGER v4.2 - $title" | tr ' ' ' '
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" "📅 $current_time" | tr ' ' ' '
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' ' '
    tput sgr0
}

# Get SSH connections for user
get_ssh_connections() {
    local user="$1"
    if grep -q "^$user:" /etc/passwd 2>/dev/null; then
        ps -u "$user" 2>/dev/null | grep -c sshd || echo "0"
    else
        echo "0"
    fi
}

# Get Dropbear connections for user
get_dropbear_connections() {
    local user="$1"
    if command -v dropbear >/dev/null 2>&1; then
        ps -u "$user" 2>/dev/null | grep -c dropbear || echo "0"
    else
        echo "0"
    fi
}

# Get OpenVPN connections for user
get_openvpn_connections() {
    local user="$1"
    local count=0
    
    # Check OpenVPN status log
    if [[ -f /etc/openvpn/openvpn-status.log ]]; then
        count=$(grep -c "^$user," /etc/openvpn/openvpn-status.log 2>/dev/null || echo "0")
    fi
    
    # Check OpenVPN server logs
    if [[ -f /var/log/openvpn/status.log ]]; then
        local log_count=$(grep -c "^$user," /var/log/openvpn/status.log 2>/dev/null || echo "0")
        count=$((count + log_count))
    fi
    
    echo "$count"
}

# Get user expiration date
get_user_expiration() {
    local user="$1"
    
    # Check main expiration file
    if [[ -f "$LEGACY_EXP_FILE" ]] && grep -q "^$user " "$LEGACY_EXP_FILE"; then
        grep "^$user " "$LEGACY_EXP_FILE" | cut -d' ' -f2
    else
        echo "Never"
    fi
}

# Check if user is expired
is_user_expired() {
    local user="$1"
    local exp_date=$(get_user_expiration "$user")
    
    if [[ "$exp_date" == "Never" ]]; then
        return 1
    fi
    
    local current_date=$(date +%Y-%m-%d)
    if [[ "$exp_date" < "$current_date" ]]; then
        return 0
    else
        return 1
    fi
}

# Create new user
create_user() {
    clear
    display_header_with_timestamp "CREATE USER"
    
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}           CREATE NEW USER              ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
  read -p "Enter new username: " username
    [[ -z "$username" ]] && { echo -e "${RED}Username cannot be empty.${RESET}"; return; }
    
    # Check if user exists
    if id "$username" &>/dev/null; then 
        echo -e "${RED}User '$username' already exists. Choose another.${RESET}"; 
        return; 
    fi
    
    read -s -p "Enter password (blank = default '1212'): " password
    echo
    [[ -z "$password" ]] && { 
        password="1212"; 
        echo -e "${GREEN}Using default password: ${WHITE}$password${RESET}"; 
    }
    
    read -p "Connection limit (0 = unlimited): " limit
    [[ -z "$limit" || ! "$limit" =~ ^[0-9]+$ ]] && limit=0
    
    read -p "Expiration in days (blank = never, 0 = unlimited): " exp_days
    [[ -z "$exp_days" ]] && exp_days="never"
    
    # Calculate expiration date from days
    if [[ "$exp_days" == "never" || "$exp_days" == "0" ]]; then
        exp_date="Never"
    elif [[ "$exp_days" =~ ^[0-9]+$ ]]; then
        exp_date=$(date -d "+${exp_days} days" +%Y-%m-%d)
        echo -e "${GREEN}✓ Account will expire on: $exp_date${RESET}"
    else
        echo -e "${RED}Invalid input. Use number of days or leave blank for never${RESET}"
        return
    fi
    
    # Create system user
    if useradd -m -s /bin/false "$username" 2>/dev/null; then
  echo "${username}:${password}" | chpasswd
        
        # Add to user database
        echo "${username}:${limit}" >> "$USER_LIST_FILE"
        
        # Store password
        mkdir -p "$PASSWORD_DIR"
        echo "$password" > "$PASSWORD_DIR/$username"
        
        # Store expiration if set
        if [[ "$exp_date" != "Never" ]]; then
            mkdir -p "$(dirname "$LEGACY_EXP_FILE")"
            echo "$username $exp_date" >> "$LEGACY_EXP_FILE"
        fi
        
        # Set connection limit
        if [[ "$limit" -gt 0 ]]; then
            LIMIT_FILE="/etc/security/limits.d/mk-script-limits.conf"
            mkdir -p /etc/security/limits.d
            echo "${username}    -    maxlogins    $limit" >> "$LIMIT_FILE"
        fi
        
        # Add user to User Limiter database automatically
        if [[ "$limit" -gt 0 ]]; then
            # Ensure limiter database exists
            mkdir -p "$(dirname "$LIMITER_DATABASE")"
            touch "$LIMITER_DATABASE"
            
            # Check if user already exists in limiter database
            if ! grep -q "^$username " "$LIMITER_DATABASE" 2>/dev/null; then
                echo "$username $limit" >> "$LIMITER_DATABASE"
                echo -e "${GREEN}✓ Added to User Limiter database (limit: $limit)${RESET}"
            fi
        fi
        
        # Display account information
        clear
        display_header_with_timestamp "USER CREATED"
        
        echo -e "\n${GREEN}┌────────────────────────────────────────┐${RESET}"
        echo -e "${GREEN}│${WHITE}        ACCOUNT CREATED SUCCESSFULLY     ${GREEN}│${RESET}"
        echo -e "${GREEN}└────────────────────────────────────────┘${RESET}\n"
        
        echo -e "${WHITE}Username:${RESET} ${GREEN}$username${RESET}"
        echo -e "${WHITE}Password:${RESET} ${GREEN}$password${RESET}"
        echo -e "${WHITE}Limit:${RESET} ${GREEN}$limit connections${RESET}"
        echo -e "${WHITE}Expires:${RESET} ${GREEN}$exp_date${RESET}"
        
        # Show connection details
  if systemctl is-active --quiet stunnel4; then
            PORT=$(grep -m1 "^accept = " /etc/stunnel/stunnel.conf 2>/dev/null | awk '{print $3}' || echo "443")
            echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
            echo -e "${BLUE}│${WHITE}         CONNECTION DETAILS             ${BLUE}│${RESET}"
            echo -e "${BLUE}└────────────────────────────────────────┘${RESET}"
            echo -e "${WHITE}SSH-SSL Port:${RESET} ${YELLOW}$PORT${RESET}"
            echo -e "${WHITE}Protocol:${RESET} ${YELLOW}Stunnel${RESET}"
        else
            echo -e "\n${WHITE}Standard SSH Port:${RESET} ${YELLOW}22${RESET}"
        fi
        
    else
        echo -e "${RED}Failed to create user '$username'${RESET}"
    fi
}

# Delete user
delete_user() {
    clear
    display_header_with_timestamp "DELETE USER"
    
    echo -e "\n${RED}┌────────────────────────────────────────┐${RESET}"
    echo -e "${RED}│${WHITE}            DELETE USER                 ${RED}│${RESET}"
    echo -e "${RED}└────────────────────────────────────────┘${RESET}\n"
    
    [[ -s "$USER_LIST_FILE" ]] || { 
        echo -e "${YELLOW}No users to delete.${RESET}"; 
        return; 
    }
    
    echo -e "${WHITE}Select user to delete:${RESET}\n"
  list_users
    echo
    
    read -p "Enter user number: " num
    [[ "$num" =~ ^[0-9]+$ ]] || { 
        echo -e "${RED}Invalid selection.${RESET}"; 
        return; 
    }
    
  username=$(sed -n "${num}p" "$USER_LIST_FILE" | cut -d: -f1)
    [[ -n "$username" ]] || { 
        echo -e "${RED}User not found.${RESET}"; 
        return; 
    }
    
    echo -e "\n${YELLOW}Are you sure you want to delete user '${WHITE}$username${YELLOW}'? [y/N]:${RESET} "
    read -n 1 -r confirm
    echo
    
    if [[ $confirm =~ ^[Yy]$ ]]; then
        # Disconnect all active connections first
        disconnect_user_connections "$username"
        sleep 2
        
        # Delete system user
  userdel -r "$username" 2>/dev/null
        
        # Remove from database
  sed -i "${num}d" "$USER_LIST_FILE"
        
        # Remove from User Limiter database
        if [[ -f "$LIMITER_DATABASE" ]]; then
            sed -i "/^$username /d" "$LIMITER_DATABASE"
            echo -e "${GREEN}✓ Removed from User Limiter database${RESET}"
        fi
        
        # Remove password files
        rm -f "$PASSWORD_DIR/$username" "$LEGACY_PASSWORD_DIR/$username" 2>/dev/null
        
        # Remove expiration entry
        if [[ -f "$LEGACY_EXP_FILE" ]]; then
            sed -i "/^$username /d" "$LEGACY_EXP_FILE"
        fi
        
        # Remove connection limits
  LIMIT_FILE="/etc/security/limits.d/mk-script-limits.conf"
        if [[ -f "$LIMIT_FILE" ]]; then
            sed -i "/^${username}[[:space:]]\+.*maxlogins/d" "$LIMIT_FILE"
        fi
        
        echo -e "\n${GREEN}✓ User '$username' deleted successfully and all connections terminated${RESET}"
    else
        echo -e "\n${YELLOW}Operation cancelled${RESET}"
    fi
}

# Set user connection limit
limit_user() {
    clear
    display_header_with_timestamp "USER LIMITS"
    
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}        SET CONNECTION LIMITS           ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
    [[ -s "$USER_LIST_FILE" ]] || { 
        echo -e "${YELLOW}No users to limit.${RESET}"; 
        return; 
    }
    
    echo -e "${WHITE}Select user to limit:${RESET}\n"
  list_users
    echo
    
    read -p "Enter user number: " num
    [[ "$num" =~ ^[0-9]+$ ]] || { 
        echo -e "${RED}Invalid selection.${RESET}"; 
        return; 
    }
    
  username=$(sed -n "${num}p" "$USER_LIST_FILE" | cut -d: -f1)
    [[ -n "$username" ]] || { 
        echo -e "${RED}User not found.${RESET}"; 
        return; 
    }
    
    current_limit=$(sed -n "${num}p" "$USER_LIST_FILE" | cut -d: -f2)
    echo -e "${WHITE}Current limit for '${GREEN}$username${WHITE}': ${YELLOW}$current_limit${RESET}"
    
    read -p "New connection limit (0 = unlimited): " limit
    [[ -z "$limit" || ! "$limit" =~ ^[0-9]+$ ]] && limit=0
    
    # Update database
    awk -F: -v user="$username" -v newlimit="$limit" '
        {if($1==user){$2=newlimit} print $1 ":" $2}
    ' "$USER_LIST_FILE" > "${USER_LIST_FILE}.tmp" && mv "${USER_LIST_FILE}.tmp" "$USER_LIST_FILE"
    
    # Update PAM limits
  LIMIT_FILE="/etc/security/limits.d/mk-script-limits.conf"
  mkdir -p /etc/security/limits.d
  sed -i "/^${username}[[:space:]]\+.*maxlogins/d" "$LIMIT_FILE" 2>/dev/null
    
    if [[ "$limit" -gt 0 ]]; then
        echo "${username}    -    maxlogins    $limit" >> "$LIMIT_FILE"
    fi
    
    # Update User Limiter database
    if [[ "$limit" -gt 0 ]]; then
        # Ensure limiter database exists
        mkdir -p "$(dirname "$LIMITER_DATABASE")"
        touch "$LIMITER_DATABASE"
        
        # Update or add user to limiter database
        if grep -q "^$username " "$LIMITER_DATABASE" 2>/dev/null; then
            # Update existing entry
            sed -i "s/^$username [0-9]\+/$username $limit/" "$LIMITER_DATABASE"
            echo -e "${GREEN}✓ Updated User Limiter database (limit: $limit)${RESET}"
        else
            # Add new entry
            echo "$username $limit" >> "$LIMITER_DATABASE"
            echo -e "${GREEN}✓ Added to User Limiter database (limit: $limit)${RESET}"
        fi
    else
        # Remove from limiter database if limit is 0 (unlimited)
        if [[ -f "$LIMITER_DATABASE" ]]; then
            sed -i "/^$username /d" "$LIMITER_DATABASE"
            echo -e "${YELLOW}✓ Removed from User Limiter database (unlimited)${RESET}"
        fi
    fi
    
    echo -e "\n${GREEN}✓ Connection limit for '$username' set to $limit and synced with User Limiter${RESET}"
}

# Configure SSH-SSL tunnel
configure_tunnel() {
    clear
    display_header_with_timestamp "SSL TUNNEL"
    
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}       SSH-SSL TUNNEL SETUP            ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
    read -p "Enter SSL port [default 443]: " port
  port=${port:-443}
    
    [[ "$port" =~ ^[0-9]+$ ]] && [[ "$port" -ge 1 && "$port" -le 65535 ]] || { 
        echo -e "${RED}Invalid port number.${RESET}"; 
        return; 
    }
    
    # Install latest stunnel if not present
    if ! command -v stunnel4 &>/dev/null && ! command -v stunnel &>/dev/null; then
        echo -e "${YELLOW}Installing latest stunnel...${RESET}"
        
        # Install build dependencies
        apt-get update -y >/dev/null 2>&1
        apt-get install -y build-essential libssl-dev zlib1g-dev wget tar >/dev/null 2>&1
        
        # Download and compile latest stunnel
        cd /tmp
        echo -e "${YELLOW}Downloading stunnel 5.75 (latest)...${RESET}"
        wget -q https://www.stunnel.org/downloads/stunnel-5.75.tar.gz || {
            echo -e "${YELLOW}Fallback: Installing from Ubuntu repository...${RESET}"
            apt-get install -y stunnel4 >/dev/null 2>&1 || { 
                echo -e "${RED}Failed to install stunnel${RESET}"; 
                return; 
            }
        }
        
        if [[ -f stunnel-5.75.tar.gz ]]; then
            echo -e "${YELLOW}Compiling stunnel 5.75...${RESET}"
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
            
            echo -e "${GREEN}✓ Latest stunnel 5.75 installed with systemd service${RESET}"
        fi
    fi
    
    # Configure stunnel for Ubuntu 22.04/24.04 compatibility
    echo -e "${YELLOW}Configuring stunnel for Ubuntu 22.04/24.04...${RESET}"
    
    # Clean up old systemd overrides if they exist
    rm -rf /etc/systemd/system/stunnel4.service.d 2>/dev/null
    
    # Create default configuration if needed
    if [[ -f /etc/default/stunnel4 ]]; then
        sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4 2>/dev/null
        echo 'ENABLED=1' >> /etc/default/stunnel4 2>/dev/null
    else
        echo 'ENABLED=1' > /etc/default/stunnel4
    fi
    
    # Reload systemd daemon to pick up new service
    systemctl daemon-reload >/dev/null 2>&1
    
    # Generate certificate if needed with proper permissions
  if [[ ! -f /etc/stunnel/stunnel.pem ]]; then
        echo -e "${YELLOW}Generating SSL certificate...${RESET}"
        
        # Create certificate with proper permissions for stunnel4 user
    openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes \
      -subj "/C=US/ST=State/L=City/O=MK-Script/OU=IT/CN=$(hostname)" \
            -keyout /etc/stunnel/key.pem -out /etc/stunnel/cert.pem >/dev/null 2>&1
        
        # Combine certificate and key
    cat /etc/stunnel/key.pem /etc/stunnel/cert.pem > /etc/stunnel/stunnel.pem
        
        # Set proper ownership and permissions for stunnel4 user
        chown stunnel4:stunnel4 /etc/stunnel/stunnel.pem 2>/dev/null || chown root:stunnel4 /etc/stunnel/stunnel.pem
        chmod 640 /etc/stunnel/stunnel.pem
        
        # Also fix permissions on the directory
        chown -R stunnel4:stunnel4 /etc/stunnel 2>/dev/null || chown -R root:stunnel4 /etc/stunnel
        chmod 755 /etc/stunnel
        
        # Clean up individual files
        rm -f /etc/stunnel/key.pem /etc/stunnel/cert.pem
        
        echo -e "${GREEN}✓ SSL certificate generated with proper permissions${RESET}"
    else
        # Fix permissions on existing certificate
        echo -e "${YELLOW}Fixing permissions on existing certificate...${RESET}"
        chown stunnel4:stunnel4 /etc/stunnel/stunnel.pem 2>/dev/null || chown root:stunnel4 /etc/stunnel/stunnel.pem
        chmod 640 /etc/stunnel/stunnel.pem
        chown -R stunnel4:stunnel4 /etc/stunnel 2>/dev/null || chown -R root:stunnel4 /etc/stunnel
        chmod 755 /etc/stunnel
    fi
    
    # Create stunnel configuration with Ubuntu 22.04/24.04 compatibility
    echo -e "${YELLOW}Creating stunnel configuration...${RESET}"
    
    # Ensure stunnel4 user exists and has proper setup
    if ! id stunnel4 >/dev/null 2>&1; then
        echo -e "${YELLOW}Creating stunnel4 user...${RESET}"
        useradd -r -s /bin/false -d /var/lib/stunnel4 -c "stunnel service" stunnel4 2>/dev/null || true
    fi
    
    # Ensure stunnel directory exists and has correct permissions
    mkdir -p /etc/stunnel
    mkdir -p /var/run/stunnel4
    mkdir -p /var/lib/stunnel4
    mkdir -p /var/log/stunnel4
    
    # Set proper ownership with fallback - try stunnel4 user first, then root
    if id stunnel4 >/dev/null 2>&1; then
        chown stunnel4:stunnel4 /var/run/stunnel4 2>/dev/null || chown root:root /var/run/stunnel4
        chown stunnel4:stunnel4 /var/lib/stunnel4 2>/dev/null || chown root:root /var/lib/stunnel4
        chown stunnel4:stunnel4 /var/log/stunnel4 2>/dev/null || chown root:root /var/log/stunnel4
    else
        chown root:root /var/run/stunnel4 /var/lib/stunnel4 /var/log/stunnel4
    fi
    
    chmod 755 /var/run/stunnel4 /var/lib/stunnel4 /var/log/stunnel4
    
    # Create configuration with user detection
    local stunnel_user="root"
    local stunnel_group="root"
    
    if id stunnel4 >/dev/null 2>&1; then
        stunnel_user="stunnel4"
        stunnel_group="stunnel4"
    fi
    
    # Create configuration for mandatory TLS_AES_256_GCM_SHA384 cipher
    cat > /etc/stunnel/stunnel.conf <<EOC
# Mandatory TLS_AES_256_GCM_SHA384 cipher configuration
cert = /etc/stunnel/stunnel.pem
pid = /var/run/stunnel4/stunnel.pid

# Run as root for maximum compatibility
# setuid = stunnel4
# setgid = stunnel4

# Logging
debug = 7
output = /var/log/stunnel4/stunnel.log

[ssh-tunnel]
accept = ${port}
connect = 127.0.0.1:22

# MANDATORY: Only TLS_AES_256_GCM_SHA384 cipher allowed
ciphersuites = TLS_AES_256_GCM_SHA384

# Force TLS 1.3 only for TLS_AES_256_GCM_SHA384
sslVersion = TLSv1.3
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1_1
options = NO_TLSv1_2
EOC

    echo -e "${GREEN}✓ Configuration created${RESET}"

    # Ensure certificate has correct permissions for the user we're using
    if [[ "$stunnel_user" == "stunnel4" ]]; then
        chown stunnel4:stunnel4 /etc/stunnel/stunnel.pem 2>/dev/null || chown root:stunnel4 /etc/stunnel/stunnel.pem
        chmod 640 /etc/stunnel/stunnel.pem
    else
        chown root:root /etc/stunnel/stunnel.pem
        chmod 600 /etc/stunnel/stunnel.pem
    fi
    
    # Create a working stunnel configuration (no test mode available in stunnel4 5.72)
    echo -e "${YELLOW}Creating optimized stunnel configuration...${RESET}"

    # Start and enable stunnel with proper error handling
    echo -e "${YELLOW}Starting stunnel4 service...${RESET}"
    
    # Stop any existing stunnel processes
    systemctl stop stunnel4 >/dev/null 2>&1 || true
    pkill -f stunnel4 >/dev/null 2>&1 || true
    
    # Reload systemd and start service
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable stunnel4 >/dev/null 2>&1
    
    # Give it a moment and start
    sleep 2
    systemctl start stunnel4 >/dev/null 2>&1
    
    # Wait and check status
    sleep 3
    
    # Check if stunnel is running and listening on the port (with fallback for newer Ubuntu)
    local port_listening=false
    if command -v netstat >/dev/null 2>&1; then
        netstat -tlnp | grep -q ":$port " && port_listening=true
    elif command -v ss >/dev/null 2>&1; then
        ss -tlnp | grep -q ":$port " && port_listening=true
    fi
    
    if systemctl is-active --quiet stunnel4 && [[ "$port_listening" == true ]]; then
        echo -e "\n${GREEN}✓ SSH-SSL tunnel configured successfully${RESET}"
        echo -e "${WHITE}SSL Port:${RESET} ${GREEN}$port${RESET}"
        echo -e "${WHITE}Target:${RESET} ${GREEN}127.0.0.1:22${RESET}"
        echo -e "${WHITE}Protocol:${RESET} ${GREEN}TLS 1.2/1.3${RESET}"
        echo -e "${WHITE}Status:${RESET} ${GREEN}Active and listening${RESET}"
        
        # Show service status
        echo -e "\n${BLUE}Service Status:${RESET}"
        systemctl status stunnel4 --no-pager -l | head -5
    else
        echo -e "\n${RED}✗ Failed to start stunnel service${RESET}"
        echo -e "${YELLOW}Troubleshooting information:${RESET}"
        
        # Show detailed error information
        echo -e "${WHITE}Service Status:${RESET}"
        systemctl status stunnel4 --no-pager -l 2>/dev/null | head -10 || echo "Could not get service status"
        
        # Show configuration file
        echo -e "\n${WHITE}Configuration File:${RESET}"
        if [[ -f /etc/stunnel/stunnel.conf ]]; then
            echo "Configuration exists at /etc/stunnel/stunnel.conf"
            echo "First 10 lines:"
            head -10 /etc/stunnel/stunnel.conf 2>/dev/null || echo "Could not read configuration"
        else
            echo "Configuration file missing: /etc/stunnel/stunnel.conf"
        fi
        
        echo -e "\n${WHITE}Certificate Check:${RESET}"
        if [[ -f /etc/stunnel/stunnel.pem ]]; then
            ls -la /etc/stunnel/stunnel.pem
            openssl x509 -in /etc/stunnel/stunnel.pem -text -noout | head -5 2>/dev/null || echo "Certificate validation failed"
        else
            echo "Certificate file missing: /etc/stunnel/stunnel.pem"
        fi
        
        echo -e "\n${WHITE}Stunnel Log:${RESET}"
        if [[ -f /var/log/stunnel4/stunnel.log ]]; then
            echo "Last 15 lines of stunnel log:"
            tail -15 /var/log/stunnel4/stunnel.log 2>/dev/null || echo "Could not read stunnel log"
        else
            echo "No stunnel log file found at /var/log/stunnel4/stunnel.log"
        fi
        
        echo -e "\n${WHITE}System Journal:${RESET}"
        journalctl -u stunnel4 --no-pager -n 10 2>/dev/null || echo "Could not get systemd journal"
        
        echo -e "\n${WHITE}Process Check:${RESET}"
        ps aux | grep stunnel | grep -v grep || echo "No stunnel processes running"
        
        echo -e "\n${WHITE}Port Check:${RESET}"
        if command -v netstat >/dev/null 2>&1; then
            netstat -tlnp | grep ":$port " || echo "Port $port is not listening"
        elif command -v ss >/dev/null 2>&1; then
            ss -tlnp | grep ":$port " || echo "Port $port is not listening"
        else
            echo "No network tools available to check port $port"
        fi
        
        echo -e "\n${WHITE}Directory Permissions:${RESET}"
        ls -la /etc/stunnel/ 2>/dev/null || echo "Could not check /etc/stunnel/"
        ls -la /var/run/stunnel4/ 2>/dev/null || echo "Could not check /var/run/stunnel4/"
        
        echo -e "\n${YELLOW}Debugging commands:${RESET}"
        echo -e "${WHITE}systemctl restart stunnel4${RESET}"
        echo -e "${WHITE}journalctl -u stunnel4 -f${RESET}"
        echo -e "${WHITE}cat /etc/stunnel/stunnel.conf${RESET}"
        echo -e "${WHITE}stunnel4 /etc/stunnel/stunnel.conf${RESET} (manual start)"
    fi
}

# Timer tracking directory
USER_TIMER_DIR="/tmp/mk-script-timers"

# Function to initialize timer tracking
init_user_timers() {
    mkdir -p "$USER_TIMER_DIR"
}

# Function to start timer for a user
start_user_timer() {
    local username="$1"
    if [[ -n "$username" ]]; then
        echo "$(date +%s)" > "$USER_TIMER_DIR/${username}.timer"
    fi
}

# Function to stop timer for a user
stop_user_timer() {
    local username="$1"
    if [[ -n "$username" ]]; then
        rm -f "$USER_TIMER_DIR/${username}.timer" 2>/dev/null
    fi
}

# Function to get connection time for a user
get_user_connection_time() {
    local username="$1"
    local timer_file="$USER_TIMER_DIR/${username}.timer"
    
    if [[ -f "$timer_file" ]]; then
        local start_time=$(cat "$timer_file" 2>/dev/null || echo "0")
        local current_time=$(date +%s)
        local duration=$((current_time - start_time))
        
        # Convert to hours:minutes:seconds
        local hours=$((duration / 3600))
        local minutes=$(((duration % 3600) / 60))
        local seconds=$((duration % 60))
        
        printf "%02d:%02d:%02d" "$hours" "$minutes" "$seconds"
    else
        echo "00:00:00"
    fi
}

# Show online users with real-time monitoring and stopwatch timer
show_online_users() {
    local refresh_count=0
    
    # Initialize timer tracking
    init_user_timers
    
    while true; do
        clear
        display_header_with_timestamp "ONLINE USERS MONITOR"
        
        echo -e "\n${BLUE}┌──────────────────────────────────────────────────────────┐${RESET}"
        echo -e "${BLUE}│${WHITE}                REAL-TIME CONNECTIONS & TIMERS            ${BLUE}│${RESET}"
        echo -e "${BLUE}├──────────────────────────────────────────────────────────┤${RESET}"
        printf "${BLUE}│${WHITE} %-12s │ %-8s │ %-12s │ %-8s │ %-6s ${BLUE}│${RESET}\n" "USERNAME" "SSH" "TIME ONLINE" "TOTAL" "STATUS"
        echo -e "${BLUE}├──────────────────────────────────────────────────────────┤${RESET}"
        
        local total_online=0
        local any_users=false
        
        if [[ -s "$USER_LIST_FILE" ]]; then
            while IFS=: read -r username limit; do
                [[ -z "$username" ]] && continue
                any_users=true
                
                local ssh_count=$(safe_number $(get_ssh_connections "$username"))
                local total_conn=$ssh_count
                
                # Timer logic: Start timer when user connects, stop when disconnects
                if [[ $total_conn -gt 0 ]]; then
                    # User is online - start timer if not already started
                    if [[ ! -f "$USER_TIMER_DIR/${username}.timer" ]]; then
                        start_user_timer "$username"
                    fi
                    total_online=$((total_online + 1))
                    local status_icon="🟢"
                    local status_color="${GREEN}"
                else
                    # User is offline - stop timer and reset
                    stop_user_timer "$username"
                    local status_icon="🔴"
                    local status_color="${RED}"
                fi
                
                # Check if expired
                if is_user_expired "$username"; then
                    status_icon="⏰"
                    status_color="${YELLOW}"
                fi
                
                # Get connection time
                local connection_time=$(get_user_connection_time "$username")
                
                printf "${BLUE}│${WHITE} %-12s ${BLUE}│${WHITE} %-8s ${BLUE}│${CYAN} %-12s ${BLUE}│${status_color} %-8s ${BLUE}│${status_color} %-6s ${BLUE}│${RESET}\n" \
                    "$username" "$ssh_count" "$connection_time" "$total_conn" "$status_icon"
                    
            done < "$USER_LIST_FILE"
        fi
        
        if [[ "$any_users" == false ]]; then
            printf "${BLUE}│${YELLOW} %-54s ${BLUE}│${RESET}\n" "No users found in database"
        fi
        
        echo -e "${BLUE}├──────────────────────────────────────────────────────────┤${RESET}"
        printf "${BLUE}│${WHITE} Total Users Online: ${GREEN}%-2d${WHITE}                            ${BLUE}│${RESET}\n" "$total_online"
        printf "${BLUE}│${WHITE} Auto-refresh: ${GREEN}%-2d${WHITE} times                           ${BLUE}│${RESET}\n" "$refresh_count"
        echo -e "${BLUE}└──────────────────────────────────────────────────────────┘${RESET}"
        
        echo -e "\n${WHITE}🟢 Online  🔴 Offline  ⏰ Expired${RESET}"
        echo -e "${CYAN}⏱️  Timer starts when user connects, resets to 00:00:00 when disconnected${RESET}"
        echo -e "${GREEN}Press ${WHITE}ENTER${GREEN} to return to main menu or wait for auto-refresh...${RESET}"
        
        # Wait for user input or timeout after 3 seconds
        if read -t 3 -n 1 user_input 2>/dev/null; then
            # If user pressed any key, exit the loop
            if [[ -n "$user_input" ]] || [[ "$user_input" == "" ]]; then
                break
            fi
        fi
        
        ((refresh_count++))
    done
}

# Network traffic monitoring
show_network_traffic() {
    clear
    display_header_with_timestamp "NETWORK TRAFFIC"
    
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}        NETWORK TRAFFIC MONITOR         ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
    if command -v nload >/dev/null 2>&1; then
        echo -e "${WHITE}Starting network traffic monitor...${RESET}"
        echo -e "${YELLOW}Press 'q' to quit nload${RESET}\n"
        sleep 2
        nload
    else
        echo -e "${YELLOW}Installing network monitoring tool...${RESET}"
        apt-get update -y >/dev/null 2>&1
        if apt-get install -y nload >/dev/null 2>&1; then
            echo -e "${GREEN}✓ Installation complete${RESET}"
            echo -e "${WHITE}Starting network traffic monitor...${RESET}"
            sleep 2
            nload
        else
            echo -e "${RED}✗ Failed to install nload${RESET}"
            echo -e "${WHITE}Showing basic network statistics:${RESET}\n"
            
            # Basic network info
            echo -e "${BLUE}Network Interfaces:${RESET}"
            ip -4 addr show | grep -E '^[0-9]+:|inet ' | while read line; do
                if [[ $line =~ ^[0-9]+: ]]; then
                    echo -e "${WHITE}$line${RESET}"
                else
                    echo -e "  ${GREEN}$line${RESET}"
                fi
            done
        fi
    fi
}

# User report with comprehensive information
show_user_report() {
    clear
    display_header_with_timestamp "USER REPORT"
    
    echo -e "\n${BLUE}┌─────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}                           USER STATUS REPORT                        ${BLUE}│${RESET}"
    echo -e "${BLUE}├─────────────────────────────────────────────────────────────────────┤${RESET}"
    printf "${BLUE}│${WHITE} %-12s │ %-8s │ %-8s │ %-12s │ %-8s │ %-8s ${BLUE}│${RESET}\n" "USERNAME" "LIMIT" "ACTIVE" "EXPIRES" "PASSWORD" "STATUS"
    echo -e "${BLUE}├─────────────────────────────────────────────────────────────────────┤${RESET}"
    
    local total_users=0
    local active_users=0
    local expired_users=0
    
    if [[ -s "$USER_LIST_FILE" ]]; then
  while IFS=: read -r username limit; do
            [[ -z "$username" ]] && continue
            total_users=$((total_users + 1))
            
            local ssh_count=$(safe_number $(get_ssh_connections "$username"))
            local dropbear_count=$(safe_number $(get_dropbear_connections "$username"))
            local openvpn_count=$(safe_number $(get_openvpn_connections "$username"))
            local total_conn=$((ssh_count + dropbear_count + openvpn_count))
            local exp_date=$(get_user_expiration "$username")
            
            # Get password
            local password="N/A"
            if [[ -f "$PASSWORD_DIR/$username" ]]; then
                password=$(cat "$PASSWORD_DIR/$username" 2>/dev/null || echo "N/A")
            elif [[ -f "$LEGACY_PASSWORD_DIR/$username" ]]; then
                password=$(cat "$LEGACY_PASSWORD_DIR/$username" 2>/dev/null || echo "N/A")
            fi
            
            # Determine status
            local status="Active"
            local status_color="${GREEN}"
            
            if is_user_expired "$username"; then
                status="Expired"
                status_color="${RED}"
                expired_users=$((expired_users + 1))
            elif [[ $total_conn -gt 0 ]]; then
                status="Online"
                status_color="${GREEN}"
                active_users=$((active_users + 1))
            else
                status="Offline"
                status_color="${YELLOW}"
            fi
            
            printf "${BLUE}│${WHITE} %-12s ${BLUE}│${WHITE} %-8s ${BLUE}│${WHITE} %-8s ${BLUE}│${WHITE} %-12s ${BLUE}│${WHITE} %-8s ${BLUE}│${status_color} %-8s ${BLUE}│${RESET}\n" \
                "$username" "$limit" "$total_conn" "$exp_date" "${password:0:8}" "$status"
                
        done < "$USER_LIST_FILE"
    else
        printf "${BLUE}│${YELLOW} %-67s ${BLUE}│${RESET}\n" "No users found in database"
    fi
    
    echo -e "${BLUE}├─────────────────────────────────────────────────────────────────────┤${RESET}"
    printf "${BLUE}│${WHITE} Total: ${GREEN}%-3d${WHITE} │ Active: ${GREEN}%-3d${WHITE} │ Expired: ${RED}%-3d${WHITE}                    ${BLUE}│${RESET}\n" \
        "$total_users" "$active_users" "$expired_users"
    echo -e "${BLUE}└─────────────────────────────────────────────────────────────────────┘${RESET}"
}

# Change user password
change_user_password() {
    clear
    display_header_with_timestamp "CHANGE PASSWORD"
    
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}         CHANGE USER PASSWORD          ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
    [[ -s "$USER_LIST_FILE" ]] || { 
        echo -e "${YELLOW}No users to modify.${RESET}"; 
        return; 
    }
    
    echo -e "${WHITE}Select user to change password:${RESET}\n"
    list_users
    echo
    
    read -p "Enter user number: " num
    [[ "$num" =~ ^[0-9]+$ ]] || { 
        echo -e "${RED}Invalid selection.${RESET}"; 
        return; 
    }
    
    username=$(sed -n "${num}p" "$USER_LIST_FILE" | cut -d: -f1)
    [[ -n "$username" ]] || { 
        echo -e "${RED}User not found.${RESET}"; 
        return; 
    }
    
    echo -e "${WHITE}Changing password for user: ${GREEN}$username${RESET}\n"
    
    read -s -p "Enter new password (blank = default '1212'): " new_password
    echo
    
    [[ -z "$new_password" ]] && { 
        new_password="1212"; 
        echo -e "${GREEN}Using default password: ${WHITE}$new_password${RESET}"; 
    }
    
    # Update system password
    if echo "${username}:${new_password}" | chpasswd 2>/dev/null; then
        # Update password files
        mkdir -p "$PASSWORD_DIR"
        echo "$new_password" > "$PASSWORD_DIR/$username"
        
        # Update legacy location if it exists
        if [[ -d "$LEGACY_PASSWORD_DIR" ]]; then
            mkdir -p "$LEGACY_PASSWORD_DIR"
            echo "$new_password" > "$LEGACY_PASSWORD_DIR/$username"
        fi
        
        echo -e "\n${GREEN}✓ Password changed successfully${RESET}"
        echo -e "${WHITE}Username:${RESET} ${GREEN}$username${RESET}"
        echo -e "${WHITE}New Password:${RESET} ${GREEN}$new_password${RESET}"
        
        # Disconnect all active connections to force re-authentication
        echo -e "\n${YELLOW}Disconnecting all active connections to force re-authentication...${RESET}"
        disconnect_user_connections "$username"
        echo -e "${GREEN}✓ All connections terminated - user must reconnect with new password${RESET}"
    else
        echo -e "\n${RED}✗ Failed to change password${RESET}"
    fi
}

# ============================================================================
# USER LIMITER FUNCTIONS
# ============================================================================

# Function to display loading bar
fun_bar() {
    local command1="$1"
    local command2="$2"
    
    (
        eval "$command1" >/dev/null 2>&1
        [[ -n "$command2" ]] && eval "$command2" >/dev/null 2>&1
        touch /tmp/limiter_done
    ) &
    
    echo -ne "${YELLOW}Please Wait... ${WHITE}- ${YELLOW}["
    while [[ ! -f /tmp/limiter_done ]]; do
        for ((i = 0; i < 18; i++)); do
            echo -ne "${RED}#"
            sleep 0.1
        done
        [[ -f /tmp/limiter_done ]] && break
        echo -e "${YELLOW}]"
        sleep 1
        echo -ne "\033[1A\033[K${YELLOW}Please Wait... ${WHITE}- ${YELLOW}["
    done
    echo -e "${YELLOW}]${WHITE} - ${GREEN}DONE!${RESET}"
    rm -f /tmp/limiter_done
}

# Function to get user connection limit from limiter database
get_user_limit_from_db() {
    local user="$1"
    if [[ -f "$LIMITER_DATABASE" ]] && grep -wq "$user" "$LIMITER_DATABASE"; then
        grep -w "$user" "$LIMITER_DATABASE" | cut -d' ' -f2
    else
        echo "1"  # Default limit
    fi
}

# Function to count SSH connections for a user (limiter version)
count_ssh_connections_limiter() {
    local user="$1"
    ps -u "$user" 2>/dev/null | grep -c sshd || echo "0"
}

# Function to count OpenVPN connections for a user (limiter version)
count_openvpn_connections_limiter() {
    local user="$1"
    if [[ -e "$OPENVPN_STATUS" ]]; then
        grep -E ",$user," "$OPENVPN_STATUS" 2>/dev/null | wc -l || echo "0"
    else
        echo "0"
    fi
}

# Function to kill excess OpenVPN connections
kill_excess_openvpn() {
    local user="$1"
    local limit="$2"
    local current_connections="$3"
    
    local connections_to_kill=$((current_connections - limit))
    if [[ $connections_to_kill -gt 0 ]]; then
        local pids_to_kill=$(grep -E ",$user," "$OPENVPN_STATUS" 2>/dev/null | cut -d',' -f3 | head -n $connections_to_kill)
        
        while IFS= read -r pid; do
            if [[ -n "$pid" ]]; then
                (
                    {
                        echo "kill $pid"
                        sleep 1
                    } | telnet localhost "$OPENVPN_MANAGEMENT_PORT" 
                ) &>/dev/null &
            fi
        done <<< "$pids_to_kill"
    fi
}

# Main limiter enforcement function
enforce_limits() {
    local users_processed=0
    local violations_found=0
    
    # Get all system users (UID >= 1000, excluding nobody)
    while IFS= read -r user; do
        [[ -z "$user" ]] && continue
        
        local limit=$(get_user_limit_from_db "$user")
        local ssh_connections=$(count_ssh_connections_limiter "$user")
        local openvpn_connections=$(count_openvpn_connections_limiter "$user")
        local total_connections=$((ssh_connections + openvpn_connections))
        
        ((users_processed++))
        
        # Check SSH connections
        if [[ $ssh_connections -gt $limit ]]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') - User $user exceeded SSH limit ($ssh_connections/$limit) - Killing processes"
            pkill -u "$user" 2>/dev/null
            ((violations_found++))
        fi
        
        # Check OpenVPN connections
        if [[ $openvpn_connections -gt $limit ]]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') - User $user exceeded OpenVPN limit ($openvpn_connections/$limit) - Killing excess connections"
            kill_excess_openvpn "$user" "$limit" "$openvpn_connections"
            ((violations_found++))
        fi
        
    done <<< "$(awk -F: '$3 >= 1000 {print $1}' /etc/passwd | grep -v nobody)"
    
    # Log summary
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Checked $users_processed users, found $violations_found violations"
}

# Function to start the limiter
start_limiter() {
    clear
    display_header_with_timestamp "USER LIMITER"
    
    echo -e "\n${GREEN}◇ STARTING USER LIMITER...${RESET}"
    echo ""
    
    # Check if already running
    if screen -list | grep -q "$LIMITER_NAME"; then
        echo -e "${YELLOW}User limiter is already running!${RESET}"
        return 1
    fi
    
    # Create the limiter daemon script
    create_limiter_daemon() {
        cat > /tmp/limiter_daemon.sh << 'LIMITER_SCRIPT'
#!/bin/bash

# User Limiter Configuration
LIMITER_DATABASE="/root/usuarios.db"
OPENVPN_STATUS="/etc/openvpn/openvpn-status.log"
OPENVPN_MANAGEMENT_PORT="7505"
CHECK_INTERVAL=15

# Function to get user limit from database
get_user_limit_from_db() {
    local username="$1"
    [[ -z "$username" ]] && return 1
    
    # Default limit if not found
    local default_limit=1
    
    if [[ -f "$LIMITER_DATABASE" ]]; then
        local limit=$(grep "^$username " "$LIMITER_DATABASE" | awk '{print $2}' | head -1)
        [[ -n "$limit" && "$limit" =~ ^[0-9]+$ ]] && echo "$limit" || echo "$default_limit"
    else
        echo "$default_limit"
    fi
}

# Function to count SSH connections for limiter
count_ssh_connections_limiter() {
    local username="$1"
    [[ -z "$username" ]] && { echo "0"; return; }
    
    local count=$(ps aux | grep "sshd.*$username" | grep -v grep | wc -l 2>/dev/null || echo "0")
    echo "$count"
}

# Function to count OpenVPN connections for limiter
count_openvpn_connections_limiter() {
    local username="$1"
    [[ -z "$username" ]] && { echo "0"; return; }
    
    if [[ -f "$OPENVPN_STATUS" ]]; then
        local count=$(grep "^$username," "$OPENVPN_STATUS" | wc -l 2>/dev/null || echo "0")
        echo "$count"
    else
        echo "0"
    fi
}

# Function to kill excess OpenVPN connections
kill_excess_openvpn() {
    local username="$1"
    local limit="$2"
    local current_connections="$3"
    
    [[ -z "$username" || -z "$limit" || -z "$current_connections" ]] && return 1
    
    local excess=$((current_connections - limit))
    [[ $excess -le 0 ]] && return 0
    
    if [[ -f "$OPENVPN_STATUS" ]]; then
        grep "^$username," "$OPENVPN_STATUS" | tail -n "$excess" | while IFS=',' read -r user endpoint _ _; do
            if [[ -n "$endpoint" ]]; then
                echo "kill $endpoint" | nc localhost "$OPENVPN_MANAGEMENT_PORT" 2>/dev/null
                echo "$(date '+%Y-%m-%d %H:%M:%S') - Killed OpenVPN connection for $user from $endpoint"
            fi
        done
    fi
}

# Main limiter enforcement function
enforce_limits() {
    local users_processed=0
    local violations_found=0
    
    # Get all system users (UID >= 1000, excluding nobody)
    while IFS= read -r user; do
        [[ -z "$user" ]] && continue
        
        local limit=$(get_user_limit_from_db "$user")
        local ssh_connections=$(count_ssh_connections_limiter "$user")
        local openvpn_connections=$(count_openvpn_connections_limiter "$user")
        local total_connections=$((ssh_connections + openvpn_connections))
        
        ((users_processed++))
        
        # Check SSH connections
        if [[ $ssh_connections -gt $limit ]]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') - User $user exceeded SSH limit ($ssh_connections/$limit) - Killing processes"
            pkill -u "$user" 2>/dev/null
            ((violations_found++))
        fi
        
        # Check OpenVPN connections
        if [[ $openvpn_connections -gt $limit ]]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') - User $user exceeded OpenVPN limit ($openvpn_connections/$limit) - Killing excess connections"
            kill_excess_openvpn "$user" "$limit" "$openvpn_connections"
            ((violations_found++))
        fi
        
    done <<< "$(awk -F: '$3 >= 1000 {print $1}' /etc/passwd | grep -v nobody)"
    
    # Log summary
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Checked $users_processed users, found $violations_found violations"
}

# Main daemon loop
echo "User Connection Limiter Started - $(date)"
echo "Database: $LIMITER_DATABASE"
echo "Check Interval: ${CHECK_INTERVAL}s"
echo "OpenVPN Status: $OPENVPN_STATUS"
echo "================================"

while true; do
    enforce_limits
    sleep $CHECK_INTERVAL
done
LIMITER_SCRIPT
        
        chmod +x /tmp/limiter_daemon.sh
    }
    
    # Start the limiter in screen session
    start_limiter_process() {
        # Create the daemon script
        create_limiter_daemon
        
        # Start in screen session
        screen -dmS "$LIMITER_NAME" /tmp/limiter_daemon.sh
        
        # Wait a moment for the screen to start
        sleep 2
        
        # Verify it started
        if screen -list | grep -q "$LIMITER_NAME"; then
            echo "Limiter started successfully in screen session"
        else
            echo "Failed to start limiter in screen session"
            return 1
        fi
        
        # Add to autostart if file exists
        if [[ -f "$AUTOSTART_FILE" ]]; then
            # Remove any existing limiter entries
            sed -i '/user_limiter/d' "$AUTOSTART_FILE" 2>/dev/null
            # Add new entry
            echo "screen -list | grep -q '$LIMITER_NAME' || screen -dmS $LIMITER_NAME /tmp/limiter_daemon.sh" >> "$AUTOSTART_FILE"
        fi
    }
    
    fun_bar 'start_limiter_process' 'sleep 2'
    echo -e "\n${GREEN}◇ USER LIMITER ACTIVATED!${RESET}"
    echo -e "${WHITE}Monitoring users every ${CHECK_INTERVAL} seconds${RESET}"
    echo -e "${WHITE}View logs: ${BLUE}screen -r $LIMITER_NAME${RESET}"
    sleep 3
}

# Function to stop the limiter
stop_limiter() {
    clear
    display_header_with_timestamp "USER LIMITER"
    
    echo -e "${GREEN}◇ STOPPING USER LIMITER...${RESET}"
    echo ""
    
    stop_limiter_process() {
        # Kill screen session
        if screen -list | grep -q "$LIMITER_NAME"; then
            screen -S "$LIMITER_NAME" -X quit 2>/dev/null
            echo "Screen session terminated"
        fi
        
        # Clean up screen sessions
        screen -wipe >/dev/null 2>&1
        
        # Remove daemon script
        if [[ -f "/tmp/limiter_daemon.sh" ]]; then
            rm -f /tmp/limiter_daemon.sh
            echo "Daemon script cleaned up"
        fi
        
        # Remove from autostart
        if [[ -f "$AUTOSTART_FILE" ]]; then
            sed -i '/user_limiter/d' "$AUTOSTART_FILE" 2>/dev/null
            echo "Removed from autostart"
        fi
        
        sleep 1
    }
    
    fun_bar 'stop_limiter_process' 'sleep 2'
    echo -e "\n${RED}◇ USER LIMITER STOPPED!${RESET}"
    sleep 3
}

# Function to check limiter status
check_limiter_status() {
    clear
    display_header_with_timestamp "LIMITER STATUS"
    
    echo -e "\n${BLUE}◇ USER LIMITER STATUS${RESET}"
    echo -e "${BLUE}========================${RESET}\n"
    
    if screen -list | grep -q "$LIMITER_NAME"; then
        echo -e "Status: ${GREEN}RUNNING${RESET}"
        echo -e "Session: ${WHITE}$LIMITER_NAME${RESET}"
        echo -e "Database: ${WHITE}$LIMITER_DATABASE${RESET}"
        echo -e "Check Interval: ${WHITE}${CHECK_INTERVAL}s${RESET}"
        
        # Show current user connections
        echo ""
        echo -e "${YELLOW}Current User Connections:${RESET}"
        echo -e "${BLUE}=========================${RESET}"
        printf "%-15s %-8s %-8s %-8s %-8s\n" "User" "Limit" "SSH" "OpenVPN" "Total"
        echo "-------------------------------------------------------"
        
        while IFS= read -r user; do
            [[ -z "$user" ]] && continue
            local limit=$(get_user_limit_from_db "$user")
            local ssh_count=$(count_ssh_connections_limiter "$user")
            local ovpn_count=$(count_openvpn_connections_limiter "$user")
            local total=$((ssh_count + ovpn_count))
            
            if [[ $total -gt 0 ]]; then
                local status_color="${WHITE}"
                if [[ $total -gt $limit ]]; then
                    status_color="${RED}"
                fi
                printf "${status_color}%-15s %-8s %-8s %-8s %-8s${RESET}\n" "$user" "$limit" "$ssh_count" "$ovpn_count" "$total"
            fi
        done <<< "$(awk -F: '$3 >= 1000 {print $1}' /etc/passwd | grep -v nobody)"
        
    else
        echo -e "Status: ${RED}STOPPED${RESET}"
        echo ""
        echo -e "${YELLOW}The user limiter is currently inactive${RESET}"
    fi
    
    echo ""
}

# User Limiter Management Menu
user_limiter_management() {
    while true; do
        clear
        display_header_with_timestamp "USER LIMITER"
        
        echo -e "\n${BLUE}◇ USER LIMITER MANAGEMENT${RESET}"
        echo -e "${BLUE}==========================${RESET}\n"
        
        if screen -list | grep -q "$LIMITER_NAME"; then
            status_text="${GREEN}ACTIVE ♦${RESET}"
            action_text="STOP LIMITER"
            action_color="${RED}"
        else
            status_text="${RED}INACTIVE ○${RESET}"
            action_text="START LIMITER"
            action_color="${GREEN}"
        fi
        
        echo -e "${WHITE}Current Status: $status_text${RESET}"
        echo ""
        echo -e "${RED}[${BLUE}1${RED}] ${WHITE}• ${action_color}$action_text${RESET}"
        echo -e "${RED}[${BLUE}2${RED}] ${WHITE}• ${YELLOW}CHECK STATUS${RESET}"
        echo -e "${RED}[${BLUE}3${RED}] ${WHITE}• ${YELLOW}VIEW LOGS${RESET}"
        echo -e "${RED}[${BLUE}4${RED}] ${WHITE}• ${YELLOW}SETUP DATABASE${RESET}"
        echo -e "${RED}[${BLUE}0${RED}] ${WHITE}• ${YELLOW}BACK TO MAIN MENU${RESET}"
        echo ""
        echo -ne "${GREEN}What do you want to do${YELLOW}? ${WHITE}"
        read choice
        
        case "$choice" in
            1)
                if screen -list | grep -q "$LIMITER_NAME"; then
                    stop_limiter
                else
                    start_limiter
                fi
                ;;
            2)
                check_limiter_status
                echo ""
                read -p "Press Enter to continue..."
                ;;
            3)
                if screen -list | grep -q "$LIMITER_NAME"; then
                    echo -e "\n${YELLOW}Connecting to limiter logs...${RESET}"
                    echo -e "${WHITE}Press Ctrl+A then D to detach${RESET}"
                    sleep 2
                    screen -r "$LIMITER_NAME"
                else
                    echo -e "\n${RED}Limiter is not running!${RESET}"
                    sleep 2
                fi
                ;;
            4)
                setup_limiter_database
                ;;
            0)
                return
                ;;
            *)
                echo -e "\n${RED}Invalid option!${RESET}"
                sleep 2
                ;;
        esac
    done
}

# Function to setup limiter database
setup_limiter_database() {
    clear
    display_header_with_timestamp "DATABASE SETUP"
    
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}        LIMITER DATABASE SETUP          ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
    echo -e "${WHITE}Current database: ${GREEN}$LIMITER_DATABASE${RESET}\n"
    
    # Create database directory if needed
    mkdir -p "$(dirname "$LIMITER_DATABASE")"
    
    # Check if database exists
    if [[ -f "$LIMITER_DATABASE" ]]; then
        echo -e "${YELLOW}Existing database found:${RESET}"
        echo -e "${BLUE}=========================${RESET}"
        cat "$LIMITER_DATABASE" 2>/dev/null || echo "Empty database"
        echo ""
    else
        echo -e "${YELLOW}No database found. Creating new one...${RESET}"
        touch "$LIMITER_DATABASE"
    fi
    
    echo -e "${WHITE}Database format: ${GREEN}username limit${RESET}"
    echo -e "${WHITE}Example: ${GREEN}user1 2${RESET} (allows 2 connections)"
    echo ""
    
    echo -e "${RED}[${BLUE}1${RED}] ${WHITE}Add User Limit${RESET}"
    echo -e "${RED}[${BLUE}2${RED}] ${WHITE}Remove User Limit${RESET}"
    echo -e "${RED}[${BLUE}3${RED}] ${WHITE}View Database${RESET}"
    echo -e "${RED}[${BLUE}4${RED}] ${WHITE}Import from Main Database${RESET}"
    echo -e "${RED}[${BLUE}5${RED}] ${WHITE}Auto-Setup & Start Limiter${RESET}"
    echo -e "${RED}[${BLUE}0${RED}] ${WHITE}Back${RESET}"
    echo ""
    echo -ne "${GREEN}Choose option: ${WHITE}"
    read db_choice
    
    case "$db_choice" in
        1)
            read -p "Enter username: " username
            [[ -z "$username" ]] && { echo -e "${RED}Username cannot be empty${RESET}"; sleep 2; return; }
            
            read -p "Enter connection limit: " limit
            [[ ! "$limit" =~ ^[0-9]+$ ]] && { echo -e "${RED}Invalid limit${RESET}"; sleep 2; return; }
            
            # Remove existing entry and add new one
            sed -i "/^$username /d" "$LIMITER_DATABASE" 2>/dev/null
            echo "$username $limit" >> "$LIMITER_DATABASE"
            
            echo -e "\n${GREEN}✓ Added $username with limit $limit${RESET}"
            sleep 2
            ;;
        2)
            if [[ -s "$LIMITER_DATABASE" ]]; then
                echo -e "\n${WHITE}Current users:${RESET}"
                nl -w2 -s ') ' "$LIMITER_DATABASE"
                echo ""
                read -p "Enter username to remove: " username
                
                if grep -q "^$username " "$LIMITER_DATABASE"; then
                    sed -i "/^$username /d" "$LIMITER_DATABASE"
                    echo -e "\n${GREEN}✓ Removed $username${RESET}"
                else
                    echo -e "\n${RED}User not found${RESET}"
                fi
            else
                echo -e "\n${YELLOW}Database is empty${RESET}"
            fi
            sleep 2
            ;;
        3)
            echo -e "\n${WHITE}Current database contents:${RESET}"
            echo -e "${BLUE}=========================${RESET}"
            if [[ -s "$LIMITER_DATABASE" ]]; then
                cat "$LIMITER_DATABASE"
            else
                echo "Database is empty"
            fi
            echo ""
            read -p "Press Enter to continue..."
            ;;
        4)
            if [[ -s "$USER_LIST_FILE" ]]; then
                echo -e "\n${YELLOW}Importing from main database...${RESET}"
                while IFS=: read -r username limit; do
                    [[ -z "$username" ]] && continue
                    # Remove existing entry and add new one
                    sed -i "/^$username /d" "$LIMITER_DATABASE" 2>/dev/null
                    echo "$username $limit" >> "$LIMITER_DATABASE"
  done < "$USER_LIST_FILE"
                echo -e "${GREEN}✓ Import completed${RESET}"
            else
                echo -e "\n${RED}Main database not found${RESET}"
            fi
            sleep 2
            ;;
        5)
            echo -e "\n${YELLOW}Auto-Setup & Start Limiter...${RESET}"
            echo -e "${WHITE}This will:${RESET}"
            echo -e "${WHITE}• Import all users from main database${RESET}"
            echo -e "${WHITE}• Start the User Limiter automatically${RESET}"
            echo ""
            read -p "Continue? (y/n): " confirm
            
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                # Import from main database
                if [[ -s "$USER_LIST_FILE" ]]; then
                    echo -e "\n${YELLOW}Importing users...${RESET}"
                    local imported=0
                    while IFS=: read -r username limit; do
                        [[ -z "$username" || "$limit" == "0" ]] && continue
                        # Remove existing entry and add new one
                        sed -i "/^$username /d" "$LIMITER_DATABASE" 2>/dev/null
                        echo "$username $limit" >> "$LIMITER_DATABASE"
                        ((imported++))
                    done < "$USER_LIST_FILE"
                    echo -e "${GREEN}✓ Imported $imported users with limits${RESET}"
                else
                    echo -e "\n${RED}Main database not found${RESET}"
                    sleep 2
                    return
                fi
                
                # Start the limiter
                echo -e "\n${YELLOW}Starting User Limiter...${RESET}"
                sleep 1
                
                if ! screen -list | grep -q "$LIMITER_NAME"; then
                    start_limiter
                    echo -e "\n${GREEN}✅ User Limiter is now active and monitoring all users!${RESET}"
                else
                    echo -e "\n${YELLOW}User Limiter is already running${RESET}"
                fi
                
                echo -e "\n${BLUE}🎯 Setup Complete! The limiter will now:${RESET}"
                echo -e "${WHITE}• Monitor all users every ${CHECK_INTERVAL} seconds${RESET}"
                echo -e "${WHITE}• Enforce connection limits automatically${RESET}"
                echo -e "${WHITE}• Kill excess connections when limits exceeded${RESET}"
                echo -e "${WHITE}• Log all violations with timestamps${RESET}"
                echo ""
                read -p "Press Enter to continue..."
            fi
            ;;
    esac
}

# ============================================================================
# BADVPN UDP GATEWAY FUNCTIONS
# ============================================================================

# BadVPN Configuration - Optimized for 2GB RAM Maximum Performance
BADVPN_DEFAULT_PORT="7300"
BADVPN_BINARY="/bin/badvpn-udpgw"
BADVPN_SCREEN_SESSION="udpvpn"
BADVPN_MAX_CLIENTS="4000"
BADVPN_MAX_CONNECTIONS_PER_CLIENT="25"
BADVPN_SOCKET_BUFFER="15000"

# Function to check if BadVPN is running
is_badvpn_running() {
    # Check if systemd service is running
    if systemctl is-active badvpn-udpgw.service >/dev/null 2>&1; then
        return 0
    fi
    
    # Fallback: Check screen session
    if ps x | grep -w "$BADVPN_SCREEN_SESSION" | grep -v grep >/dev/null 2>&1; then
        return 0
    fi
    
    # Also check if badvpn-udpgw process is running
    if pgrep -f "badvpn-udpgw" >/dev/null 2>&1; then
        return 0
    fi
    
    return 1
}

# Function to get BadVPN port
get_badvpn_port() {
    if is_badvpn_running; then
        netstat -nplt 2>/dev/null | grep 'badvpn-ud' | awk '{print $4}' | cut -d: -f2 | head -1
    else
        echo ""
    fi
}

# Function to install BadVPN binary
install_badvpn() {
    if [[ ! -e "$BADVPN_BINARY" ]]; then
        echo -e "${YELLOW}◇ Installing BadVPN UDP Gateway...${RESET}"
        cd "$HOME" || return 1
        
        # Install build dependencies
        apt-get update -y >/dev/null 2>&1
        apt-get install -y build-essential cmake wget tar >/dev/null 2>&1
        
        # Download and compile BadVPN
        if wget -q --timeout=10 "https://github.com/ambrop72/badvpn/archive/master.tar.gz" -O badvpn.tar.gz; then
            echo -e "${GREEN}◇ Download successful, compiling...${RESET}"
            tar -xf badvpn.tar.gz
            cd badvpn-* || return 1
            mkdir build && cd build
            cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
            make
            cp udpgw/badvpn-udpgw "$BADVPN_BINARY"
            chmod +x "$BADVPN_BINARY"
            cd "$HOME" && rm -rf badvpn*
            echo -e "${GREEN}◇ BadVPN installed successfully${RESET}"
        else
            echo -e "${RED}◇ Failed to download BadVPN${RESET}"
            return 1
        fi
    fi
    return 0
}

# Function to create BadVPN systemd service
create_badvpn_systemd_service() {
    local port="${1:-$BADVPN_DEFAULT_PORT}"
    
    # Ensure BadVPN binary exists
    if [[ ! -f "$BADVPN_BINARY" ]]; then
        echo -e "${RED}BadVPN binary not found at $BADVPN_BINARY${RESET}"
        return 1
    fi
    
    # Create systemd service with expanded variables
    cat > /etc/systemd/system/badvpn-udpgw.service << EOF
[Unit]
Description=BadVPN UDP Gateway
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
Group=root
ExecStart=${BADVPN_BINARY} --listen-addr 127.0.0.1:${port} --max-clients ${BADVPN_MAX_CLIENTS} --max-connections-for-client ${BADVPN_MAX_CONNECTIONS_PER_CLIENT} --client-socket-sndbuf ${BADVPN_SOCKET_BUFFER}
Restart=always
RestartSec=5
StartLimitBurst=3
StandardOutput=journal
StandardError=journal
WorkingDirectory=/tmp

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd and enable the service
    systemctl daemon-reload
    systemctl enable badvpn-udpgw.service
}

# Function to start BadVPN
start_badvpn() {
    local port="${1:-$BADVPN_DEFAULT_PORT}"
    
    clear
    display_header_with_timestamp "BADVPN START"
    
    if is_badvpn_running; then
        echo -e "\n${YELLOW}◇ BadVPN is already running!${RESET}"
        sleep 3
        return 1
    fi
    
    echo -e "\n${GREEN}◇ STARTING BADVPN UDP GATEWAY...${RESET}"
    echo ""
    
    # Install if not present
    if ! install_badvpn; then
        sleep 3
        return 1
    fi
    
    # Create and enable systemd service for persistence
    start_badvpn_process() {
        # Verify binary exists and is executable
        if [[ ! -x "$BADVPN_BINARY" ]]; then
            echo -e "${RED}◇ BadVPN binary not found or not executable at $BADVPN_BINARY${RESET}"
            return 1
        fi
        
        # Create systemd service
        if ! create_badvpn_systemd_service "$port"; then
            echo -e "${RED}◇ Failed to create systemd service${RESET}"
            return 1
        fi
        
        # Start the service
        if ! systemctl start badvpn-udpgw.service; then
            echo -e "${YELLOW}◇ Systemd service failed, trying screen session...${RESET}"
            # Fallback to screen session
            if ! screen -list | grep -q "$BADVPN_SCREEN_SESSION"; then
                screen -dmS "$BADVPN_SCREEN_SESSION" "$BADVPN_BINARY" \
                    --listen-addr "127.0.0.1:$port" \
                    --max-clients "$BADVPN_MAX_CLIENTS" \
                    --max-connections-for-client "$BADVPN_MAX_CONNECTIONS_PER_CLIENT" \
                    --client-socket-sndbuf "$BADVPN_SOCKET_BUFFER"
            fi
        else
            echo -e "${GREEN}◇ Systemd service started successfully${RESET}"
        fi
        
        sleep 3
    }
    
    fun_bar 'start_badvpn_process' 'sleep 2'
    
    if is_badvpn_running; then
        echo -e "\n${GREEN}◇ BADVPN SUCCESSFULLY ACTIVATED ON PORT $port!${RESET}"
        echo -e "${WHITE}◇ Session: $BADVPN_SCREEN_SESSION${RESET}"
        echo -e "${WHITE}◇ Max Clients: $BADVPN_MAX_CLIENTS${RESET}"
        echo -e "${CYAN}◇ Persistence: ENABLED (will auto-start after reboot)${RESET}"
    else
        echo -e "\n${RED}◇ FAILED TO START BADVPN!${RESET}"
        echo -e "${YELLOW}◇ Troubleshooting Information:${RESET}"
        echo -e "${WHITE}  - Binary path: $BADVPN_BINARY${RESET}"
        echo -e "${WHITE}  - Binary exists: $(if [[ -f "$BADVPN_BINARY" ]]; then echo "YES"; else echo "NO"; fi)${RESET}"
        echo -e "${WHITE}  - Binary executable: $(if [[ -x "$BADVPN_BINARY" ]]; then echo "YES"; else echo "NO"; fi)${RESET}"
        echo -e "${WHITE}  - Systemd service status: $(systemctl is-active badvpn-udpgw.service 2>/dev/null || echo "not found")${RESET}"
        echo -e "${WHITE}  - Port $port available: $(if netstat -ln | grep ":$port " >/dev/null; then echo "NO (in use)"; else echo "YES"; fi)${RESET}"
    fi
    
    sleep 3
}

# Function to stop BadVPN
stop_badvpn() {
    clear
    display_header_with_timestamp "BADVPN STOP"
    
    echo -e "\n${GREEN}◇ STOPPING BADVPN UDP GATEWAY...${RESET}"
    echo ""
    
    stop_badvpn_process() {
        # Stop and disable systemd service
        systemctl stop badvpn-udpgw.service 2>/dev/null
        systemctl disable badvpn-udpgw.service 2>/dev/null
        
        # Remove systemd service file
        rm -f /etc/systemd/system/badvpn-udpgw.service
        systemctl daemon-reload
        
        # Kill screen sessions
        for pid in $(screen -ls | grep ".$BADVPN_SCREEN_SESSION" | awk '{print $1}'); do
            screen -r -S "$pid" -X quit 2>/dev/null
        done
        
        # Kill any remaining badvpn processes
        pkill -f "badvpn-udpgw" 2>/dev/null
        
        # Clean up screen sessions
        screen -wipe >/dev/null 2>&1
        sleep 1
    }
    
    fun_bar 'stop_badvpn_process' 'sleep 2'
    
    if ! is_badvpn_running; then
        echo -e "\n${GREEN}◇ BADVPN SUCCESSFULLY STOPPED!${RESET}"
        echo -e "${CYAN}◇ Persistence: DISABLED (will NOT auto-start after reboot)${RESET}"
    else
        echo -e "\n${RED}◇ FAILED TO STOP BADVPN!${RESET}"
    fi
    
    sleep 3
}

# Function to show BadVPN status
show_badvpn_status() {
    clear
    display_header_with_timestamp "BADVPN STATUS"
    
    echo -e "\n${BLUE}◇ BADVPN UDP GATEWAY STATUS${RESET}"
    echo -e "${BLUE}============================${RESET}\n"
    
    # Check persistence status
    local persistence_status="DISABLED"
    local persistence_color="${RED}"
    if systemctl is-enabled badvpn-udpgw.service >/dev/null 2>&1; then
        persistence_status="ENABLED"
        persistence_color="${GREEN}"
    fi
    
    if is_badvpn_running; then
        local port=$(get_badvpn_port)
        echo -e "${GREEN}Status: ${WHITE}RUNNING ♦${RESET}"
        echo -e "${GREEN}Port: ${WHITE}${port:-$BADVPN_DEFAULT_PORT}${RESET}"
        echo -e "${GREEN}Session: ${WHITE}$BADVPN_SCREEN_SESSION${RESET}"
        echo -e "${GREEN}Max Clients: ${WHITE}$BADVPN_MAX_CLIENTS${RESET}"
        echo -e "${GREEN}Max Connections/Client: ${WHITE}$BADVPN_MAX_CONNECTIONS_PER_CLIENT${RESET}"
        echo -e "${persistence_color}Persistence: ${WHITE}$persistence_status${RESET}"
        
        # Show process info
        local pid=$(ps aux | grep "$BADVPN_SCREEN_SESSION" | grep -v grep | awk '{print $2}' | head -1)
        if [[ -n "$pid" ]]; then
            local memory=$(ps -p "$pid" -o rss= 2>/dev/null | awk '{print int($1/1024)"MB"}')
            local cpu=$(ps -p "$pid" -o %cpu= 2>/dev/null | awk '{print $1"%"}')
            echo -e "${GREEN}PID: ${WHITE}$pid${RESET}"
            echo -e "${GREEN}Memory Usage: ${WHITE}${memory:-N/A}${RESET}"
            echo -e "${GREEN}CPU Usage: ${WHITE}${cpu:-N/A}${RESET}"
        fi
        
        # Show connections
        local connections=$(netstat -n | grep ":${port:-$BADVPN_DEFAULT_PORT}" | wc -l 2>/dev/null || echo "0")
        echo -e "${GREEN}Active Connections: ${WHITE}$connections${RESET}"
        
    else
        echo -e "${RED}Status: ${WHITE}STOPPED ○${RESET}"
        echo -e "${persistence_color}Persistence: ${WHITE}$persistence_status${RESET}"
        echo ""
        echo -e "${YELLOW}BadVPN is not running${RESET}"
    fi
    
    echo ""
    echo -e "${BLUE}What is BadVPN UDP Gateway?${RESET}"
    echo -e "${WHITE}• Forwards UDP traffic for OpenVPN${RESET}"
    echo -e "${WHITE}• Improves VoIP call quality${RESET}"
    echo -e "${WHITE}• Reduces packet loss for UDP connections${RESET}"
    echo -e "${WHITE}• Essential for UDP-based applications${RESET}"
    
    if [[ "$persistence_status" == "ENABLED" ]]; then
        echo ""
        echo -e "${CYAN}🔄 Auto-Start: BadVPN will automatically start after server reboot${RESET}"
    else
        echo ""
        echo -e "${YELLOW}⚠️  Auto-Start: BadVPN will NOT start after server reboot${RESET}"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Function to change BadVPN port
change_badvpn_port() {
    clear
    display_header_with_timestamp "BADVPN PORT"
    
    if ! is_badvpn_running; then
        echo -e "\n${RED}◇ BADVPN IS NOT RUNNING!${RESET}"
        echo -e "${YELLOW}◇ Please start BadVPN first.${RESET}"
        sleep 3
        return 1
    fi
    
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}          CHANGE BADVPN PORT            ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
    local current_port=$(get_badvpn_port)
    echo -e "${WHITE}Current Port: ${GREEN}${current_port:-$BADVPN_DEFAULT_PORT}${RESET}\n"
    
    read -p "Enter new port (1024-65535): " new_port
    
    if [[ -z "$new_port" ]]; then
        echo -e "\n${RED}◇ Invalid port!${RESET}"
        sleep 2
        return 1
    fi
    
    # Validate port number
    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [[ "$new_port" -lt 1024 ]] || [[ "$new_port" -gt 65535 ]]; then
        echo -e "\n${RED}◇ Invalid port! Please use a port between 1024-65535.${RESET}"
        sleep 3
        return 1
    fi
    
    # Check if port is already in use
    if netstat -ln | grep ":$new_port " >/dev/null 2>&1; then
        echo -e "\n${RED}◇ Port $new_port is already in use!${RESET}"
        sleep 3
        return 1
    fi
    
    echo -e "\n${GREEN}◇ CHANGING BADVPN PORT TO $new_port...${RESET}"
    
    # Stop current instance
    stop_badvpn_process() {
        for pid in $(screen -ls | grep ".$BADVPN_SCREEN_SESSION" | awk '{print $1}'); do
            screen -r -S "$pid" -X quit 2>/dev/null
        done
        sleep 1
    }
    
    fun_bar 'stop_badvpn_process' 'sleep 1'
    
    # Start with new port
    start_badvpn_process() {
        # Update systemd service with new port
        create_badvpn_systemd_service "$new_port"
        systemctl start badvpn-udpgw.service
        
        # Also update screen session
        screen -dmS "$BADVPN_SCREEN_SESSION" "$BADVPN_BINARY" \
            --listen-addr "127.0.0.1:$new_port" \
            --max-clients "$BADVPN_MAX_CLIENTS" \
            --max-connections-for-client "$BADVPN_MAX_CONNECTIONS_PER_CLIENT" \
            --client-socket-sndbuf "$BADVPN_SOCKET_BUFFER"
        
        sleep 2
    }
    
    fun_bar 'start_badvpn_process' 'sleep 2'
    
    if is_badvpn_running; then
        echo -e "\n${GREEN}◇ BADVPN SUCCESSFULLY ACTIVATED ON PORT $new_port!${RESET}"
    else
        echo -e "\n${RED}◇ FAILED TO START BADVPN ON PORT $new_port!${RESET}"
        echo -e "${YELLOW}◇ Trying to restart on default port...${RESET}"
        start_badvpn "$BADVPN_DEFAULT_PORT" >/dev/null 2>&1
    fi
    
    sleep 3
}

# Main BadVPN management function
manage_badvpn() {
    while true; do
        clear
        display_header_with_timestamp "BADVPN MANAGER"
        
        echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
        echo -e "${BLUE}│${WHITE}        ⚡ BADVPN UDP GATEWAY ⚡         ${BLUE}│${RESET}"
        echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
        
        # Show current status
        if is_badvpn_running; then
            local port=$(get_badvpn_port)
            echo -e "${WHITE}Current Status: ${GREEN}RUNNING ♦${RESET}"
            echo -e "${WHITE}Port: ${GREEN}${port:-$BADVPN_DEFAULT_PORT}${RESET}"
            local action_text="STOP BADVPN"
            local action_color="${RED}"
        else
            echo -e "${WHITE}Current Status: ${RED}STOPPED ○${RESET}"
            local action_text="START BADVPN"
            local action_color="${GREEN}"
        fi
        
        echo ""
        echo -e "${RED}[${BLUE}1${RED}] ${WHITE}• ${action_color}$action_text${RESET}"
        echo -e "${RED}[${BLUE}2${RED}] ${WHITE}• ${YELLOW}CHANGE PORT${RESET}"
        echo -e "${RED}[${BLUE}3${RED}] ${WHITE}• ${YELLOW}VIEW STATUS & INFO${RESET}"
        echo -e "${RED}[${BLUE}4${RED}] ${WHITE}• ${YELLOW}VIEW LOGS${RESET}"
        echo -e "${RED}[${BLUE}0${RED}] ${WHITE}• ${YELLOW}BACK TO MAIN MENU${RESET}"
        echo ""
        echo -ne "${GREEN}What do you want to do${YELLOW}? ${WHITE}"
        read choice
        
        case "$choice" in
            1)
                if is_badvpn_running; then
                    stop_badvpn
                else
                    start_badvpn
                fi
                ;;
            2)
                change_badvpn_port
                ;;
            3)
                show_badvpn_status
                ;;
            4)
                if is_badvpn_running; then
                    echo ""
                    echo -e "${GREEN}◇ Connecting to BadVPN logs...${RESET}"
                    echo -e "${YELLOW}◇ Press Ctrl+A then D to detach${RESET}"
                    sleep 2
                    screen -r "$BADVPN_SCREEN_SESSION"
                else
                    echo ""
                    echo -e "${RED}◇ BadVPN is not running!${RESET}"
                    sleep 2
                fi
                ;;
            0)
                return
                ;;
            *)
                echo -e "\n${RED}Invalid option!${RESET}"
                sleep 2
                ;;
        esac
    done
}

# ============================================================================
# BANNER MESSAGE CREATOR FUNCTIONS
# ============================================================================

# Banner configuration paths
MOTD_FILE="/etc/motd"
ISSUE_FILE="/etc/issue.net"
SSH_BANNER_FILE="/etc/ssh/ssh_banner"

# Function to get color code for banners
get_banner_color_code() {
    local color_choice="$1"
    
    case "$color_choice" in
        "1"|"red")     echo "\033[1;31m" ;;
        "2"|"green")   echo "\033[1;32m" ;;
        "3"|"yellow")  echo "\033[1;33m" ;;
        "4"|"blue")    echo "\033[1;34m" ;;
        "5"|"magenta") echo "\033[1;35m" ;;
        "6"|"cyan")    echo "\033[1;36m" ;;
        "7"|"white")   echo "\033[1;37m" ;;
        "8"|"orange")  echo "\033[1;91m" ;;
        "9"|"purple")  echo "\033[1;95m" ;;
        "10"|"lime")   echo "\033[1;92m" ;;
        *)             echo "\033[1;37m" ;; # Default to white
    esac
}

# Function to display color selection menu
show_color_menu() {
    echo -e "\n${BLUE}┌─────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}           SELECT BANNER COLOR           ${BLUE}│${RESET}"
    echo -e "${BLUE}└─────────────────────────────────────────┘${RESET}\n"
    
    echo -e "${RED}1)${RESET} ${RED}■${RESET} Red"
    echo -e "${GREEN}2)${RESET} ${GREEN}■${RESET} Green"
    echo -e "${YELLOW}3)${RESET} ${YELLOW}■${RESET} Yellow"
    echo -e "${BLUE}4)${RESET} ${BLUE}■${RESET} Blue"
    echo -e "${MAGENTA}5)${RESET} ${MAGENTA}■${RESET} Magenta"
    echo -e "${CYAN}6)${RESET} ${CYAN}■${RESET} Cyan"
    echo -e "${WHITE}7)${RESET} ${WHITE}■${RESET} White"
    echo -e "\033[1;91m8)\033[0m \033[1;91m■\033[0m Orange"
    echo -e "\033[1;95m9)\033[0m \033[1;95m■\033[0m Purple"
    echo -e "\033[1;92m10)\033[0m \033[1;92m■\033[0m Lime"
    echo ""
}

# Function to create ASCII art banner with color (SSH-compatible)
create_ascii_banner() {
    local text="$1"
    local style="$2"
    local color_code="${3:-}" # Color code parameter
    
    # For SSH banners, we'll use simple text without ANSI codes
    # The color will be handled by the terminal's interpretation
    case "$style" in
        "1"|"basic")
            echo "============================================"
            echo "          $text"
            echo "============================================"
            ;;
        "2"|"stars")
            echo "********************************************"
            echo "***          $text          ***"
            echo "********************************************"
            ;;
        "3"|"double")
            echo "╔══════════════════════════════════════════╗"
            echo "║          $text           ║"
            echo "╚══════════════════════════════════════════╝"
            ;;
        "4"|"diamond")
            echo "◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇"
            echo "◇          $text           ◇"
            echo "◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇"
            ;;
        "5"|"fire")
            echo "🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥"
            echo "🔥          $text           🔥"
            echo "🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥"
            ;;
        *)
            echo "============================================"
            echo "          $text"
            echo "============================================"
            ;;
    esac
}

# Function to create ASCII art banner with color for terminal display
create_ascii_banner_colored() {
    local text="$1"
    local style="$2"
    local color_code="${3:-\033[1;37m}" # Default to white if no color specified
    local reset_code="\033[0m"
    
    case "$style" in
        "1"|"basic")
            echo -e "${color_code}============================================${reset_code}"
            echo -e "${color_code}          $text${reset_code}"
            echo -e "${color_code}============================================${reset_code}"
            ;;
        "2"|"stars")
            echo -e "${color_code}********************************************${reset_code}"
            echo -e "${color_code}***          $text          ***${reset_code}"
            echo -e "${color_code}********************************************${reset_code}"
            ;;
        "3"|"double")
            echo -e "${color_code}╔══════════════════════════════════════════╗${reset_code}"
            echo -e "${color_code}║          $text           ║${reset_code}"
            echo -e "${color_code}╚══════════════════════════════════════════╝${reset_code}"
            ;;
        "4"|"diamond")
            echo -e "${color_code}◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇${reset_code}"
            echo -e "${color_code}◇          $text           ◇${reset_code}"
            echo -e "${color_code}◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇◆◇${reset_code}"
            ;;
        "5"|"fire")
            echo -e "${color_code}🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥${reset_code}"
            echo -e "${color_code}🔥          $text           🔥${reset_code}"
            echo -e "${color_code}🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥${reset_code}"
            ;;
        *)
            echo -e "${color_code}============================================${reset_code}"
            echo -e "${color_code}          $text${reset_code}"
            echo -e "${color_code}============================================${reset_code}"
            ;;
    esac
}

# Function to create system info banner (SSH-compatible)
create_system_info_banner() {
    local color_code="${1:-}" # Color parameter (not used in SSH banners)
    local hostname=$(hostname)
    local os_info=$(lsb_release -d 2>/dev/null | cut -f2 || echo "Linux Server")
    local kernel=$(uname -r)
    local uptime=$(uptime -p 2>/dev/null || uptime | awk '{print $3,$4}')
    local load_avg=$(uptime | awk -F'load average:' '{print $2}')
    local memory=$(free -h | grep Mem | awk '{print $3"/"$2}')
    
    cat << EOF
╔══════════════════════════════════════════════════════════════╗
║                    WELCOME TO $hostname                    ║
╠══════════════════════════════════════════════════════════════╣
║ OS Info    : $os_info
║ Kernel     : $kernel  
║ Uptime     : $uptime
║ Load Avg   : $load_avg
║ Memory     : $memory
╚══════════════════════════════════════════════════════════════╝
EOF
}

# Function to create system info banner with color for terminal display
create_system_info_banner_colored() {
    local color_code="${1:-\033[1;37m}" # Default to white if no color specified
    local reset_code="\033[0m"
    local hostname=$(hostname)
    local os_info=$(lsb_release -d 2>/dev/null | cut -f2 || echo "Linux Server")
    local kernel=$(uname -r)
    local uptime=$(uptime -p 2>/dev/null || uptime | awk '{print $3,$4}')
    local load_avg=$(uptime | awk -F'load average:' '{print $2}')
    local memory=$(free -h | grep Mem | awk '{print $3"/"$2}')
    
    cat << EOF
${color_code}╔══════════════════════════════════════════════════════════════╗${reset_code}
${color_code}║                    WELCOME TO $hostname                    ║${reset_code}
${color_code}╠══════════════════════════════════════════════════════════════╣${reset_code}
${color_code}║ OS Info    : $os_info${reset_code}
${color_code}║ Kernel     : $kernel${reset_code}  
${color_code}║ Uptime     : $uptime${reset_code}
${color_code}║ Load Avg   : $load_avg${reset_code}
${color_code}║ Memory     : $memory${reset_code}
${color_code}╚══════════════════════════════════════════════════════════════╝${reset_code}
EOF
}

# Function to manage SSH banner
manage_ssh_banner() {
    while true; do
        clear
        display_header_with_timestamp "SSH BANNER MANAGER"
        
        echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
        echo -e "${BLUE}│${WHITE}         SSH BANNER CREATOR            ${BLUE}│${RESET}"
        echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
        
        # Show current banner status
        if [[ -f "$SSH_BANNER_FILE" ]]; then
            echo -e "${WHITE}Current SSH Banner: ${GREEN}ACTIVE${RESET}"
            echo -e "${YELLOW}Preview:${RESET}"
            echo -e "${CYAN}$(head -5 "$SSH_BANNER_FILE")${RESET}"
            if [[ $(wc -l < "$SSH_BANNER_FILE") -gt 5 ]]; then
                echo -e "${GRAY}... (truncated)${RESET}"
            fi
        else
            echo -e "${WHITE}Current SSH Banner: ${RED}NOT SET${RESET}"
        fi
        
        echo ""
        echo -e "${RED}[${BLUE}1${RED}] ${WHITE}• ${GREEN}Create Custom Text Banner${RESET}"
        echo -e "${RED}[${BLUE}2${RED}] ${WHITE}• ${GREEN}Create System Info Banner${RESET}"
        echo -e "${RED}[${BLUE}3${RED}] ${WHITE}• ${YELLOW}Edit Banner Manually${RESET}"
        echo -e "${RED}[${BLUE}4${RED}] ${WHITE}• ${CYAN}Preview Current Banner${RESET}"
        echo -e "${RED}[${BLUE}5${RED}] ${WHITE}• ${BLUE}Apply Banner to SSH${RESET}"
        echo -e "${RED}[${BLUE}6${RED}] ${WHITE}• ${RED}Remove SSH Banner${RESET}"
        echo -e "${RED}[${BLUE}0${RED}] ${WHITE}• ${YELLOW}BACK TO MAIN MENU${RESET}"
        echo ""
        echo -ne "${GREEN}What do you want to do${YELLOW}? ${WHITE}"
        read choice
        
        case "$choice" in
            1)
                create_custom_banner
                ;;
            2)
                create_system_banner
                ;;
            3)
                edit_banner_manually
                ;;
            4)
                preview_banner
                ;;
            5)
                apply_ssh_banner
                ;;
            6)
                remove_ssh_banner
                ;;
            0)
                return
                ;;
            *)
                echo -e "\n${RED}Invalid option!${RESET}"
                sleep 2
                ;;
        esac
    done
}

# Function to create custom text banner
create_custom_banner() {
    clear
    display_header_with_timestamp "CUSTOM BANNER CREATOR"
    
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}         CREATE CUSTOM BANNER           ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
    echo -e "${WHITE}Enter your banner text:${RESET}"
    read -p "Banner Title: " banner_title
    
    if [[ -z "$banner_title" ]]; then
        echo -e "\n${RED}Banner title cannot be empty!${RESET}"
        sleep 2
        return
    fi
    
    echo -e "\n${WHITE}Choose banner style:${RESET}"
    echo -e "${CYAN}1) Basic Lines${RESET}"
    echo -e "${CYAN}2) Stars${RESET}"
    echo -e "${CYAN}3) Double Lines${RESET}"
    echo -e "${CYAN}4) Diamonds${RESET}"
    echo -e "${CYAN}5) Fire Emojis${RESET}"
    echo ""
    read -p "Select style [1-5]: " style_choice
    
    # Show color selection menu
    show_color_menu
    read -p "Color choice [1-10]: " color_choice
    
    # Get the color code
    local selected_color=$(get_banner_color_code "$color_choice")
    
    echo -e "\n${WHITE}Additional message (optional):${RESET}"
    read -p "Welcome message: " welcome_msg
    
    # Create banner without color codes for SSH compatibility
    {
        create_ascii_banner "$banner_title" "$style_choice"
        echo ""
        if [[ -n "$welcome_msg" ]]; then
            echo "$welcome_msg"
            echo ""
        fi
    } > "$SSH_BANNER_FILE"
    
    echo -e "\n${GREEN}✓ Custom banner created successfully!${RESET}"
    echo -e "${YELLOW}Preview (with colors for demonstration):${RESET}"
    # Show colored preview in terminal
    create_ascii_banner_colored "$banner_title" "$style_choice" "$selected_color"
    if [[ -n "$welcome_msg" ]]; then
        echo -e "${selected_color}$welcome_msg\033[0m"
    fi
    
    echo ""
    read -p "Apply this banner to SSH? (y/n): " apply_choice
    if [[ "$apply_choice" =~ ^[Yy]$ ]]; then
        apply_ssh_banner
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Function to create system info banner
create_system_banner() {
    clear
    display_header_with_timestamp "SYSTEM INFO BANNER"
    
    # Show color selection menu
    show_color_menu
    read -p "Color choice [1-10]: " color_choice
    
    # Get the color code
    local selected_color=$(get_banner_color_code "$color_choice")
    
    echo -e "\n${GREEN}Creating system information banner...${RESET}"
    
    # Create plain banner for SSH compatibility
    create_system_info_banner > "$SSH_BANNER_FILE"
    
    echo -e "\n${GREEN}✓ System info banner created successfully!${RESET}"
    echo -e "${YELLOW}Preview (with colors for demonstration):${RESET}"
    # Show colored preview in terminal
    create_system_info_banner_colored "$selected_color"
    
    echo ""
    read -p "Apply this banner to SSH? (y/n): " apply_choice
    if [[ "$apply_choice" =~ ^[Yy]$ ]]; then
        apply_ssh_banner
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Function to edit banner manually
edit_banner_manually() {
    clear
    display_header_with_timestamp "EDIT BANNER"
    
    echo -e "\n${BLUE}Manual Banner Editor${RESET}"
    echo -e "${YELLOW}Opening nano editor...${RESET}"
    echo -e "${WHITE}Press Ctrl+X to save and exit${RESET}"
    sleep 2
    
    if [[ ! -f "$SSH_BANNER_FILE" ]]; then
        echo "# SSH Login Banner - Edit as needed" > "$SSH_BANNER_FILE"
    fi
    
    nano "$SSH_BANNER_FILE"
    
    echo -e "\n${GREEN}Banner editing completed!${RESET}"
    sleep 2
}

# Function to preview current banner
preview_banner() {
    clear
    display_header_with_timestamp "BANNER PREVIEW"
    
    if [[ -f "$SSH_BANNER_FILE" ]]; then
        echo -e "\n${YELLOW}Current Banner Preview:${RESET}"
        echo -e "${BLUE}═══════════════════════════════════════${RESET}"
        echo -e "${CYAN}$(cat "$SSH_BANNER_FILE")${RESET}"
        echo -e "${BLUE}═══════════════════════════════════════${RESET}"
    else
        echo -e "\n${RED}No banner file found!${RESET}"
        echo -e "${YELLOW}Create a banner first using options 1 or 2.${RESET}"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Function to apply SSH banner
apply_ssh_banner() {
    if [[ ! -f "$SSH_BANNER_FILE" ]]; then
        echo -e "\n${RED}No banner file found! Create one first.${RESET}"
        sleep 2
        return
    fi
    
    echo -e "\n${GREEN}Applying SSH banner...${RESET}"
    
    # Copy banner to system locations
    cp "$SSH_BANNER_FILE" "$MOTD_FILE"
    cp "$SSH_BANNER_FILE" "$ISSUE_FILE"
    
    # Configure SSH to show banner
    if ! grep -q "Banner $SSH_BANNER_FILE" /etc/ssh/sshd_config; then
        echo "Banner $SSH_BANNER_FILE" >> /etc/ssh/sshd_config
    fi
    
    # Restart SSH service
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
    
    echo -e "${GREEN}✓ SSH banner applied successfully!${RESET}"
    echo -e "${WHITE}Users will see this banner when they log in via SSH.${RESET}"
    
    sleep 3
}

# Function to remove SSH banner
remove_ssh_banner() {
    clear
    display_header_with_timestamp "REMOVE BANNER"
    
    echo -e "\n${RED}Remove SSH Banner${RESET}"
    echo -e "${YELLOW}This will remove all custom SSH banners.${RESET}"
    echo ""
    read -p "Are you sure? (y/n): " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        # Remove banner files
        rm -f "$SSH_BANNER_FILE" "$MOTD_FILE" "$ISSUE_FILE"
        
        # Remove banner configuration from SSH
        sed -i '/^Banner /d' /etc/ssh/sshd_config
        
        # Restart SSH service
        systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
        
        echo -e "\n${GREEN}✓ SSH banner removed successfully!${RESET}"
    else
        echo -e "\n${YELLOW}Banner removal cancelled.${RESET}"
    fi
    
    sleep 2
}

#################################################################
# SQUID PROXY MANAGEMENT
#################################################################

# Check if Squid is installed
is_squid_installed() {
    command -v squid >/dev/null 2>&1
}

# Check if Squid is running
is_squid_running() {
    systemctl is-active --quiet squid 2>/dev/null
}

# Install Squid Proxy with SSL/TLS support
install_squid() {
    clear
    display_header_with_timestamp "SQUID PROXY INSTALLER"
    
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}      SQUID PROXY SSL/TLS SETUP        ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
    if is_squid_installed; then
        echo -e "${YELLOW}⚠️  Squid is already installed!${RESET}\n"
        read -p "Do you want to reinstall/reconfigure? (y/n): " reinstall
        [[ ! "$reinstall" =~ ^[Yy]$ ]] && return
    fi
    
    echo -e "${WHITE}Installing Squid Proxy with SSL support...${RESET}\n"
    
    # Install Squid
    apt-get update >/dev/null 2>&1
    apt-get install -y squid squid-openssl apache2-utils >/dev/null 2>&1
    
    # Get configuration details
    read -p "Enter Squid proxy port (default: 3128): " SQUID_PORT
    SQUID_PORT=${SQUID_PORT:-3128}
    
    read -p "Enter SSL/TLS proxy port (default: 3129): " SQUID_SSL_PORT
    SQUID_SSL_PORT=${SQUID_SSL_PORT:-3129}
    
    read -p "Enable authentication? (y/n): " enable_auth
    
    if [[ "$enable_auth" =~ ^[Yy]$ ]]; then
        read -p "Enter proxy username: " PROXY_USER
        read -s -p "Enter proxy password: " PROXY_PASS
        echo ""
        
        # Create password file
        htpasswd -bc /etc/squid/passwd "$PROXY_USER" "$PROXY_PASS" >/dev/null 2>&1
        chmod 640 /etc/squid/passwd
        chown proxy:proxy /etc/squid/passwd 2>/dev/null
    fi
    
    # Reuse stunnel certificate or create new one
    if [[ -f "/etc/stunnel/stunnel.pem" ]]; then
        echo -e "\n${GREEN}✓ Using existing stunnel certificate${RESET}"
        cp /etc/stunnel/stunnel.pem /etc/squid/squid.pem
    else
        echo -e "\n${YELLOW}Creating SSL certificate for Squid...${RESET}"
        openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes \
            -subj "/C=US/ST=State/L=City/O=MK-Script/OU=Proxy/CN=$(hostname)" \
            -keyout /tmp/squid-key.pem -out /tmp/squid-cert.pem >/dev/null 2>&1
        cat /tmp/squid-key.pem /tmp/squid-cert.pem > /etc/squid/squid.pem
        rm -f /tmp/squid-key.pem /tmp/squid-cert.pem
    fi
    
    chmod 600 /etc/squid/squid.pem
    chown proxy:proxy /etc/squid/squid.pem 2>/dev/null
    
    # Backup original config
    cp /etc/squid/squid.conf /etc/squid/squid.conf.backup 2>/dev/null
    
    # Create optimized Squid configuration
    cat > /etc/squid/squid.conf << EOF
# MK Script Manager - Squid Proxy Configuration with SSL/TLS
# High-performance HTTP/HTTPS proxy with SSL bump

# Network Configuration
http_port $SQUID_PORT
https_port $SQUID_SSL_PORT cert=/etc/squid/squid.pem

# SSL Bump Configuration (HTTPS interception)
ssl_bump server-first all
sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/lib/ssl_db -M 20MB
sslcrtd_children 5
ssl_bump bump all

# ACLs (Access Control Lists)
acl SSL_ports port 443
acl Safe_ports port 80          # HTTP
acl Safe_ports port 21          # FTP
acl Safe_ports port 443         # HTTPS
acl Safe_ports port 70          # Gopher
acl Safe_ports port 210         # WAIS
acl Safe_ports port 1025-65535  # Unregistered ports
acl Safe_ports port 280         # HTTP-MGMT
acl Safe_ports port 488         # GSS-HTTP
acl Safe_ports port 591         # FileMaker
acl Safe_ports port 777         # Multiling HTTP
acl CONNECT method CONNECT

# Access Rules
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost manager
http_access deny manager

EOF

    if [[ "$enable_auth" =~ ^[Yy]$ ]]; then
        cat >> /etc/squid/squid.conf << EOF
# Authentication
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic children 5
auth_param basic realm Squid Proxy Server
auth_param basic credentialsttl 2 hours
acl authenticated proxy_auth REQUIRED
http_access allow authenticated

EOF
    else
        cat >> /etc/squid/squid.conf << EOF
# Allow all access (no authentication)
http_access allow all

EOF
    fi
    
    cat >> /etc/squid/squid.conf << EOF
# Performance Tuning
cache_mem 256 MB
maximum_object_size_in_memory 512 KB
cache_dir ufs /var/spool/squid 2000 16 256
maximum_object_size 100 MB
cache_swap_low 90
cache_swap_high 95

# Connection Limits
client_lifetime 1 hour
half_closed_clients off
pconn_timeout 60 seconds
request_timeout 60 seconds

# Logging
access_log /var/log/squid/access.log squid
cache_log /var/log/squid/cache.log
cache_store_log none

# Anonymity & Privacy
forwarded_for delete
request_header_access Via deny all
request_header_access X-Forwarded-For deny all

# DNS
dns_nameservers 8.8.8.8 8.8.4.4 1.1.1.1

# Miscellaneous
coredump_dir /var/spool/squid
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320
EOF

    # Initialize SSL certificate database
    if [[ ! -d "/var/lib/ssl_db" ]]; then
        /usr/lib/squid/security_file_certgen -c -s /var/lib/ssl_db -M 20MB >/dev/null 2>&1
        chown -R proxy:proxy /var/lib/ssl_db 2>/dev/null
    fi
    
    # Initialize cache directories
    squid -z >/dev/null 2>&1
    
    # Start and enable Squid
    systemctl restart squid
    systemctl enable squid >/dev/null 2>&1
    
    # Verify installation
    sleep 2
    if is_squid_running; then
        echo -e "\n${GREEN}═══════════════════════════════════════${RESET}"
        echo -e "${GREEN}✓ SQUID PROXY INSTALLED SUCCESSFULLY!${RESET}"
        echo -e "${GREEN}═══════════════════════════════════════${RESET}\n"
        echo -e "${WHITE}Configuration Details:${RESET}"
        echo -e "${BLUE}• HTTP Proxy Port:${WHITE} $SQUID_PORT${RESET}"
        echo -e "${BLUE}• HTTPS/SSL Port:${WHITE} $SQUID_SSL_PORT${RESET}"
        if [[ "$enable_auth" =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}• Authentication:${WHITE} Enabled${RESET}"
            echo -e "${BLUE}• Username:${WHITE} $PROXY_USER${RESET}"
        else
            echo -e "${BLUE}• Authentication:${WHITE} Disabled (Open Proxy)${RESET}"
        fi
        echo -e "${BLUE}• SSL/TLS:${WHITE} Enabled with certificate${RESET}"
        echo -e "${BLUE}• Status:${WHITE} Running${RESET}"
        echo -e "\n${YELLOW}Client Configuration:${RESET}"
        echo -e "${WHITE}Proxy Server:${RESET} $(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')"
        echo -e "${WHITE}HTTP Port:${RESET} $SQUID_PORT"
        echo -e "${WHITE}HTTPS Port:${RESET} $SQUID_SSL_PORT"
    else
        echo -e "\n${RED}✗ Squid installation completed but service is not running${RESET}"
        echo -e "${YELLOW}Check logs: journalctl -u squid -n 50${RESET}"
    fi
    
    sleep 3
}

# Uninstall Squid Proxy
uninstall_squid() {
    clear
    display_header_with_timestamp "SQUID UNINSTALLER"
    
    echo -e "\n${RED}⚠️  WARNING: This will completely remove Squid Proxy${RESET}\n"
    read -p "Are you sure? Type 'yes' to confirm: " confirm
    
    if [[ "$confirm" == "yes" ]]; then
        echo -e "\n${YELLOW}Uninstalling Squid Proxy...${RESET}\n"
        
        systemctl stop squid 2>/dev/null
        systemctl disable squid 2>/dev/null
        apt-get remove --purge -y squid squid-openssl >/dev/null 2>&1
        rm -rf /etc/squid /var/spool/squid /var/log/squid /var/lib/ssl_db
        
        echo -e "${GREEN}✓ Squid Proxy uninstalled successfully${RESET}"
    else
        echo -e "${YELLOW}Uninstall cancelled${RESET}"
    fi
    
    sleep 2
}

# Show Squid status and statistics
show_squid_status() {
    clear
    display_header_with_timestamp "SQUID PROXY STATUS"
    
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}        SQUID PROXY STATUS              ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
    if ! is_squid_installed; then
        echo -e "${RED}✗ Squid is not installed${RESET}\n"
        return
    fi
    
    # Service status
    if is_squid_running; then
        echo -e "${GREEN}● Service Status: Running${RESET}"
    else
        echo -e "${RED}● Service Status: Stopped${RESET}"
    fi
    
    # Get configuration details
    if [[ -f "/etc/squid/squid.conf" ]]; then
        HTTP_PORT=$(grep "^http_port" /etc/squid/squid.conf | awk '{print $2}' | head -1)
        HTTPS_PORT=$(grep "^https_port" /etc/squid/squid.conf | awk '{print $2}' | head -1)
        
        echo -e "${WHITE}● HTTP Port: ${BLUE}$HTTP_PORT${RESET}"
        echo -e "${WHITE}● HTTPS Port: ${BLUE}$HTTPS_PORT${RESET}"
        
        if grep -q "auth_param" /etc/squid/squid.conf; then
            echo -e "${WHITE}● Authentication: ${GREEN}Enabled${RESET}"
        else
            echo -e "${WHITE}● Authentication: ${YELLOW}Disabled${RESET}"
        fi
    fi
    
    # Show active connections
    if is_squid_running; then
        ACTIVE_CONN=$(netstat -tn | grep ":$HTTP_PORT" | grep ESTABLISHED | wc -l 2>/dev/null || echo "0")
        echo -e "${WHITE}● Active Connections: ${GREEN}$ACTIVE_CONN${RESET}"
    fi
    
    # Cache statistics
    if [[ -d "/var/spool/squid" ]]; then
        CACHE_SIZE=$(du -sh /var/spool/squid 2>/dev/null | awk '{print $1}')
        echo -e "${WHITE}● Cache Size: ${BLUE}$CACHE_SIZE${RESET}"
    fi
    
    # Recent access log entries
    if [[ -f "/var/log/squid/access.log" ]]; then
        echo -e "\n${YELLOW}Recent Access Log (Last 10 entries):${RESET}"
        echo -e "${BLUE}═══════════════════════════════════════${RESET}"
        tail -n 10 /var/log/squid/access.log 2>/dev/null | while read line; do
            echo -e "${WHITE}$line${RESET}"
        done
    fi
    
    echo -e "\n${WHITE}Press Enter to continue...${RESET}"
    read
}

# Squid management menu
manage_squid() {
    while true; do
        clear
        display_header_with_timestamp "SQUID PROXY MANAGER"
        
        echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
        echo -e "${BLUE}│${WHITE}       SQUID PROXY MANAGEMENT           ${BLUE}│${RESET}"
        echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
        
        # Status indicator
        if is_squid_installed; then
            if is_squid_running; then
                echo -e "${GREEN}● Status: RUNNING${RESET}\n"
            else
                echo -e "${RED}● Status: STOPPED${RESET}\n"
            fi
        else
            echo -e "${YELLOW}● Status: NOT INSTALLED${RESET}\n"
        fi
        
        echo -e "${RED}[${BLUE}1${RED}] ${WHITE}◇ ${GREEN}Install Squid Proxy${RESET}"
        echo -e "${RED}[${BLUE}2${RED}] ${WHITE}◇ ${BLUE}View Status & Stats${RESET}"
        echo -e "${RED}[${BLUE}3${RED}] ${WHITE}◇ ${YELLOW}Start/Stop Service${RESET}"
        echo -e "${RED}[${BLUE}4${RED}] ${WHITE}◇ ${RED}Uninstall Squid${RESET}"
        echo -e "${RED}[${BLUE}0${RED}] ${WHITE}◇ ${YELLOW}Back to Main Menu${RESET}"
        
        echo ""
        echo -e "\033[0;34m◇───────────────────────────────────────◇${RESET}"
        echo ""
        echo -ne "${GREEN}◇ SELECT OPTION ${YELLOW}❯ ${WHITE}"
        read choice
        
        case "$choice" in
            1)
                install_squid
                ;;
            2)
                show_squid_status
                ;;
            3)
                if is_squid_running; then
                    systemctl stop squid
                    echo -e "\n${YELLOW}Squid service stopped${RESET}"
                else
                    systemctl start squid
                    echo -e "\n${GREEN}Squid service started${RESET}"
                fi
                sleep 2
                ;;
            4)
                uninstall_squid
                ;;
            0)
                return
                ;;
            *)
                echo -e "${RED}Invalid option${RESET}"
                sleep 1
                ;;
        esac
    done
}

#################################################################
# SHADOWSOCKS MANAGEMENT
#################################################################

# Check if Shadowsocks is installed
is_shadowsocks_installed() {
    command -v ss-server >/dev/null 2>&1
}

# Check if Shadowsocks is running
is_shadowsocks_running() {
    screen -list | grep -q "shadowsocks"
}

# Install Shadowsocks-libev with SSL/TLS plugin
install_shadowsocks() {
    clear
    display_header_with_timestamp "SHADOWSOCKS INSTALLER"
    
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}    SHADOWSOCKS SSL/TLS SETUP          ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
    if is_shadowsocks_installed; then
        echo -e "${YELLOW}⚠️  Shadowsocks is already installed!${RESET}\n"
        read -p "Do you want to reinstall/reconfigure? (y/n): " reinstall
        [[ ! "$reinstall" =~ ^[Yy]$ ]] && return
    fi
    
    echo -e "${WHITE}Installing Shadowsocks-libev...${RESET}\n"
    
    # Install Shadowsocks-libev and dependencies
    apt-get update >/dev/null 2>&1
    apt-get install -y shadowsocks-libev simple-obfs >/dev/null 2>&1
    
    # Get configuration
    read -p "Enter Shadowsocks port (default: 8388): " SS_PORT
    SS_PORT=${SS_PORT:-8388}
    
    read -s -p "Enter password: " SS_PASSWORD
    echo ""
    [[ -z "$SS_PASSWORD" ]] && SS_PASSWORD=$(< /dev/urandom tr -dc 'A-Za-z0-9' | head -c16)
    
    echo -e "\n${WHITE}Select encryption method:${RESET}"
    echo "1) aes-256-gcm (Recommended - Fast & Secure)"
    echo "2) chacha20-ietf-poly1305 (Mobile Optimized)"
    echo "3) xchacha20-ietf-poly1305 (Maximum Security)"
    read -p "Choice [1-3]: " encrypt_choice
    
    case $encrypt_choice in
        2) SS_METHOD="chacha20-ietf-poly1305" ;;
        3) SS_METHOD="xchacha20-ietf-poly1305" ;;
        *) SS_METHOD="aes-256-gcm" ;;
    esac
    
    read -p "Enable simple-obfs plugin? (y/n): " enable_obfs
    
    # Create configuration directory
    mkdir -p /etc/shadowsocks-libev
    
    # Create Shadowsocks configuration
    cat > /etc/shadowsocks-libev/config.json << EOF
{
    "server":"0.0.0.0",
    "server_port":$SS_PORT,
    "password":"$SS_PASSWORD",
    "timeout":300,
    "method":"$SS_METHOD",
    "fast_open":true,
    "reuse_port":true,
    "no_delay":true,
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp"
EOF

    if [[ "$enable_obfs" =~ ^[Yy]$ ]]; then
        cat >> /etc/shadowsocks-libev/config.json << EOF
,
    "plugin":"obfs-server",
    "plugin_opts":"obfs=tls;fast-open;t=400"
EOF
    fi

    cat >> /etc/shadowsocks-libev/config.json << EOF
}
EOF

    # Create systemd service
    cat > /etc/systemd/system/shadowsocks.service << EOF
[Unit]
Description=Shadowsocks-libev Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/ss-server -c /etc/shadowsocks-libev/config.json
Restart=on-abort
User=nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
EOF

    # Enable and start service
    systemctl daemon-reload
    systemctl enable shadowsocks >/dev/null 2>&1
    systemctl restart shadowsocks
    
    # Verify installation
    sleep 2
    if systemctl is-active --quiet shadowsocks; then
        SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
        
        echo -e "\n${GREEN}═══════════════════════════════════════${RESET}"
        echo -e "${GREEN}✓ SHADOWSOCKS INSTALLED SUCCESSFULLY!${RESET}"
        echo -e "${GREEN}═══════════════════════════════════════${RESET}\n"
        echo -e "${WHITE}Configuration Details:${RESET}"
        echo -e "${BLUE}• Server:${WHITE} $SERVER_IP${RESET}"
        echo -e "${BLUE}• Port:${WHITE} $SS_PORT${RESET}"
        echo -e "${BLUE}• Password:${WHITE} $SS_PASSWORD${RESET}"
        echo -e "${BLUE}• Encryption:${WHITE} $SS_METHOD${RESET}"
        if [[ "$enable_obfs" =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}• Plugin:${WHITE} obfs-server (TLS mode)${RESET}"
        fi
        echo -e "${BLUE}• Protocol:${WHITE} TCP & UDP${RESET}"
        echo -e "${BLUE}• Status:${WHITE} Running${RESET}"
        
        # Generate ss:// URL
        SS_URL_DATA="${SS_METHOD}:${SS_PASSWORD}@${SERVER_IP}:${SS_PORT}"
        SS_URL_ENCODED=$(echo -n "$SS_URL_DATA" | base64 -w0)
        echo -e "\n${YELLOW}Connection URL:${RESET}"
        echo -e "${WHITE}ss://${SS_URL_ENCODED}${RESET}"
        
        # Save configuration for reference
        cat > /root/shadowsocks-info.txt << EOF
Shadowsocks Configuration
=========================
Server: $SERVER_IP
Port: $SS_PORT
Password: $SS_PASSWORD
Encryption: $SS_METHOD
Plugin: $([ "$enable_obfs" = "y" ] && echo "obfs-server (TLS)" || echo "None")

Connection URL:
ss://${SS_URL_ENCODED}
EOF
        
        echo -e "\n${GREEN}✓ Configuration saved to: ${WHITE}/root/shadowsocks-info.txt${RESET}"
    else
        echo -e "\n${RED}✗ Shadowsocks installation completed but service is not running${RESET}"
        echo -e "${YELLOW}Check logs: journalctl -u shadowsocks -n 50${RESET}"
    fi
    
    sleep 3
}

# Uninstall Shadowsocks
uninstall_shadowsocks() {
    clear
    display_header_with_timestamp "SHADOWSOCKS UNINSTALLER"
    
    echo -e "\n${RED}⚠️  WARNING: This will completely remove Shadowsocks${RESET}\n"
    read -p "Are you sure? Type 'yes' to confirm: " confirm
    
    if [[ "$confirm" == "yes" ]]; then
        echo -e "\n${YELLOW}Uninstalling Shadowsocks...${RESET}\n"
        
        systemctl stop shadowsocks 2>/dev/null
        systemctl disable shadowsocks 2>/dev/null
        apt-get remove --purge -y shadowsocks-libev simple-obfs >/dev/null 2>&1
        rm -rf /etc/shadowsocks-libev /etc/systemd/system/shadowsocks.service
        rm -f /root/shadowsocks-info.txt
        systemctl daemon-reload
        
        echo -e "${GREEN}✓ Shadowsocks uninstalled successfully${RESET}"
    else
        echo -e "${YELLOW}Uninstall cancelled${RESET}"
    fi
    
    sleep 2
}

# Show Shadowsocks status
show_shadowsocks_status() {
    clear
    display_header_with_timestamp "SHADOWSOCKS STATUS"
    
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}      SHADOWSOCKS STATUS                ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
    if ! is_shadowsocks_installed; then
        echo -e "${RED}✗ Shadowsocks is not installed${RESET}\n"
        return
    fi
    
    # Service status
    if systemctl is-active --quiet shadowsocks; then
        echo -e "${GREEN}● Service Status: Running${RESET}"
    else
        echo -e "${RED}● Service Status: Stopped${RESET}"
    fi
    
    # Get configuration
    if [[ -f "/etc/shadowsocks-libev/config.json" ]]; then
        SS_PORT=$(grep -o '"server_port":[0-9]*' /etc/shadowsocks-libev/config.json | cut -d':' -f2)
        SS_METHOD=$(grep -o '"method":"[^"]*"' /etc/shadowsocks-libev/config.json | cut -d'"' -f4)
        HAS_PLUGIN=$(grep -q '"plugin"' /etc/shadowsocks-libev/config.json && echo "Yes" || echo "No")
        
        echo -e "${WHITE}● Port: ${BLUE}$SS_PORT${RESET}"
        echo -e "${WHITE}● Encryption: ${BLUE}$SS_METHOD${RESET}"
        echo -e "${WHITE}● Obfuscation: ${BLUE}$HAS_PLUGIN${RESET}"
    fi
    
    # Show active connections
    if systemctl is-active --quiet shadowsocks; then
        ACTIVE_CONN=$(netstat -tn | grep ":$SS_PORT" | grep ESTABLISHED | wc -l 2>/dev/null || echo "0")
        echo -e "${WHITE}● Active Connections: ${GREEN}$ACTIVE_CONN${RESET}"
    fi
    
    # Show saved configuration
    if [[ -f "/root/shadowsocks-info.txt" ]]; then
        echo -e "\n${YELLOW}Saved Configuration:${RESET}"
        echo -e "${BLUE}═══════════════════════════════════════${RESET}"
        cat /root/shadowsocks-info.txt
    fi
    
    # Recent logs
    echo -e "\n${YELLOW}Recent Logs (Last 10 lines):${RESET}"
    echo -e "${BLUE}═══════════════════════════════════════${RESET}"
    journalctl -u shadowsocks -n 10 --no-pager 2>/dev/null
    
    echo -e "\n${WHITE}Press Enter to continue...${RESET}"
    read
}

# Shadowsocks management menu
manage_shadowsocks() {
    while true; do
        clear
        display_header_with_timestamp "SHADOWSOCKS MANAGER"
        
        echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
        echo -e "${BLUE}│${WHITE}     SHADOWSOCKS MANAGEMENT             ${BLUE}│${RESET}"
        echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
        
        # Status indicator
        if is_shadowsocks_installed; then
            if systemctl is-active --quiet shadowsocks; then
                echo -e "${GREEN}● Status: RUNNING${RESET}\n"
            else
                echo -e "${RED}● Status: STOPPED${RESET}\n"
            fi
        else
            echo -e "${YELLOW}● Status: NOT INSTALLED${RESET}\n"
        fi
        
        echo -e "${RED}[${BLUE}1${RED}] ${WHITE}◇ ${GREEN}Install Shadowsocks${RESET}"
        echo -e "${RED}[${BLUE}2${RED}] ${WHITE}◇ ${BLUE}View Status & Config${RESET}"
        echo -e "${RED}[${BLUE}3${RED}] ${WHITE}◇ ${YELLOW}Start/Stop Service${RESET}"
        echo -e "${RED}[${BLUE}4${RED}] ${WHITE}◇ ${CYAN}View Connection Info${RESET}"
        echo -e "${RED}[${BLUE}5${RED}] ${WHITE}◇ ${RED}Uninstall Shadowsocks${RESET}"
        echo -e "${RED}[${BLUE}0${RED}] ${WHITE}◇ ${YELLOW}Back to Main Menu${RESET}"
        
        echo ""
        echo -e "\033[0;34m◇───────────────────────────────────────◇${RESET}"
        echo ""
        echo -ne "${GREEN}◇ SELECT OPTION ${YELLOW}❯ ${WHITE}"
        read choice
        
        case "$choice" in
            1)
                install_shadowsocks
                ;;
            2)
                show_shadowsocks_status
                ;;
            3)
                if systemctl is-active --quiet shadowsocks; then
                    systemctl stop shadowsocks
                    echo -e "\n${YELLOW}Shadowsocks service stopped${RESET}"
                else
                    systemctl start shadowsocks
                    echo -e "\n${GREEN}Shadowsocks service started${RESET}"
                fi
                sleep 2
                ;;
            4)
                if [[ -f "/root/shadowsocks-info.txt" ]]; then
                    clear
                    display_header_with_timestamp "CONNECTION INFO"
                    echo ""
                    cat /root/shadowsocks-info.txt
                    echo -e "\n${WHITE}Press Enter to continue...${RESET}"
                    read
                else
                    echo -e "\n${RED}No configuration file found${RESET}"
                    sleep 2
                fi
                ;;
            5)
                uninstall_shadowsocks
                ;;
            0)
                return
                ;;
            *)
                echo -e "${RED}Invalid option${RESET}"
                sleep 1
                ;;
        esac
    done
}

# Print main menu (elegant design)
print_menu() {
    display_professional_dashboard
    
    # Main Menu Options (elegant two-column layout)
    echo -e "${RED}[${BLUE}01${RED}] ${WHITE}◇ ${GREEN}Create User${RESET}          ${RED}[${BLUE}08${RED}] ${WHITE}◇ ${GREEN}Change Password${RESET}"
    echo -e "${RED}[${BLUE}02${RED}] ${WHITE}◇ ${RED}Delete User${RESET}          ${RED}[${BLUE}09${RED}] ${WHITE}◇ ${BLUE}User Limiter${RESET}"
    echo -e "${RED}[${BLUE}03${RED}] ${WHITE}◇ ${YELLOW}Limit User${RESET}           ${RED}[${BLUE}10${RED}] ${WHITE}◇ ${CYAN}Server Optimization${RESET}"
    echo -e "${RED}[${BLUE}04${RED}] ${WHITE}◇ ${BLUE}Connection Mode${RESET}      ${RED}[${BLUE}11${RED}] ${WHITE}◇ ${RED}Uninstall${RESET}"
    echo -e "${RED}[${BLUE}05${RED}] ${WHITE}◇ ${GREEN}Online Users${RESET}         ${RED}[${BLUE}12${RED}] ${WHITE}◇ ${MAGENTA}BadVPN Manager${RESET}"
    echo -e "${RED}[${BLUE}06${RED}] ${WHITE}◇ ${BLUE}Network Traffic${RESET}      ${RED}[${BLUE}13${RED}] ${WHITE}◇ ${YELLOW}Banner Creator${RESET}"
    echo -e "${RED}[${BLUE}07${RED}] ${WHITE}◇ ${YELLOW}User Report${RESET}         ${RED}[${BLUE}14${RED}] ${WHITE}◇ ${CYAN}Squid Proxy${RESET}"
    echo -e "                                        ${RED}[${BLUE}15${RED}] ${WHITE}◇ ${MAGENTA}Shadowsocks${RESET}"
    echo -e "                                        ${RED}[${BLUE}00${RED}] ${WHITE}◇ ${YELLOW}EXIT ${GREEN}<${YELLOW}<${RED}< ${RESET}"
    
    echo ""
    echo -e "\033[0;34m◇───────────────────────────────────────────────◇${RESET}"
    echo ""
    echo -ne "${GREEN}◇ SELECT AN OPTION ${YELLOW}❯${RED}❯${WHITE} "
}

# Uninstall system
uninstall_script() {
    clear
    display_header_with_timestamp "UNINSTALL"
    
    echo -e "\n${RED}┌────────────────────────────────────────┐${RESET}"
    echo -e "${RED}│${WHITE}         UNINSTALL MK SCRIPT            ${RED}│${RESET}"
    echo -e "${RED}└────────────────────────────────────────┘${RESET}\n"
    
    echo -e "${YELLOW}⚠️  This will completely remove:${RESET}"
    echo -e "${WHITE}   • All managed users and their data${RESET}"
    echo -e "${WHITE}   • SSL/TLS configurations${RESET}"
    echo -e "${WHITE}   • Menu system and scripts${RESET}"
    echo -e "${WHITE}   • Configuration files${RESET}\n"
    
    read -p "Are you absolutely sure? Type 'yes' to confirm: " confirm
    
    if [[ "$confirm" == "yes" ]]; then
        echo -e "\n${YELLOW}Uninstalling MK Script Manager...${RESET}\n"
        
        # Stop services
        echo -e "${WHITE}[1/6] Stopping services...${RESET}"
  systemctl stop stunnel4 2>/dev/null
        systemctl disable stunnel4 2>/dev/null
        
        # Remove users
        echo -e "${WHITE}[2/6] Removing managed users...${RESET}"
        if [[ -s "$USER_LIST_FILE" ]]; then
  while IFS=: read -r username limit; do
                [[ -n "$username" ]] && userdel -r "$username" 2>/dev/null
  done < "$USER_LIST_FILE"
        fi
        
        # Remove configurations
        echo -e "${WHITE}[3/6] Removing configurations...${RESET}"
        rm -rf /etc/mk-script /etc/VPSManager 2>/dev/null
        rm -f /etc/stunnel/stunnel.conf /etc/stunnel/stunnel.pem 2>/dev/null
        rm -f /etc/security/limits.d/mk-script-limits.conf 2>/dev/null
        
        # Remove packages
        echo -e "${WHITE}[4/6] Removing packages...${RESET}"
        apt-get remove -y stunnel4 >/dev/null 2>&1
        
        # Remove scripts
        echo -e "${WHITE}[5/6] Removing menu system...${RESET}"
        rm -f /usr/local/bin/menu 2>/dev/null
        
        # Final cleanup
        echo -e "${WHITE}[6/6] Final cleanup...${RESET}"
        apt-get autoremove -y >/dev/null 2>&1
        
        echo -e "\n${GREEN}✓ MK Script Manager uninstalled successfully${RESET}"
        echo -e "${WHITE}Thank you for using MK Script Manager v4.2!${RESET}\n"
        
  exit 0
    else
        echo -e "\n${YELLOW}Uninstall cancelled${RESET}"
    fi
}

# Server optimization function with loading animation
optimize_server() {
    clear
    display_header_with_timestamp "SERVER OPTIMIZATION"
    
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}         SERVER OPTIMIZATION            ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
    echo -e "${WHITE}This will optimize your server performance and security...${RESET}\n"
    read -p "Do you want to proceed? (y/n): " confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo -e "\n${YELLOW}Server optimization cancelled${RESET}"
        return
    fi
    
    # Loading animation function
    show_loading() {
        local message="$1"
        local duration="$2"
        local chars="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        local delay=0.1
        local elapsed=0
        
        while [ $elapsed -lt $duration ]; do
            for (( i=0; i<${#chars}; i++ )); do
                printf "\r${YELLOW}${chars:$i:1} ${WHITE}$message${RESET}"
                sleep $delay
                elapsed=$(echo "$elapsed + $delay" | bc -l 2>/dev/null || echo $((elapsed + 1)))
                if [ $(echo "$elapsed >= $duration" | bc -l 2>/dev/null || echo 0) -eq 1 ]; then
                    break 2
                fi
            done
        done
        printf "\r${GREEN}✓${WHITE} $message${RESET}\n"
    }
    
    clear
    display_header_with_timestamp "OPTIMIZING SERVER"
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}      OPTIMIZATION IN PROGRESS          ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
    local optimization_results=""
    local optimization_count=0
    
    # 1. Update system packages
    (
        apt-get update >/dev/null 2>&1
        apt-get upgrade -y >/dev/null 2>&1
    ) &
    show_loading "Updating system packages..." 3
    wait
    optimization_results+="✓ System packages updated\n"
    ((optimization_count++))
    
    # 2. Clean system cache
    (
        apt-get autoremove -y >/dev/null 2>&1
        apt-get autoclean >/dev/null 2>&1
        rm -rf /tmp/* 2>/dev/null
        find /var/log -name "*.log" -type f -size +50M -delete 2>/dev/null
    ) &
    show_loading "Cleaning system cache and logs..." 2
    wait
    optimization_results+="✓ System cache and logs cleaned\n"
    ((optimization_count++))
    
    # 3. Optimize network settings - MAXIMUM PERFORMANCE
    (
        # Remove existing entries to prevent duplicates
        sed -i '/net.core.rmem_max/d' /etc/sysctl.conf 2>/dev/null
        sed -i '/net.core.wmem_max/d' /etc/sysctl.conf 2>/dev/null
        sed -i '/net.ipv4.tcp_rmem/d' /etc/sysctl.conf 2>/dev/null
        sed -i '/net.ipv4.tcp_wmem/d' /etc/sysctl.conf 2>/dev/null
        sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf 2>/dev/null
        sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf 2>/dev/null
        sed -i '/net.ipv4.tcp_window_scaling/d' /etc/sysctl.conf 2>/dev/null
        sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf 2>/dev/null
        sed -i '/net.ipv4.tcp_sack/d' /etc/sysctl.conf 2>/dev/null
        sed -i '/net.ipv4.tcp_no_metrics_save/d' /etc/sysctl.conf 2>/dev/null
        sed -i '/net.ipv4.tcp_moderate_rcvbuf/d' /etc/sysctl.conf 2>/dev/null
        
        # MAXIMUM PERFORMANCE TCP OPTIMIZATIONS FOR SSL/TLS TUNNEL
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
    ) &
    show_loading "Applying maximum performance network settings..." 3
    wait
    optimization_results+="✓ Network settings optimized\n"
    ((optimization_count++))
    
    # 4. Security hardening
    (
        # SSH security
        sed -i 's/#PermitRootLogin yes/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null
        sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null
        
        # Firewall basic setup
        ufw --force reset >/dev/null 2>&1
        ufw default deny incoming >/dev/null 2>&1
        ufw default allow outgoing >/dev/null 2>&1
        ufw allow 22 >/dev/null 2>&1
        ufw allow 80 >/dev/null 2>&1
        ufw allow 443 >/dev/null 2>&1
        echo "y" | ufw enable >/dev/null 2>&1
    ) &
    show_loading "Applying security hardening..." 3
    wait
    optimization_results+="✓ Security settings hardened\n"
    ((optimization_count++))
    
    # 5. Memory optimization
    (
        # Swap optimization
        echo 'vm.swappiness = 10' >> /etc/sysctl.conf 2>/dev/null
        echo 'vm.vfs_cache_pressure = 50' >> /etc/sysctl.conf 2>/dev/null
        
        # Clear memory cache
        sync
        echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
        sysctl -p >/dev/null 2>&1
    ) &
    show_loading "Optimizing memory usage..." 2
    wait
    optimization_results+="✓ Memory settings optimized\n"
    ((optimization_count++))
    
    # 6. Service optimization
    (
        systemctl daemon-reload >/dev/null 2>&1
        systemctl restart networking >/dev/null 2>&1
        systemctl restart ssh >/dev/null 2>&1
        systemctl restart stunnel4 >/dev/null 2>&1 || true
    ) &
    show_loading "Restarting optimized services..." 2
    wait
    optimization_results+="✓ Services restarted with new settings\n"
    ((optimization_count++))
    
    # Show results
    clear
    display_header_with_timestamp "OPTIMIZATION COMPLETE"
    
    echo -e "\n${GREEN}┌────────────────────────────────────────┐${RESET}"
    echo -e "${GREEN}│${WHITE}     OPTIMIZATION SUCCESSFUL!           ${GREEN}│${RESET}"
    echo -e "${GREEN}└────────────────────────────────────────┘${RESET}\n"
    
    echo -e "${WHITE}Optimization Results:${RESET}\n"
    echo -e "$optimization_results"
    
    echo -e "${BLUE}📊 Performance Summary:${RESET}"
    echo -e "${WHITE}• Total optimizations applied: ${GREEN}$optimization_count${RESET}"
    echo -e "${WHITE}• System packages: ${GREEN}Updated${RESET}"
    echo -e "${WHITE}• Cache cleanup: ${GREEN}Completed${RESET}"
    echo -e "${WHITE}• Network performance: ${GREEN}Enhanced${RESET}"
    echo -e "${WHITE}• Security hardening: ${GREEN}Applied${RESET}"
    echo -e "${WHITE}• Memory optimization: ${GREEN}Configured${RESET}"
    echo -e "${WHITE}• Services: ${GREEN}Restarted${RESET}"
    
    echo -e "\n${YELLOW}💡 Recommendations:${RESET}"
    echo -e "${WHITE}• Reboot your server for all changes to take full effect${RESET}"
    echo -e "${WHITE}• Monitor performance over the next 24 hours${RESET}"
    echo -e "${WHITE}• Run optimization monthly for best results${RESET}"
    
    echo -e "\n${GREEN}✅ Your server has been successfully optimized!${RESET}"
}

# Graceful exit function
graceful_exit() {
    echo -e "\n\n${YELLOW}👋 Thank you for using MK Script Manager v4.2!${RESET}"
    echo -e "${WHITE}Exiting gracefully...${RESET}"
    exit 0
}

# Main program loop
main() {
    # Ensure running as root
    if [[ "$EUID" -ne 0 ]]; then
        echo -e "${RED}This script must be run as root (use sudo)${RESET}"
        exit 1
    fi
    
    # Set up CTRL+C handler for graceful exit
    trap graceful_exit SIGINT
    
    # Create required directories
    mkdir -p "$(dirname "$USER_LIST_FILE")" "$PASSWORD_DIR"
    
    # Main menu loop
    while true; do
        print_menu
        read choice
        echo
        
        case "$choice" in
            1|01) create_user ;;
            2|02) delete_user ;;
            3|03) limit_user ;;
            4|04) configure_tunnel ;;
            5|05) show_online_users ;;
            6|06) show_network_traffic ;;
            7|07) show_user_report ;;
            8|08) change_user_password ;;
            9|09) user_limiter_management ;;
            10) optimize_server ;;
            11) uninstall_script ;;
            12) manage_badvpn ;;
            13) manage_ssh_banner ;;
            14) manage_squid ;;
            15) manage_shadowsocks ;;
            0|00) 
                echo -e "\n${YELLOW}◇ Exiting MK Script Manager...${RESET}"
                echo -e "${GREEN}Thank you for using MK Script Manager v4.2!${RESET}"
                sleep 2
                clear
                exit 0
                ;;
            *) echo -e "${RED}◇ Invalid option! Please try again.${RESET}" ;;
        esac
        
        [[ "$choice" != "11" && "$choice" != "0" && "$choice" != "00" ]] && {
            echo -e "\n${WHITE}Press any key to return to main menu...${RESET}"
            read -n1 -s -r
        }
    done
}

# CTRL+C handling is now set up in main() function

# Start the program
main "$@"
