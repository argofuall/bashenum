#!/bin/bash

# =============================================================================
# System Security Audit Script
# =============================================================================
# Description: A comprehensive system security auditing script inspired by Lynis.
# Author: Your Name
# Date: YYYY-MM-DD
# =============================================================================

# ---------------------------
# Color Definitions
# ---------------------------
GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
PURPLE="\033[1;35m"
NC="\033[0m" # No Color

# ---------------------------
# Helper Functions
# ---------------------------

# Function to print headers
print_header() {
    echo -e "${BLUE}====================================${NC}"
    echo -e "${GREEN}* $1${NC}"
    echo -e "${BLUE}====================================${NC}"
}

# Function to print sub-headers
print_subheader() {
    echo -e "${PURPLE}--- $1 ---${NC}"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to display warnings
warn() {
    echo -e "${YELLOW}[-] $1${NC}"
}

# Function to display errors
error() {
    echo -e "${RED}[!] $1${NC}"
}

# Function to display success messages
success() {
    echo -e "${GREEN}[+] $1${NC}"
}

# ---------------------------
# Sudo Privilege Handling
# ---------------------------

# Prompt the user to decide on using sudo privileges
use_sudo_prompt() {
    while true; do
        read -rp "Do you want to run the script with sudo privileges? (y/n): " yn
        case $yn in
            [Yy]* )
                USE_SUDO=true
                break
                ;;
            [Nn]* )
                USE_SUDO=false
                break
                ;;
            * )
                echo "Please answer yes (y) or no (n)."
                ;;
        esac
    done
}

# Function to execute commands with or without sudo
execute_cmd() {
    if [ "$USE_SUDO" = true ]; then
        sudo bash -c "$1"
    else
        bash -c "$1"
    fi
}

# ---------------------------
# Start of Audit
# ---------------------------

# Initialize USE_SUDO variable
USE_SUDO=false

# Run the sudo prompt
use_sudo_prompt

# Verify sudo access if user opted to use sudo
if [ "$USE_SUDO" = true ]; then
    if sudo -v; then
        success "Sudo privileges granted."
    else
        error "Sudo privileges required but not granted. Exiting."
        exit 1
    fi
else
    warn "Running without sudo privileges. Some checks may be limited."
fi

echo

# 1. System Information
print_header "System Information"

# Hostname and Uptime
print_subheader "Hostname & Uptime"
whoami
hostname
uptime
echo

# Kernel and OS
print_subheader "Kernel & OS Details"
uname -a
if [ -f /etc/os-release ]; then
    cat /etc/os-release
elif [ -f /etc/lsb-release ]; then
    cat /etc/lsb-release
else
    cat /etc/*-release 2>/dev/null
fi
echo

# 2. User Accounts and Permissions
print_header "User Accounts & Permissions"

# Current User
print_subheader "Current User"
whoami
echo

# List All Users
print_subheader "All User Accounts"
cut -d: -f1 /etc/passwd
echo

# Root User Accessibility
print_subheader "Root User Accessibility"
if [ -e /etc/shadow ]; then
    if [ -r /etc/shadow ]; then
        warn "/etc/shadow is readable. This is a security risk."
    else
        success "/etc/shadow is not readable."
    fi
else
    warn "/etc/shadow does not exist."
fi
echo

# Sudo Privileges
print_subheader "Sudo Privileges"
if command_exists sudo; then
    if [ "$USE_SUDO" = true ]; then
        sudo -l 2>/dev/null || warn "Cannot list sudo privileges."
    else
        warn "Sudo privileges were not requested."
    fi
else
    warn "sudo is not installed."
fi
echo

# 3. Authentication and Authorization
print_header "Authentication & Authorization"

# Password Policies
print_subheader "Password Policies"
if [ -f /etc/login.defs ]; then
    grep -E "^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_MIN_LEN|^PASS_WARN_AGE" /etc/login.defs
else
    warn "/etc/login.defs not found."
fi
echo

# PAM Configuration
print_subheader "PAM Configuration for Passwords"
if ls /etc/pam.d/* &>/dev/null; then
    grep "^password" /etc/pam.d/* | grep -v '^#'
else
    warn "No PAM configuration files found."
fi
echo

# 4. Network Configuration
print_header "Network Configuration"

# Network Interfaces
print_subheader "Network Interfaces"
ip a | grep 'inet'
echo

# Open Ports
print_subheader "Listening Ports"
if command_exists ss; then
    ss -tuln
elif command_exists netstat; then
    netstat -tuln
else
    warn "Neither ss nor netstat is available."
fi
echo

# Firewall Status
print_subheader "Firewall Status"
if command_exists ufw; then
    if [ "$USE_SUDO" = true ]; then
        sudo ufw status
    else
        warn "Firewall status requires sudo privileges."
    fi
elif [ -f /etc/iptables/rules.v4 ]; then
    cat /etc/iptables/rules.v4
else
    warn "Firewall status could not be determined."
fi
echo

# DNS Configuration
print_subheader "DNS Configuration"
if [ -f /etc/resolv.conf ]; then
    cat /etc/resolv.conf
else
    warn "/etc/resolv.conf not found."
fi
echo

# Routing Table
print_subheader "Routing Table"
if command_exists ip; then
    execute_cmd "ip route"
elif command_exists route; then
    execute_cmd "route -n"
else
    warn "Neither ip nor route command is available."
fi
echo

# 5. Installed Software and Services
print_header "Installed Software & Services"

# Package Manager Check
print_subheader "Package Manager"
if command_exists dpkg; then
    echo "Dpkg-based system detected."
    print_subheader "Installed Packages"
    dpkg -l
elif command_exists rpm; then
    echo "RPM-based system detected."
    print_subheader "Installed Packages"
    rpm -qa
else
    warn "Unsupported package manager."
fi
echo

# Running Services
print_subheader "Running Services"
if command_exists systemctl; then
    if [ "$USE_SUDO" = true ]; then
        sudo systemctl list-units --type=service --state=running
    else
        systemctl list-units --type=service --state=running
    fi
elif command_exists service; then
    service --status-all 2>&1 | grep "+"
else
    warn "No service management commands found."
fi
echo

# 6. File System and Permissions
print_header "File System & Permissions"

# World-Writable Files
print_subheader "World-Writable Files"
WW_FILES_COUNT=$(find / -type f -perm -o+w 2>/dev/null | wc -l)
echo "Total World-Writable Files: $WW_FILES_COUNT"
find / -type f -perm -o+w 2>/dev/null | head -n 20
echo

# World-Writable Directories
print_subheader "World-Writable Directories"
WW_DIRS_COUNT=$(find / -type d -perm -o+w 2>/dev/null | wc -l)
echo "Total World-Writable Directories: $WW_DIRS_COUNT"
find / -type d -perm -o+w 2>/dev/null | head -n 20
echo

# Sensitive Files Detection
print_subheader "Sensitive Files Detection"
SENSITIVE_FILES=$(find /home /root /etc -type f \( -iname "*.env" -o -iname "id_rsa" -o -iname "*.pem" -o -iname "*.key" \) 2>/dev/null)
if [ -n "$SENSITIVE_FILES" ]; then
    echo "Sensitive files found:"
    echo "$SENSITIVE_FILES" | head -n 20
    echo "Total Sensitive Files Found: $(echo "$SENSITIVE_FILES" | wc -l)"
else
    success "No sensitive files found in common locations."
fi
echo

# Home Directory Permissions
print_subheader "Home Directory Permissions"
while IFS=: read -r user pass uid gid gecos home shell; do
    if [ -d "$home" ]; then
        perms=$(stat -c "%a" "$home" 2>/dev/null)
        if [ "$perms" -le 755 ]; then
            echo "User: $user - Home Directory: $home - Permissions: $perms"
        else
            warn "User: $user - Home Directory: $home has overly permissive permissions: $perms"
        fi
    fi
done < /etc/passwd
echo

# SSH Directory and Files Permissions
print_subheader "SSH Directory and Files Permissions"
for user in $(cut -f1 -d: /etc/passwd); do
    SSH_DIR="/home/$user/.ssh"
    AUTH_KEYS="$SSH_DIR/authorized_keys"
    if [ -d "$SSH_DIR" ]; then
        dir_perms=$(stat -c "%a" "$SSH_DIR" 2>/dev/null)
        auth_perms=$(stat -c "%a" "$AUTH_KEYS" 2>/dev/null)
        if [ "$dir_perms" -le 750 ]; then
            echo "User: $user - .ssh Directory Permissions: $dir_perms"
        else
            warn "User: $user - .ssh Directory has overly permissive permissions: $dir_perms"
        fi
        if [ -f "$AUTH_KEYS" ]; then
            if [ "$auth_perms" -le 640 ]; then
                echo "User: $user - authorized_keys Permissions: $auth_perms"
            else
                warn "User: $user - authorized_keys has overly permissive permissions: $auth_perms"
            fi
        fi
    fi
done
echo

# Cron Directory Permissions
print_subheader "Cron Directory Permissions"
CRON_DIRS=("/etc/cron.hourly" "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly" "/etc/crontab" "/var/spool/cron/crontabs")
for dir in "${CRON_DIRS[@]}"; do
    if [ -e "$dir" ]; then
        perms=$(stat -c "%a" "$dir" 2>/dev/null)
        if [ "$perms" -le 700 ]; then
            echo "$dir Permissions: $perms"
        else
            warn "$dir has overly permissive permissions: $perms"
        fi
    fi
done
echo

# 7. Security Configurations
print_header "Security Configurations"

# SSH Configuration
print_subheader "SSH Configuration"
if [ -f /etc/ssh/sshd_config ]; then
    grep -E "PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|X11Forwarding" /etc/ssh/sshd_config
else
    warn "/etc/ssh/sshd_config not found."
fi
echo

# Firewall Rules
print_subheader "Firewall Rules"
if command_exists iptables; then
    if [ "$USE_SUDO" = true ]; then
        sudo iptables -L -v
    else
        warn "Viewing firewall rules requires sudo privileges."
    fi
else
    warn "iptables not installed."
fi
echo

# SELinux Status
print_subheader "SELinux Status"
if command_exists getenforce; then
    getenforce
else
    warn "SELinux is not installed."
fi
echo

# AppArmor Status
print_subheader "AppArmor Status"
if command_exists apparmor_status; then
    apparmor_status
else
    warn "AppArmor is not installed."
fi
echo

# 8. Logging and Auditing
print_header "Logging & Auditing"

# Auditd Status
print_subheader "Auditd Status"
if command_exists systemctl; then
    if [ "$USE_SUDO" = true ]; then
        sudo systemctl status auditd
    else
        warn "Checking auditd status requires sudo privileges."
    fi
elif [ -f /etc/init.d/auditd ]; then
    /etc/init.d/auditd status
else
    warn "auditd not installed."
fi
echo

# Log Files Monitoring
print_subheader "Recent System Logs"
if [ -f /var/log/syslog ]; then
    tail -n 20 /var/log/syslog
elif [ -f /var/log/messages ]; then
    tail -n 20 /var/log/messages
else
    warn "No standard system log files found."
fi
echo

# 9. Scheduled Tasks
print_header "Scheduled Tasks"

# Cron Jobs for All Users
print_subheader "Cron Jobs for All Users"
for user in $(cut -f1 -d: /etc/passwd); do
    echo "Cron jobs for user: $user"
    if [ "$USE_SUDO" = true ]; then
        sudo crontab -u "$user" -l 2>/dev/null || echo "No cron jobs for user: $user"
    else
        crontab -u "$user" -l 2>/dev/null || echo "No cron jobs for user: $user"
    fi
    echo
done
echo

# At Jobs
print_subheader "At Jobs"
if command_exists at; then
    if [ "$USE_SUDO" = true ]; then
        sudo atq
    else
        atq
    fi
else
    warn "at command not installed."
fi
echo

# 10. Containerization Checks
print_header "Containerization Checks"

# Check for Docker
print_subheader "Docker Installation"
if command_exists docker; then
    success "Docker is installed."
else
    warn "Docker is not installed."
fi
echo

# Check if Running Inside a Docker Container
print_subheader "Running Inside a Docker Container?"
if grep -qa 'docker' /proc/1/cgroup; then
    success "System is running inside a Docker container."
else
    warn "System is not running inside a Docker container."
fi
echo

# Check if Running Inside an LXC Container
print_subheader "Running Inside an LXC Container?"
if grep -qa 'lxc' /proc/1/cgroup; then
    success "System is running inside an LXC container."
else
    warn "System is not running inside an LXC container."
fi
echo

# 11. Additional Security Checks
print_header "Additional Security Checks"

# Pending Security Updates
print_subheader "Pending Security Updates"
if command_exists dpkg; then
    dpkg -l | grep '^ii  ' | grep -E 'security|updates'
elif command_exists rpm; then
    yum check-update
else
    warn "Could not determine package manager for security updates."
fi
echo

# Services Listening on Non-Standard Ports
print_subheader "Services Listening on Non-Standard Ports"
STANDARD_PORTS=(22 80 443)
if command_exists ss; then
    LISTEN_PORTS=$(ss -tuln | awk '{print $5}' | grep -oP '(?<=:)\d+')
elif command_exists netstat; then
    LISTEN_PORTS=$(netstat -tuln | awk '{print $4}' | grep -oP '(?<=:)\d+')
else
    warn "Neither ss nor netstat is available to check listening ports."
fi

if [ -n "$LISTEN_PORTS" ]; then
    NON_STANDARD_PORTS=()
    for port in $LISTEN_PORTS; do
        if [[ ! " ${STANDARD_PORTS[@]} " =~ " ${port} " ]]; then
            NON_STANDARD_PORTS+=("$port")
        fi
    done

    if [ ${#NON_STANDARD_PORTS[@]} -gt 0 ]; then
        echo "Non-standard ports in use:"
        printf '%s\n' "${NON_STANDARD_PORTS[@]}" | sort -u | head -n 20
    else
        success "No services are listening on non-standard ports."
    fi
else
    warn "Could not retrieve listening ports."
fi
echo

# ---------------------------
# Summary
# ---------------------------
print_header "Audit Summary"
echo "The audit has been completed. Review the above sections for detailed information."
echo -e "${YELLOW}Recommendations: Address any warnings and review suggestions to enhance system security.${NC}"
echo -e "${BLUE}====================================${NC}"
echo -e "${GREEN}* Audit Completed Successfully *${NC}"
echo -e "${BLUE}====================================${NC}"
