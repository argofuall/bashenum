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
# Start of Audit
# ---------------------------

# 1. System Information
print_header "System Information"

# Hostname and Uptime
print_subheader "Hostname & Uptime"
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
    cat /etc/*-release
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
if [ -r /etc/shadow ]; then
    success "/etc/shadow is readable."
else
    warn "/etc/shadow is not readable."
fi
echo

# Sudo Privileges
print_subheader "Sudo Privileges"
if command_exists sudo; then
    sudo -l 2>/dev/null
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
    grep "^password" /etc/pam.d/*
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
    sudo ufw status
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
    ip route
else
    route -n
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
    systemctl list-units --type=service --state=running
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
find / -type f -perm -o+w 2>/dev/null | wc -l | awk '{print "Total World-Writable Files: " $1}'
find / -type f -perm -o+w 2>/dev/null | head -n 20
echo

# SUID and GUID Files
print_subheader "SUID Executables"
find / -type f -perm /4000 2>/dev/null | wc -l | awk '{print "Total SUID Files: " $1}'
find / -type f -perm /4000 2>/dev/null | head -n 20
echo

print_subheader "GUID Executables"
find / -type f -perm /2000 2>/dev/null | wc -l | awk '{print "Total GUID Files: " $1}'
find / -type f -perm /2000 2>/dev/null | head -n 20
echo

# Mounted Filesystems
print_subheader "Mounted Filesystems"
df -hT
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
    sudo iptables -L -v
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
    systemctl status auditd
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
    crontab -u "$user" -l 2>/dev/null || echo "No cron jobs for user: $user"
    echo
done
echo

# At Jobs
print_subheader "At Jobs"
if command_exists at; then
    atq
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

# Check if Running Inside a Container
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

# ---------------------------
# Summary
# ---------------------------
print_header "Audit Summary"
echo "The audit has been completed. Review the above sections for detailed information."
echo -e "${YELLOW}Recommendations: Address any warnings and review suggestions to enhance system security.${NC}"
echo -e "${BLUE}====================================${NC}"
echo -e "${GREEN}* Audit Completed Successfully *${NC}"
echo -e "${BLUE}====================================${NC}"
