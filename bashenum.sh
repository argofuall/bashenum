#!/bin/bash

# ===========================
# System Enumeration Script
# ===========================
# Author: Your Name
# Date: YYYY-MM-DD
# Description: A comprehensive system enumeration script for auditing purposes.

# ---------------------------
# Color Definitions
# ---------------------------
GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
NC="\033[0m" # No Color

# ---------------------------
# Helper Functions
# ---------------------------

# Function to print headers
print_header() {
    echo -e "${RED}[+] $1${NC}"
}

# Function to print sub-headers
print_subheader() {
    echo -e "${GREEN}[+] $1${NC}"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to handle missing commands gracefully
execute_command() {
    if command_exists "$1"; then
        eval "$2"
    else
        echo -e "${YELLOW}[-] Command '$1' not found.${NC}"
    fi
}

# ---------------------------
# Start of Enumeration
# ---------------------------

# Kernel and Distribution Release Details
print_header "Kernel and Distribution Release Details"
uname -a
if [ -f /etc/os-release ]; then
    cat /etc/os-release
elif [ -f /etc/lsb-release ]; then
    cat /etc/lsb-release
else
    cat /etc/*-release
fi
echo

# System Information
print_header "System Information"

# Hostname
print_subheader "Hostname"
hostname
echo

# Networking Details
print_subheader "Networking Details"

# Current IP
print_subheader "Current IP Addresses"
ip a | grep 'inet'
echo

# Default Route Details
print_subheader "Default Route Details"
if command_exists "ip"; then
    ip route
else
    execute_command "route" "route -n"
fi
echo

# DNS Server Information
print_subheader "DNS Server Information"
if [ -f /etc/resolv.conf ]; then
    cat /etc/resolv.conf
else
    echo -e "${YELLOW}[-] /etc/resolv.conf not found.${NC}"
fi
echo

# User Information
print_header "User Information"

# Current User Details
print_subheader "Current User Details"
whoami
echo

# Last Logged On Users
print_subheader "Last Logged On Users"
last
echo

# Users Currently Logged On
print_subheader "Users Currently Logged On"
who
echo

# List All Users Including UID/GID Information
print_subheader "List All Users (Including UID/GID)"
if [ -f /etc/passwd ]; then
    cat /etc/passwd
else
    echo -e "${YELLOW}[-] /etc/passwd not found.${NC}"
fi
echo

# List Root Accounts
print_subheader "List Root Accounts"
grep "x:0:" /etc/passwd || echo -e "${YELLOW}[-] No root accounts found.${NC}"
echo

# Password Policies and Hash Storage Method Information
print_subheader "Password Policies and Hash Storage Methods"
if ls /etc/pam.d/* &>/dev/null; then
    grep "^password" /etc/pam.d/*
else
    echo -e "${YELLOW}[-] No PAM configuration files found.${NC}"
fi
echo

# Check Umask Value
print_subheader "Umask Value"
umask
echo

# Attempt to Read Restricted Files (e.g., /etc/shadow)
print_header "Attempt to Read Restricted Files (e.g., /etc/shadow)"
if [ -r /etc/shadow ]; then
    cat /etc/shadow
else
    echo -e "${YELLOW}[-] /etc/shadow is not readable.${NC}"
fi
echo

# List Current Users' History Files
print_header "List Current Users' History Files"
find /home -type f \( -name ".bash_history" -o -name ".nano_history" \) -exec ls -la {} \; 2>/dev/null
echo

# Users Who Have Recently Used Sudo
print_header "Users Who Have Recently Used Sudo"
if [ -f /var/log/auth.log ]; then
    grep "sudo" /var/log/auth.log
elif [ -f /var/log/secure ]; then
    grep "sudo" /var/log/secure
else
    echo -e "${YELLOW}[-] Authentication log not found.${NC}"
fi
echo

# Check if /etc/sudoers is Accessible
print_header "Check if /etc/sudoers is Accessible"
ls -la /etc/sudoers || echo -e "${YELLOW}[-] /etc/sudoers not accessible.${NC}"
echo

# Check for Known 'Good' Breakout Binaries via Sudo
print_header "Known 'Good' Breakout Binaries via Sudo"
if command_exists "sudo"; then
    sudo -l | grep -E "nmap|vim|less|more|nano|vi|perl|python|ruby|gcc|gdb" || echo -e "${YELLOW}[-] No known breakout binaries found via sudo.${NC}"
else
    echo -e "${YELLOW}[-] sudo not installed.${NC}"
fi
echo

# Check if Root’s Home Directory is Accessible
print_header "Check if Root’s Home Directory is Accessible"
ls -ld /root || echo -e "${YELLOW}[-] /root directory not accessible.${NC}"
echo

# List Permissions for /home/
print_header "List Permissions for /home/"
ls -ld /home || echo -e "${YELLOW}[-] /home directory not found.${NC}"
echo

# Display Current $PATH
print_header "Display Current \$PATH"
echo "$PATH"
echo

# List All Cron Jobs for Current User
print_header "List All Cron Jobs for Current User"
crontab -l 2>/dev/null || echo -e "${YELLOW}[-] No cron jobs for current user.${NC}"
echo

# Locate All World-Writable Cron Jobs
print_header "Locate All World-Writable Cron Jobs"
find /etc/cron* -type f -perm -002 -exec ls -la {} \; 2>/dev/null || echo -e "${YELLOW}[-] No world-writable cron jobs found.${NC}"
echo

# Locate Cron Jobs Owned by Other Users
print_header "Locate Cron Jobs Owned by Other Users"
find /etc/cron* ! -user root -type f -exec ls -la {} \; 2>/dev/null || echo -e "${YELLOW}[-] No cron jobs owned by other users found.${NC}"
echo

# List Active and Inactive Systemd Timers
print_header "List Active and Inactive Systemd Timers"
if command_exists "systemctl"; then
    systemctl list-timers --all
else
    echo -e "${YELLOW}[-] systemctl not found.${NC}"
fi
echo

# List Running Processes
print_header "List Running Processes"
ps aux
echo

# Lookup and List Process Binaries and Associated Permissions
print_header "Process Binaries and Permissions (Top CPU Usage)"
if command_exists "ps" && command_exists "ls"; then
    ps aux --sort=-%cpu | awk 'NR>1 {print $11}' | sort -u | xargs -r ls -la 2>/dev/null
else
    echo -e "${YELLOW}[-] Required commands not found.${NC}"
fi
echo

# List init.d Binary Permissions
print_header "List init.d Binary Permissions"
if [ -d /etc/init.d/ ]; then
    ls -la /etc/init.d/*
else
    echo -e "${YELLOW}[-] /etc/init.d directory not found.${NC}"
fi
echo

# Locate All SUID/GUID Files
print_header "Locate All SUID/GUID Files"
find / -perm /4000 -type f 2>/dev/null || echo -e "${YELLOW}[-] No SUID files found.${NC}"
echo

# Locate All World-Writable SUID/GUID Files
print_header "Locate All World-Writable SUID/GUID Files"
find / -perm /6000 -type f 2>/dev/null || echo -e "${YELLOW}[-] No world-writable SUID/GUID files found.${NC}"
echo

# Locate All SUID/GUID Files Owned by Root
print_header "Locate All SUID/GUID Files Owned by Root"
find / -user root -perm /4000 -type f 2>/dev/null || echo -e "${YELLOW}[-] No SUID/GUID files owned by root found.${NC}"
echo

# Locate 'Interesting' SUID/GUID Files (e.g., nmap, vim)
print_header "Locate 'Interesting' SUID/GUID Files (e.g., nmap, vim)"
find / -user root -perm /4000 -type f \( -name "nmap" -o -name "vim" -o -name "perl" -o -name "python" \) 2>/dev/null || echo -e "${YELLOW}[-] No interesting SUID/GUID files found.${NC}"
echo

# Locate Files with POSIX Capabilities
print_header "Locate Files with POSIX Capabilities"
if command_exists "getcap"; then
    getcap -r / 2>/dev/null
else
    echo -e "${YELLOW}[-] getcap not installed.${NC}"
fi
echo

# List All World-Writable Files
print_header "List All World-Writable Files"
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null || echo -e "${YELLOW}[-] No world-writable directories found.${NC}"
echo

# Find/List All Accessible *.plan Files and Display Contents
print_header "Find and Display *.plan Files"
find / -type f -name "*.plan" -exec cat {} \; 2>/dev/null || echo -e "${YELLOW}[-] No *.plan files found.${NC}"
echo

# Find/List All Accessible *.rhosts Files and Display Contents
print_header "Find and Display *.rhosts Files"
find / -type f -name "*.rhosts" -exec cat {} \; 2>/dev/null || echo -e "${YELLOW}[-] No *.rhosts files found.${NC}"
echo

# Show NFS Server Details
print_header "NFS Server Details"
if command_exists "showmount"; then
    showmount -e || echo -e "${YELLOW}[-] No NFS exports found or showmount failed.${NC}"
else
    echo -e "${YELLOW}[-] showmount not installed.${NC}"
fi
echo

# Locate *.conf and *.log Files Containing a User-Supplied Keyword
print_header "Search *.conf and *.log Files for a Keyword"
if [ "$#" -ge 1 ]; then
    KEYWORD="$1"
    grep -r --include="*.conf" --include="*.log" "$KEYWORD" /etc /var/log 2>/dev/null || echo -e "${YELLOW}[-] No matches found for keyword '${KEYWORD}'.${NC}"
else
    echo -e "${YELLOW}[-] No keyword supplied. Usage: $0 <keyword>${NC}"
fi
echo

# List All *.conf Files Located in /etc
print_header "List All *.conf Files in /etc"
if [ -d /etc ]; then
    find /etc -type f -name "*.conf" -exec ls -la {} \; 2>/dev/null || echo -e "${YELLOW}[-] No *.conf files found in /etc.${NC}"
else
    echo -e "${YELLOW}[-] /etc directory not found.${NC}"
fi
echo

# .bak File Search
print_header "Search for *.bak Files"
find / -type f -name "*.bak" -exec ls -la {} \; 2>/dev/null || echo -e "${YELLOW}[-] No *.bak files found.${NC}"
echo

# Locate Mail Files or Directories
print_header "Locate Mail Files or Directories"
find / -type f -name "mail" -o -type d -name "mail" -exec ls -la {} \; 2>/dev/null || echo -e "${YELLOW}[-] No 'mail' files or directories found.${NC}"
echo

# Check if Running Inside a Docker Container
print_header "Check if Running Inside a Docker Container"
if [ -f /proc/1/cgroup ]; then
    grep -iq "docker" /proc/1/cgroup && echo -e "${GREEN}[+] Running inside a Docker container.${NC}" || echo -e "${YELLOW}[-] Not running inside a Docker container.${NC}"
else
    echo -e "${YELLOW}[-] /proc/1/cgroup not found.${NC}"
fi
echo

# Check if Docker is Installed on the Host
print_header "Check if Docker is Installed on the Host"
command_exists "docker" && echo -e "${GREEN}[+] Docker is installed.${NC}" || echo -e "${YELLOW}[-] Docker is not installed.${NC}"
echo

# Check if Running Inside an LXC Container
print_header "Check if Running Inside an LXC Container"
if [ -f /proc/1/cgroup ]; then
    grep -iq "lxc" /proc/1/cgroup && echo -e "${GREEN}[+] Running inside an LXC container.${NC}" || echo -e "${YELLOW}[-] Not running inside an LXC container.${NC}"
else
    echo -e "${YELLOW}[-] /proc/1/cgroup not found.${NC}"
fi
echo

# Additional Enumeration Techniques

# List Installed Packages
print_header "List Installed Packages"
if command_exists "dpkg"; then
    dpkg -l
elif command_exists "rpm"; then
    rpm -qa
else
    echo -e "${YELLOW}[-] Neither dpkg nor rpm found.${NC}"
fi
echo

# List Enabled Services
print_header "List Enabled Services"
if command_exists "systemctl"; then
    systemctl list-unit-files --type=service --state=enabled
elif command_exists "service"; then
    service --status-all
else
    echo -e "${YELLOW}[-] Neither systemctl nor service command found.${NC}"
fi
echo

# List Listening Network Ports
print_header "List Listening Network Ports"
if command_exists "ss"; then
    ss -tuln
elif command_exists "netstat"; then
    netstat -tuln
else
    echo -e "${YELLOW}[-] Neither ss nor netstat found.${NC}"
fi
echo

# List Mounted Filesystems
print_header "List Mounted Filesystems"
df -hT
echo

# Display SSH Configuration
print_header "SSH Configuration Details"
if [ -f /etc/ssh/sshd_config ]; then
    grep -E "PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords" /etc/ssh/sshd_config
else
    echo -e "${YELLOW}[-] /etc/ssh/sshd_config not found.${NC}"
fi
echo

# List Scheduled 'at' Jobs
print_header "List Scheduled 'at' Jobs"
if command_exists "at"; then
    atq
else
    echo -e "${YELLOW}[-] at command not installed.${NC}"
fi
echo

# Check for Kubernetes Environment
print_header "Check if Running Inside a Kubernetes Environment"
if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
    echo -e "${GREEN}[+] Running inside a Kubernetes environment.${NC}"
else
    echo -e "${YELLOW}[-] Not running inside a Kubernetes environment.${NC}"
fi
echo

# ---------------------------
# End of Enumeration
# ---------------------------
echo -e "${BLUE}Enumeration Completed.${NC}"
