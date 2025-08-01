#!/usr/bin/env bash
#
# Elastic Stack Cleanup Script
# Completely removes Elasticsearch, Kibana, and Filebeat installations
#

set -euo pipefail

# Color definitions
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                Elastic Stack Cleanup Script                  ║${NC}"
echo -e "${BLUE}║                                                              ║${NC}"
echo -e "${BLUE}║  This will completely remove Elasticsearch, Kibana, and     ║${NC}"
echo -e "${BLUE}║  Filebeat installations including all data and configs      ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}❌ This script must be run as root or with sudo${NC}"
    exit 1
fi

# Confirmation prompt
echo -e "${YELLOW}⚠️  WARNING: This will permanently delete:${NC}"
echo "   • All Elasticsearch data and indices"
echo "   • All Kibana configurations and saved objects"
echo "   • All SSL certificates and credentials"
echo "   • All log files and configuration files"
echo ""
read -p "Are you sure you want to proceed? (yes/NO): " confirm

if [[ "$confirm" != "yes" ]]; then
    echo "Cleanup cancelled."
    exit 0
fi

echo ""
echo -e "${BLUE}🧹 Starting Elastic Stack cleanup...${NC}"

# Stop services
echo "🛑 Stopping services..."
for service in elasticsearch kibana filebeat; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        echo "   Stopping $service..."
        systemctl stop "$service" || true
    fi
    
    if systemctl is-enabled --quiet "$service" 2>/dev/null; then
        echo "   Disabling $service..."
        systemctl disable "$service" || true
    fi
done

# Remove packages
echo "📦 Removing packages..."
for package in elasticsearch kibana filebeat; do
    if rpm -qa | grep -q "^$package"; then
        echo "   Removing $package..."
        rpm -e "$package" --nodeps || true
    fi
done

# Remove directories and files
echo "🗂️  Removing directories and files..."

# Elasticsearch
echo "   Removing Elasticsearch files..."
rm -rf /etc/elasticsearch
rm -rf /var/lib/elasticsearch
rm -rf /var/log/elasticsearch
rm -rf /usr/share/elasticsearch
rm -rf /etc/systemd/system/elasticsearch.service.d

# Kibana
echo "   Removing Kibana files..."
rm -rf /etc/kibana
rm -rf /var/lib/kibana
rm -rf /var/log/kibana
rm -rf /var/run/kibana
rm -rf /usr/share/kibana
rm -rf /etc/systemd/system/kibana.service.d

# Filebeat
echo "   Removing Filebeat files..."
rm -rf /etc/filebeat
rm -rf /var/lib/filebeat
rm -rf /var/log/filebeat
rm -rf /usr/share/filebeat
rm -rf /etc/systemd/system/filebeat.service.d

# Remove users and groups
echo "👥 Removing users and groups..."
for user in elasticsearch kibana; do
    if id "$user" &>/dev/null; then
        echo "   Removing user: $user"
        userdel "$user" 2>/dev/null || true
    fi
    
    if getent group "$user" &>/dev/null; then
        echo "   Removing group: $user"
        groupdel "$user" 2>/dev/null || true
    fi
done

# Clean up systemd
echo "🔄 Cleaning up systemd..."
systemctl daemon-reload

# Remove firewall rules if they exist
echo "🔥 Cleaning up firewall rules..."
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    echo "   Removing firewall rules..."
    firewall-cmd --permanent --remove-port=9200/tcp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=5601/tcp 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
elif command -v ufw >/dev/null 2>&1; then
    echo "   Removing UFW rules..."
    ufw delete allow 9200/tcp 2>/dev/null || true
    ufw delete allow 5601/tcp 2>/dev/null || true
fi

# Remove installation logs
echo "📋 Removing logs..."
rm -f /var/log/elastic-install.log

# Remove deployment packages from current directory
echo "📦 Cleaning up deployment packages..."
rm -f elasticsearch-*.rpm
rm -f kibana-*.rpm
rm -f filebeat-*.rpm
rm -f filebeat-deployment-*.tar.gz
rm -rf filebeat-deployment/

# Remove system modifications
echo "🔧 Cleaning up system modifications..."

# Remove sysctl modifications
if grep -q "vm.max_map_count=262144" /etc/sysctl.conf 2>/dev/null; then
    echo "   Removing sysctl modifications..."
    sed -i '/vm.max_map_count=262144/d' /etc/sysctl.conf
    sysctl vm.max_map_count=65530  # Reset to default
fi

# Remove security limits
if grep -q "elasticsearch" /etc/security/limits.conf 2>/dev/null; then
    echo "   Removing security limits..."
    sed -i '/elasticsearch/d' /etc/security/limits.conf
fi

# Clean up any remaining processes
echo "🔍 Checking for remaining processes..."
for process in elasticsearch kibana filebeat; do
    if pgrep -f "$process" >/dev/null 2>&1; then
        echo "   Killing remaining $process processes..."
        pkill -f "$process" || true
        sleep 2
        pkill -9 -f "$process" 2>/dev/null || true
    fi
done

# Final verification
echo ""
echo -e "${BLUE}🔍 Verification:${NC}"

# Check for remaining packages
remaining_packages=$(rpm -qa | grep -E "(elasticsearch|kibana|filebeat)" || true)
if [[ -n "$remaining_packages" ]]; then
    echo -e "${YELLOW}⚠️  Some packages may still be installed:${NC}"
    echo "$remaining_packages"
else
    echo -e "${GREEN}✅ All packages removed${NC}"
fi

# Check for remaining processes
remaining_processes=$(pgrep -f "(elasticsearch|kibana|filebeat)" || true)
if [[ -n "$remaining_processes" ]]; then
    echo -e "${YELLOW}⚠️  Some processes may still be running:${NC}"
    ps -p $remaining_processes -o pid,cmd || true
else
    echo -e "${GREEN}✅ No remaining processes${NC}"
fi

# Check for remaining directories
remaining_dirs=""
for dir in /etc/elasticsearch /etc/kibana /etc/filebeat /var/lib/elasticsearch /var/lib/kibana /var/lib/filebeat; do
    if [[ -d "$dir" ]]; then
        remaining_dirs="$remaining_dirs $dir"
    fi
done

if [[ -n "$remaining_dirs" ]]; then
    echo -e "${YELLOW}⚠️  Some directories may still exist:${NC}"
    echo "   $remaining_dirs"
    echo "   You may need to remove them manually"
else
    echo -e "${GREEN}✅ All directories removed${NC}"
fi

# Check ports
echo ""
echo -e "${BLUE}🌐 Port status:${NC}"
for port in 9200 5601; do
    if ss -tuln | grep -q ":$port "; then
        echo -e "${YELLOW}⚠️  Port $port is still in use${NC}"
    else
        echo -e "${GREEN}✅ Port $port is free${NC}"
    fi
done

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    CLEANUP COMPLETED                         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"

echo ""
echo -e "${BLUE}📋 Summary:${NC}"
echo "   • Services stopped and disabled"
echo "   • Packages removed"
echo "   • Data directories deleted"
echo "   • Configuration files removed"
echo "   • Users and groups deleted"
echo "   • Firewall rules cleaned up"
echo "   • System modifications reverted"

echo ""
echo -e "${BLUE}🔄 Next Steps:${NC}"
echo "   • System is ready for fresh Elastic Stack installation"
echo "   • You may want to reboot to ensure all changes take effect"
echo "   • Run your installation script to start fresh"

echo ""
echo -e "${GREEN}✅ Cleanup complete! System is ready for fresh installation.${NC}"