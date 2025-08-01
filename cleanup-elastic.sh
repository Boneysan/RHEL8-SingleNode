#!/usr/bin/env bash
#
# Combined Elastic Stack Cleanup Script
# Completely removes Elasticsearch, Kibana, and Filebeat installations
# Supports both standard and force cleanup modes
#

set -euo pipefail

# Color definitions
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Script mode
FORCE_MODE=false
QUIET_MODE=false

# Show usage information
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Completely removes Elasticsearch, Kibana, and Filebeat installations"
    echo ""
    echo "Options:"
    echo "  -f, --force     Force removal mode (aggressive cleanup)"
    echo "  -q, --quiet     Quiet mode (skip confirmation prompts)"
    echo "  -h, --help      Show this help message"
    echo ""
    echo "Standard Mode:"
    echo "  • Graceful service shutdown"
    echo "  • Standard package removal"
    echo "  • Safe cleanup procedures"
    echo ""
    echo "Force Mode (-f):"
    echo "  • Force kills all processes"
    echo "  • Aggressive package removal"
    echo "  • Deep system cleanup"
    echo "  • Use when standard cleanup fails"
    echo ""
    echo "Examples:"
    echo "  $0                    # Standard cleanup with confirmation"
    echo "  $0 -f                 # Force cleanup with confirmation"
    echo "  $0 -q                 # Standard cleanup without confirmation"
    echo "  $0 -f -q              # Force cleanup without confirmation"
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -f|--force)
                FORCE_MODE=true
                shift
                ;;
            -q|--quiet)
                QUIET_MODE=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Print banner
print_banner() {
    if [[ "$FORCE_MODE" == "true" ]]; then
        echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║              FORCE CLEANUP - AGGRESSIVE REMOVAL              ║${NC}"
        echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
    else
        echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║                Elastic Stack Cleanup Script                  ║${NC}"
        echo -e "${BLUE}║                                                              ║${NC}"
        echo -e "${BLUE}║  This will completely remove Elasticsearch, Kibana, and     ║${NC}"
        echo -e "${BLUE}║  Filebeat installations including all data and configs      ║${NC}"
        echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    fi
    echo ""
}

# Get confirmation from user
get_confirmation() {
    if [[ "$QUIET_MODE" == "true" ]]; then
        return 0
    fi
    
    echo -e "${YELLOW}⚠️  WARNING: This will permanently delete:${NC}"
    echo "   • All Elasticsearch data and indices"
    echo "   • All Kibana configurations and saved objects"
    echo "   • All SSL certificates and credentials"
    echo "   • All log files and configuration files"
    echo "   • All users and groups"
    echo ""
    
    if [[ "$FORCE_MODE" == "true" ]]; then
        echo -e "${RED}🔥 FORCE MODE: Using aggressive removal methods${NC}"
        echo ""
    fi
    
    read -p "Are you sure you want to proceed? (yes/NO): " confirm
    if [[ "$confirm" != "yes" ]]; then
        echo "Cleanup cancelled."
        exit 0
    fi
}

# Stop services
stop_services() {
    echo "🛑 Stopping services..."
    
    if [[ "$FORCE_MODE" == "true" ]]; then
        # Force mode: Kill processes first, then stop services
        echo "💀 Force killing all Elastic processes..."
        pkill -9 -f elasticsearch 2>/dev/null || true
        pkill -9 -f kibana 2>/dev/null || true
        pkill -9 -f filebeat 2>/dev/null || true
        sleep 2
    fi
    
    # Stop and disable services
    for service in elasticsearch kibana filebeat; do
        if systemctl list-units --type=service | grep -q "$service"; then
            if systemctl is-active --quiet "$service" 2>/dev/null; then
                echo "   Stopping $service..."
                if [[ "$FORCE_MODE" == "true" ]]; then
                    systemctl kill "$service" 2>/dev/null || true
                    sleep 1
                fi
                systemctl stop "$service" 2>/dev/null || true
            fi
            
            if systemctl is-enabled --quiet "$service" 2>/dev/null; then
                echo "   Disabling $service..."
                systemctl disable "$service" 2>/dev/null || true
            fi
        fi
    done
}

# Remove packages
remove_packages() {
    echo "📦 Removing packages..."
    
    if [[ "$FORCE_MODE" == "true" ]]; then
        # Force mode: More aggressive package removal
        rpm -qa | grep -E "(elasticsearch|kibana|filebeat)" | while read package; do
            echo "   Force removing: $package"
            rpm -e "$package" --nodeps --noscripts --notriggers 2>/dev/null || true
        done
        
        # Clean RPM database
        echo "🗃️  Cleaning RPM database..."
        rpm --rebuilddb 2>/dev/null || true
    else
        # Standard mode: Normal package removal
        for package in elasticsearch kibana filebeat; do
            if rpm -qa | grep -q "^$package"; then
                echo "   Removing $package..."
                rpm -e "$package" --nodeps 2>/dev/null || true
            fi
        done
    fi
}

# Remove directories and files
remove_directories() {
    echo "🗂️  Removing directories and files..."
    
    # Elasticsearch
    echo "   Removing Elasticsearch files..."
    rm -rf /etc/elasticsearch* /var/lib/elasticsearch* /var/log/elasticsearch* /usr/share/elasticsearch*
    
    # Kibana
    echo "   Removing Kibana files..."
    rm -rf /etc/kibana* /var/lib/kibana* /var/log/kibana* /var/run/kibana* /usr/share/kibana*
    
    # Filebeat
    echo "   Removing Filebeat files..."
    rm -rf /etc/filebeat* /var/lib/filebeat* /var/log/filebeat* /usr/share/filebeat*
    
    # Remove systemd files
    echo "   Removing systemd files..."
    rm -f /usr/lib/systemd/system/elasticsearch.service
    rm -f /usr/lib/systemd/system/kibana.service
    rm -f /usr/lib/systemd/system/filebeat.service
    rm -rf /etc/systemd/system/elasticsearch.service.d
    rm -rf /etc/systemd/system/kibana.service.d
    rm -rf /etc/systemd/system/filebeat.service.d
    
    if [[ "$FORCE_MODE" == "true" ]]; then
        # Force mode: Additional cleanup
        echo "   Deep cleaning remaining files..."
        find /opt -name "*elastic*" -type d -exec rm -rf {} + 2>/dev/null || true
        find /tmp -name "*elastic*" -exec rm -rf {} + 2>/dev/null || true
        find /var/tmp -name "*elastic*" -exec rm -rf {} + 2>/dev/null || true
    fi
}

# Remove users and groups
remove_users() {
    echo "👥 Removing users and groups..."
    
    for user in elasticsearch kibana; do
        if [[ "$FORCE_MODE" == "true" ]]; then
            # Force mode: Kill any remaining processes by user
            pkill -9 -u "$user" 2>/dev/null || true
        fi
        
        if id "$user" &>/dev/null; then
            echo "   Removing user: $user"
            userdel -r "$user" 2>/dev/null || true
        fi
        
        if getent group "$user" &>/dev/null; then
            echo "   Removing group: $user"
            groupdel "$user" 2>/dev/null || true
        fi
    done
}

# Clean up system modifications
cleanup_system_modifications() {
    echo "🔧 Cleaning up system modifications..."
    
    # Remove sysctl modifications
    if grep -q "vm.max_map_count.*262144" /etc/sysctl.conf 2>/dev/null; then
        echo "   Removing sysctl modifications..."
        sed -i '/vm.max_map_count.*262144/d' /etc/sysctl.conf
        sysctl vm.max_map_count=65530 2>/dev/null || true
    fi
    
    # Remove security limits
    if grep -q "elasticsearch" /etc/security/limits.conf 2>/dev/null; then
        echo "   Removing security limits..."
        sed -i '/elasticsearch/d' /etc/security/limits.conf
    fi
    
    # Check for mounted filesystems
    if [[ "$FORCE_MODE" == "true" ]]; then
        echo "💾 Checking for mounted filesystems..."
        mount | grep -E "(elasticsearch|kibana|filebeat)" | awk '{print $3}' | while read mountpoint; do
            echo "   Unmounting: $mountpoint"
            umount "$mountpoint" 2>/dev/null || true
        done
    fi
}

# Clean firewall rules
cleanup_firewall() {
    echo "🔥 Cleaning up firewall rules..."
    
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        echo "   Removing firewall rules..."
        firewall-cmd --permanent --remove-port=9200/tcp 2>/dev/null || true
        firewall-cmd --permanent --remove-port=5601/tcp 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
        if [[ $? -eq 0 ]]; then
            echo "   Firewall rules removed successfully"
        fi
    elif command -v ufw >/dev/null 2>&1; then
        echo "   Removing UFW rules..."
        ufw delete allow 9200/tcp 2>/dev/null || true
        ufw delete allow 5601/tcp 2>/dev/null || true
    else
        echo "   No supported firewall detected"
    fi
}

# Clean up logs and deployment packages
cleanup_files() {
    echo "📋 Removing logs and deployment packages..."
    
    # Remove installation logs
    rm -f /var/log/elastic-install.log
    
    # Remove deployment packages from current directory
    echo "📦 Cleaning up deployment packages..."
    rm -f elasticsearch-*.rpm
    rm -f kibana-*.rpm
    rm -f filebeat-*.rpm
    rm -f filebeat-deployment-*.tar.gz
    rm -rf filebeat-deployment/
    rm -rf elastic-packages/
}

# Reload systemd
reload_systemd() {
    echo "🔄 Reloading systemd..."
    systemctl daemon-reload
}

# Check for remaining processes
check_remaining_processes() {
    echo "🔍 Checking for remaining processes..."
    
    local remaining_processes=$(pgrep -f "(elasticsearch|kibana|filebeat)" || true)
    if [[ -n "$remaining_processes" ]]; then
        echo -e "${YELLOW}⚠️  Found remaining processes:${NC}"
        ps -p $remaining_processes -o pid,cmd || true
        
        if [[ "$FORCE_MODE" == "true" ]]; then
            echo "   Force killing remaining processes..."
            kill -9 $remaining_processes 2>/dev/null || true
        fi
    else
        echo -e "${GREEN}✅ No remaining processes${NC}"
    fi
}

# Perform final verification
final_verification() {
    echo ""
    echo -e "${BLUE}🔍 Final Verification:${NC}"
    
    # Check for remaining packages
    local remaining_packages=$(rpm -qa | grep -E "(elasticsearch|kibana|filebeat)" || true)
    if [[ -n "$remaining_packages" ]]; then
        echo -e "${YELLOW}⚠️  Some packages may still be installed:${NC}"
        echo "$remaining_packages"
        
        if [[ "$FORCE_MODE" == "true" ]]; then
            echo "   Attempting final package removal..."
            echo "$remaining_packages" | while read pkg; do
                rpm -e "$pkg" --nodeps --noscripts --notriggers --force 2>/dev/null || true
            done
        fi
    else
        echo -e "${GREEN}✅ All packages removed${NC}"
    fi
    
    # Check for remaining processes
    check_remaining_processes
    
    # Check for remaining directories
    local remaining_dirs=""
    for dir in /etc/elasticsearch /etc/kibana /etc/filebeat /var/lib/elasticsearch /var/lib/kibana /var/lib/filebeat /usr/share/elasticsearch /usr/share/kibana /usr/share/filebeat; do
        if [[ -d "$dir" ]]; then
            remaining_dirs="$remaining_dirs $dir"
        fi
    done
    
    if [[ -n "$remaining_dirs" ]]; then
        echo -e "${YELLOW}⚠️  Some directories may still exist:${NC}"
        echo "   $remaining_dirs"
        
        if [[ "$FORCE_MODE" == "true" ]]; then
            echo "   Force removing remaining directories..."
            rm -rf $remaining_dirs 2>/dev/null || true
        else
            echo "   You may need to remove them manually or use --force mode"
        fi
    else
        echo -e "${GREEN}✅ All directories removed${NC}"
    fi
    
    # Check ports
    echo ""
    echo -e "${BLUE}🌐 Port Status:${NC}"
    for port in 9200 5601; do
        if ss -tuln | grep -q ":$port "; then
            echo -e "${YELLOW}⚠️  Port $port is still in use${NC}"
            if [[ "$FORCE_MODE" == "true" ]]; then
                echo "   Processes using port $port:"
                lsof -i :$port 2>/dev/null || netstat -tlnp | grep ":$port " || true
            fi
        else
            echo -e "${GREEN}✅ Port $port is free${NC}"
        fi
    done
}

# Print final summary
print_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    CLEANUP COMPLETED                         ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    
    echo ""
    echo -e "${BLUE}📋 Cleanup Summary:${NC}"
    echo "   • Mode: $([ "$FORCE_MODE" == "true" ] && echo "Force cleanup" || echo "Standard cleanup")"
    echo "   • Services stopped and disabled"
    echo "   • Packages removed"
    echo "   • Data directories deleted"
    echo "   • Configuration files removed"
    echo "   • Users and groups deleted"
    echo "   • Firewall rules cleaned up"
    echo "   • System modifications reverted"
    echo "   • Deployment packages cleaned"
    
    echo ""
    echo -e "${BLUE}🔄 Recommendations:${NC}"
    if [[ "$FORCE_MODE" == "true" ]]; then
        echo "   • Force cleanup completed - system should be completely clean"
        echo "   • Reboot recommended to ensure all changes take effect"
    else
        echo "   • Standard cleanup completed"
        echo "   • If any issues remain, try running with --force flag"
        echo "   • Reboot recommended for complete cleanup"
    fi
    
    echo "   • System is ready for fresh Elastic Stack installation"
    echo "   • Run your installation script to start fresh"
    
    echo ""
    echo -e "${GREEN}✅ Cleanup complete! System is ready for fresh installation.${NC}"
}

# Main cleanup function
main() {
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}❌ This script must be run as root or with sudo${NC}"
        exit 1
    fi
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Print banner
    print_banner
    
    # Get user confirmation
    get_confirmation
    
    echo ""
    if [[ "$FORCE_MODE" == "true" ]]; then
        echo -e "${YELLOW}🔥 Starting FORCE cleanup of Elastic Stack...${NC}"
    else
        echo -e "${BLUE}🧹 Starting cleanup of Elastic Stack...${NC}"
    fi
    echo ""
    
    # Execute cleanup steps
    stop_services
    remove_packages
    remove_directories
    remove_users
    cleanup_system_modifications
    cleanup_firewall
    cleanup_files
    reload_systemd
    
    # Verify cleanup
    final_verification
    
    # Show summary
    print_summary
}

# Run main function with all arguments
main "$@"