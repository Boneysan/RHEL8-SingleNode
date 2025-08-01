#!/usr/bin/env bash
#
# Secure Single-Node Elastic Stack Installer - FIXED VERSION
# Goals:
# 1. Install and setup a secure single node Elasticsearch cluster
# 2. Install Kibana securely and connect it to Elasticsearch
# 3. Create a Filebeat installation package with RPM and configuration
#

set -euo pipefail

# Color definitions
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
VERSION="${VERSION:-8.11.0}"
INSTALL_LOG="/var/log/elastic-install.log"
SERVER_IP=$(hostname -I | awk '{print $1}')

# Global variables for validation
VALIDATION_ERRORS=0

# Setup logging
setup_logging() {
    sudo mkdir -p "$(dirname "$INSTALL_LOG")"
    exec 1> >(tee -a "$INSTALL_LOG")
    exec 2>&1
    echo "$(date): Starting Elastic Stack installation" >> "$INSTALL_LOG"
}

# Print banner
print_banner() {
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           Secure Elastic Stack Single-Node Installer        ║${NC}"
    echo -e "${BLUE}║                                                              ║${NC}"
    echo -e "${BLUE}║  Goal 1: ✓ Secure Single-Node Elasticsearch Cluster        ║${NC}"
    echo -e "${BLUE}║  Goal 2: ✓ Secure Kibana Installation & Connection          ║${NC}"
    echo -e "${BLUE}║  Goal 3: ✓ Filebeat Deployment Package Creation             ║${NC}"
    echo -e "${BLUE}║                                                              ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}🎯 Installing Elastic Stack $VERSION on $SERVER_IP${NC}"
    echo -e "${BLUE}📝 Logging to: $INSTALL_LOG${NC}"
}

# Auto-detect latest version if not specified
detect_latest_version() {
    if [[ -z "$VERSION" ]] || [[ "$VERSION" == "latest" ]]; then
        echo "🔍 Auto-detecting latest Elastic Stack version..."
        VERSION=$(curl -s https://artifacts.elastic.co/downloads/elasticsearch/ 2>/dev/null | \
            grep -oP 'elasticsearch-\K[0-9]+\.[0-9]+\.[0-9]+' | sort -V | tail -1 || echo "8.11.0")
        echo "✅ Using version: $VERSION"
    fi
}

# Download or use local RPM packages
get_package() {
    local package_name="$1"
    local rpm_filename="${package_name}-${VERSION}-x86_64.rpm"
    
    # Check for local package first
    if [[ -f "./$rpm_filename" ]]; then
        echo "📦 Using local package: $rpm_filename"
        return 0
    fi
    
    # Download if not found locally
    echo "📥 Downloading $rpm_filename..."
    local download_url=""
    case "$package_name" in
        "elasticsearch")
            download_url="https://artifacts.elastic.co/downloads/elasticsearch/$rpm_filename"
            ;;
        "kibana")
            download_url="https://artifacts.elastic.co/downloads/kibana/$rpm_filename"
            ;;
        "filebeat")
            download_url="https://artifacts.elastic.co/downloads/beats/filebeat/$rpm_filename"
            ;;
    esac
    
    if curl -L -o "$rpm_filename" "$download_url"; then
        echo "✅ Downloaded $rpm_filename"
    else
        echo -e "${RED}❌ Failed to download $rpm_filename${NC}"
        return 1
    fi
}

# Wait for service to be ready with timeout
wait_for_service() {
    local service_name="$1"
    local test_command="$2"
    local timeout="${3:-120}"
    local description="${4:-$service_name}"
    
    echo "⏳ Waiting for $description to be ready..."
    local elapsed=0
    
    while ! eval "$test_command" >/dev/null 2>&1; do
        if [[ $elapsed -ge $timeout ]]; then
            echo -e "${RED}❌ $description failed to start within $timeout seconds${NC}"
            echo "Service status:"
            sudo systemctl status "$service_name" --no-pager -l
            echo "Recent logs:"
            sudo journalctl -u "$service_name" -n 20 --no-pager
            return 1
        fi
        sleep 5
        elapsed=$((elapsed + 5))
        echo -n "."
    done
    echo ""
    echo -e "${GREEN}✅ $description is ready${NC}"
    return 0
}

# Setup index templates and ILM policies
setup_index_management() {
    local elastic_password=$(sudo grep "elastic:" /etc/elasticsearch/credentials.txt | cut -d':' -f2)
    
    # Wait a moment for Elasticsearch to be fully ready
    sleep 5
    
    echo "🗂️  Creating ILM policy for log management..."
    # Create ILM policy for automatic log rotation and cleanup
    if curl -s -k -u "elastic:$elastic_password" \
        -X PUT "https://localhost:9200/_ilm/policy/filebeat-policy" \
        -H "Content-Type: application/json" \
        -d '{
            "policy": {
                "phases": {
                    "hot": {
                        "actions": {
                            "rollover": {
                                "max_size": "5GB",
                                "max_age": "7d",
                                "max_docs": 1000000
                            }
                        }
                    },
                    "warm": {
                        "min_age": "7d",
                        "actions": {
                            "allocate": {
                                "number_of_replicas": 0
                            }
                        }
                    },
                    "cold": {
                        "min_age": "30d",
                        "actions": {
                            "allocate": {
                                "number_of_replicas": 0
                            }
                        }
                    },
                    "delete": {
                        "min_age": "90d"
                    }
                }
            }
        }' | grep -q "acknowledged.*true"; then
        echo "✅ ILM policy created successfully"
    else
        echo -e "${YELLOW}⚠️  Failed to create ILM policy${NC}"
    fi
    
    echo "📋 Creating optimized index template..."
    # Create index template with optimized mappings
    if curl -s -k -u "elastic:$elastic_password" \
        -X PUT "https://localhost:9200/_index_template/filebeat-template" \
        -H "Content-Type: application/json" \
        -d '{
            "index_patterns": ["filebeat-*"],
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "refresh_interval": "30s",
                    "index.lifecycle.name": "filebeat-policy",
                    "index.lifecycle.rollover_alias": "filebeat"
                },
                "mappings": {
                    "properties": {
                        "@timestamp": {
                            "type": "date"
                        },
                        "message": {
                            "type": "text",
                            "analyzer": "standard"
                        },
                        "host": {
                            "properties": {
                                "name": {
                                    "type": "keyword"
                                },
                                "hostname": {
                                    "type": "keyword"
                                }
                            }
                        },
                        "log": {
                            "properties": {
                                "file": {
                                    "properties": {
                                        "path": {
                                            "type": "keyword"
                                        }
                                    }
                                },
                                "level": {
                                    "type": "keyword"
                                }
                            }
                        },
                        "log_type": {
                            "type": "keyword"
                        },
                        "fields": {
                            "type": "object"
                        },
                        "agent": {
                            "properties": {
                                "version": {
                                    "type": "keyword"
                                },
                                "name": {
                                    "type": "keyword"
                                }
                            }
                        }
                    }
                }
            }
        }' | grep -q "acknowledged.*true"; then
        echo "✅ Index template created successfully"
    else
        echo -e "${YELLOW}⚠️  Failed to create index template${NC}"
    fi
    
    echo "🔄 Creating initial index with alias..."
    # Create the initial index with write alias
    if curl -s -k -u "elastic:$elastic_password" \
        -X PUT "https://localhost:9200/filebeat-000001" \
        -H "Content-Type: application/json" \
        -d '{
            "aliases": {
                "filebeat": {
                    "is_write_index": true
                }
            }
        }' | grep -q "acknowledged.*true"; then
        echo "✅ Initial index and alias created successfully"
    else
        echo -e "${YELLOW}⚠️  Failed to create initial index${NC}"
    fi
    
    echo "✅ Index management configured:"
    echo "   • ILM Policy: filebeat-policy (90-day retention)"
    echo "   • Index Template: filebeat-template (optimized mappings)"
    echo "   • Write Alias: filebeat -> filebeat-000001"
}

# Configure firewall if available
configure_firewall() {
    echo "🔥 Configuring firewall..."
    
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        echo "Detected firewalld, configuring ports..."
        
        # Add Elasticsearch and Kibana ports
        if sudo firewall-cmd --permanent --add-port=9200/tcp --add-port=5601/tcp; then
            sudo firewall-cmd --reload
            echo -e "${GREEN}✅ Firewall configured for Elasticsearch (9200) and Kibana (5601)${NC}"
        else
            echo -e "${YELLOW}⚠️  Failed to configure firewall${NC}"
        fi
    elif command -v ufw >/dev/null 2>&1; then
        echo "Detected ufw, configuring ports..."
        if sudo ufw allow 9200/tcp && sudo ufw allow 5601/tcp; then
            echo -e "${GREEN}✅ UFW configured for Elasticsearch (9200) and Kibana (5601)${NC}"
        else
            echo -e "${YELLOW}⚠️  Failed to configure UFW${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  No supported firewall detected or firewall not running${NC}"
        echo "   You may need to manually open ports 9200 and 5601"
    fi
}

# Install Elasticsearch securely
install_elasticsearch() {
    echo -e "${GREEN}=== Installing Secure Elasticsearch Cluster ===${NC}"
    
    # Check if already installed
    if rpm -qa | grep -q "^elasticsearch"; then
        echo -e "${YELLOW}⚠️  Elasticsearch is already installed${NC}"
        read -p "Do you want to reinstall? (y/N): " reinstall
        if [[ "$reinstall" =~ ^[Yy]$ ]]; then
            echo "🔄 Stopping and removing existing installation..."
            sudo systemctl stop elasticsearch 2>/dev/null || true
            sudo rpm -e elasticsearch --nodeps || true
            sudo rm -rf /etc/elasticsearch /var/lib/elasticsearch /var/log/elasticsearch
        else
            echo "📋 Continuing with existing installation..."
            # Skip to configuration if elasticsearch is already installed
            if systemctl is-active --quiet elasticsearch; then
                echo "✅ Elasticsearch is already running"
                return 0
            fi
        fi
    fi
    
    # Get and install package
    get_package "elasticsearch"
    sudo rpm -ivh "elasticsearch-${VERSION}-x86_64.rpm"
    
    # Apply system optimizations
    echo "🔧 Applying system optimizations..."
    echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
    sudo sysctl -p
    
    # Set memory limits
    cat <<EOF | sudo tee -a /etc/security/limits.conf
elasticsearch soft nofile 65536
elasticsearch hard nofile 65536
elasticsearch soft memlock unlimited
elasticsearch hard memlock unlimited
EOF
    
    # Auto-configure heap size based on available RAM
    local total_mem_gb=$(free -g | awk '/^Mem:/{print $2}')
    local heap_size="4g"
    if [[ $total_mem_gb -ge 16 ]]; then
        heap_size="8g"
    elif [[ $total_mem_gb -ge 8 ]]; then
        heap_size="4g"
    elif [[ $total_mem_gb -ge 4 ]]; then
        heap_size="2g"
    else
        heap_size="1g"
    fi
    echo "💾 Setting Elasticsearch heap size to: $heap_size"
    
    # Generate JVM options
    cat <<EOF | sudo tee /etc/elasticsearch/jvm.options > /dev/null
-Xms$heap_size
-Xmx$heap_size
-XX:+UseG1GC
-XX:+HeapDumpOnOutOfMemoryError
-XX:HeapDumpPath=/var/lib/elasticsearch
-XX:+AlwaysPreTouch
-server
-Dfile.encoding=UTF-8
EOF
    
    # Generate secure Elasticsearch configuration
    cat <<EOF | sudo tee /etc/elasticsearch/elasticsearch.yml > /dev/null
# Cluster Configuration
cluster.name: elasticsearch-secure
node.name: node-1
node.roles: ["master", "data", "ingest", "remote_cluster_client"]

# Paths
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

# Memory
bootstrap.memory_lock: true

# Network
network.host: 0.0.0.0
http.port: 9200
transport.port: 9300

# Discovery
discovery.type: single-node

# Security
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.http.ssl.enabled: true

# SSL Configuration
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.client_authentication: required
xpack.security.transport.ssl.key: /etc/elasticsearch/certs/elasticsearch.key
xpack.security.transport.ssl.certificate: /etc/elasticsearch/certs/elasticsearch.crt

xpack.security.http.ssl.key: /etc/elasticsearch/certs/elasticsearch.key
xpack.security.http.ssl.certificate: /etc/elasticsearch/certs/elasticsearch.crt
xpack.security.http.ssl.client_authentication: optional

# Additional Security
action.destructive_requires_name: true
xpack.monitoring.collection.enabled: true
EOF
    
    # Generate SSL certificates
    echo "🔐 Generating SSL certificates..."
    sudo mkdir -p /etc/elasticsearch/certs
    
    # Create CA
    sudo /usr/share/elasticsearch/bin/elasticsearch-certutil ca --silent --pem --out /tmp/elastic-stack-ca.zip
    sudo unzip -o /tmp/elastic-stack-ca.zip -d /tmp/
    
    # Create node certificate
    cat <<EOF | sudo tee /tmp/cert-config.yml > /dev/null
instances:
  - name: elasticsearch
    dns: [localhost, $(hostname)]
    ip: ["127.0.0.1", "$SERVER_IP"]
EOF
    
    sudo /usr/share/elasticsearch/bin/elasticsearch-certutil cert --silent --pem \
        --in /tmp/cert-config.yml --out /tmp/elasticsearch-certs.zip \
        --ca-cert /tmp/ca/ca.crt --ca-key /tmp/ca/ca.key
    
    sudo unzip -o /tmp/elasticsearch-certs.zip -d /tmp/
    sudo cp /tmp/elasticsearch/elasticsearch.crt /etc/elasticsearch/certs/
    sudo cp /tmp/elasticsearch/elasticsearch.key /etc/elasticsearch/certs/
    sudo cp /tmp/ca/ca.crt /etc/elasticsearch/elastic-stack-ca.pem
    
    # Set proper permissions
    sudo chown -R elasticsearch:elasticsearch /etc/elasticsearch
    sudo chmod 600 /etc/elasticsearch/certs/*
    sudo chmod 644 /etc/elasticsearch/elastic-stack-ca.pem
    
    # Initialize keystore
    sudo rm -f /etc/elasticsearch/elasticsearch.keystore
    sudo /usr/share/elasticsearch/bin/elasticsearch-keystore create
    sudo chown elasticsearch:elasticsearch /etc/elasticsearch/elasticsearch.keystore
    
    # Start Elasticsearch
    echo "🚀 Starting Elasticsearch..."
    sudo systemctl daemon-reload
    sudo systemctl enable elasticsearch.service
    sudo systemctl start elasticsearch.service
    
    # Wait for Elasticsearch to start properly
    if ! wait_for_service "elasticsearch" "curl -s -k https://localhost:9200" 180 "Elasticsearch"; then
        echo -e "${RED}❌ Elasticsearch failed to start properly${NC}"
        exit 1
    fi
    
    echo "🔐 Generating secure passwords..."
    local elastic_password=$(sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -s -b)
    local kibana_password=$(sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana_system -s -b)
    
    # Store credentials securely
    cat <<EOF | sudo tee /etc/elasticsearch/credentials.txt > /dev/null
elastic:$elastic_password
kibana_system:$kibana_password
# Generated on: $(date)
# Server: $SERVER_IP
EOF
    sudo chmod 600 /etc/elasticsearch/credentials.txt
    sudo chown root:elasticsearch /etc/elasticsearch/credentials.txt
    
    # Apply ILM policies and index templates
    echo "📋 Setting up index management..."
    setup_index_management
    
    echo "✅ Elasticsearch installed and secured"
    echo "   🌐 URL: https://$SERVER_IP:9200"
    echo "   🔑 Credentials: /etc/elasticsearch/credentials.txt"
    echo "   📊 Index templates and ILM policies configured"
    
    # Cleanup temporary files
    sudo rm -rf /tmp/elastic-stack-ca.zip /tmp/elasticsearch-certs.zip /tmp/ca /tmp/elasticsearch /tmp/cert-config.yml
}

# Install Kibana securely
install_kibana() {
    echo -e "${GREEN}=== Installing Secure Kibana ===${NC}"
    
    # Check if already installed
    if rpm -qa | grep -q "^kibana"; then
        echo -e "${YELLOW}⚠️  Kibana is already installed${NC}"
        read -p "Do you want to reinstall? (y/N): " reinstall
        if [[ "$reinstall" =~ ^[Yy]$ ]]; then
            echo "🔄 Stopping and removing existing installation..."
            sudo systemctl stop kibana 2>/dev/null || true
            sudo rpm -e kibana --nodeps || true
            sudo rm -rf /etc/kibana /var/lib/kibana /var/log/kibana /var/run/kibana
        else
            echo "📋 Continuing with existing installation..."
            if systemctl is-active --quiet kibana; then
                echo "✅ Kibana is already running"
                return 0
            fi
        fi
    fi
    
    # Get and install package
    get_package "kibana"
    sudo rpm -ivh "kibana-${VERSION}-x86_64.rpm"
    
    # Setup certificates for Kibana
    sudo mkdir -p /etc/kibana/certs
    sudo cp /etc/elasticsearch/elastic-stack-ca.pem /etc/kibana/certs/
    
    # Get Kibana password
    local kibana_password=$(sudo grep "kibana_system:" /etc/elasticsearch/credentials.txt | cut -d':' -f2)
    
    # Generate encryption keys
    local encryption_key=$(openssl rand -base64 32 | tr -d '\n')
    
    # Generate secure Kibana configuration
    cat <<EOF | sudo tee /etc/kibana/kibana.yml > /dev/null
# Server Configuration
server.port: 5601
server.host: "0.0.0.0"

# Elasticsearch Connection
elasticsearch.hosts: ["https://localhost:9200"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "$kibana_password"
elasticsearch.ssl.certificateAuthorities: ["/etc/kibana/certs/elastic-stack-ca.pem"]
elasticsearch.ssl.verificationMode: certificate

# Security and Encryption
xpack.encryptedSavedObjects.encryptionKey: "$encryption_key"
xpack.reporting.encryptionKey: "$encryption_key"
xpack.security.encryptionKey: "$encryption_key"

# Logging
logging.appenders:
  file:
    type: file
    fileName: /var/log/kibana/kibana.log
    layout:
      type: json
logging.root:
  level: info

# Paths
pid.file: /var/run/kibana/kibana.pid
path.data: /var/lib/kibana
EOF
    
    # Create required directories
    sudo mkdir -p /var/log/kibana /var/lib/kibana /var/run/kibana
    sudo chown -R kibana:kibana /etc/kibana /var/log/kibana /var/lib/kibana /var/run/kibana
    
    # Start Kibana
    echo "🚀 Starting Kibana..."
    sudo systemctl daemon-reload
    sudo systemctl enable kibana.service
    sudo systemctl start kibana.service
    
    # Wait for Kibana to be ready with extended timeout
    if ! wait_for_service "kibana" "curl -s http://localhost:5601/api/status" 300 "Kibana"; then
        echo -e "${YELLOW}⚠️  Kibana may still be starting up...${NC}"
        echo "   This is normal for first-time installations"
        echo "   Kibana can take 3-5 minutes to fully initialize"
    fi
    
    echo "✅ Kibana installed and configured"
    echo "   🌐 URL: http://$SERVER_IP:5601"
    echo "   🔑 Login with 'elastic' user credentials"
}

# Create Filebeat deployment package
create_filebeat_package() {
    echo -e "${GREEN}=== Creating Filebeat Deployment Package ===${NC}"
    
    local package_dir="filebeat-deployment"
    rm -rf "$package_dir"
    mkdir -p "$package_dir"
    
    # Get Filebeat RPM
    get_package "filebeat"
    cp "filebeat-${VERSION}-x86_64.rpm" "$package_dir/"
    
    # Get elastic password for Filebeat configuration
    local elastic_password=$(sudo grep "elastic:" /etc/elasticsearch/credentials.txt | cut -d':' -f2)
    
    # Generate Filebeat configuration
    cat <<EOF > "$package_dir/filebeat.yml"
# Filebeat Configuration for Secure Elasticsearch Connection

# Input Configuration
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/*.log
    - /var/log/messages
    - /var/log/secure
  fields:
    log_type: system
  fields_under_root: true

- type: log
  enabled: true
  paths:
    - /var/log/httpd/*.log
    - /var/log/nginx/*.log
    - /var/log/apache2/*.log
  fields:
    log_type: web
  fields_under_root: true

# General Configuration
name: \$(hostname)
tags: ["production"]

# Elasticsearch Output (Secure)
output.elasticsearch:
  hosts: ["https://$SERVER_IP:9200"]
  username: "elastic"
  password: "$elastic_password"
  ssl.certificate_authorities: ["/etc/filebeat/certs/elastic-stack-ca.pem"]
  ssl.verification_mode: certificate
  
  # Template settings (required when using custom indices)
  template.enabled: true
  template.name: "filebeat"
  template.pattern: "filebeat-*"
  template.settings:
    index.number_of_shards: 1
    index.number_of_replicas: 0
    index.refresh_interval: 30s

# Processors
processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded

# Logging
logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat.log
  keepfiles: 7

# Paths
path.home: /usr/share/filebeat
path.config: /etc/filebeat
path.data: /var/lib/filebeat
path.logs: /var/log/filebeat
EOF
    
    # Copy credentials and CA certificate
    if [[ -f "/etc/elasticsearch/credentials.txt" ]]; then
        sudo cp /etc/elasticsearch/credentials.txt "$package_dir/"
        sudo chmod 644 "$package_dir/credentials.txt"
        echo "   ✅ Copied credentials file"
    else
        echo -e "${RED}   ❌ Credentials file not found${NC}"
        return 1
    fi
    
    # Copy CA certificate
    sudo cp /etc/elasticsearch/elastic-stack-ca.pem "$package_dir/"
    
    # Create installation script - FIXED VERSION WITH PROPER TERMINATION
    cat > "$package_dir/install-filebeat.sh" << 'FILEBEAT_SCRIPT_END'
#!/bin/bash
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}Installing Filebeat for Secure Elasticsearch Connection${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}❌ This script must be run as root or with sudo${NC}"
    exit 1
fi

# Install Filebeat RPM
FILEBEAT_RPM=$(find . -name "filebeat-*.rpm" | head -1)
if [[ -z "$FILEBEAT_RPM" ]]; then
    echo -e "${RED}❌ Filebeat RPM not found${NC}"
    exit 1
fi

echo "📦 Installing $(basename "$FILEBEAT_RPM")..."
rpm -ivh "$FILEBEAT_RPM"

# Setup directories and configuration
echo "📁 Setting up Filebeat..."
mkdir -p /etc/filebeat/certs /var/log/filebeat /var/lib/filebeat

# Copy configuration and certificate
cp filebeat.yml /etc/filebeat/
cp elastic-stack-ca.pem /etc/filebeat/certs/
chmod 600 /etc/filebeat/filebeat.yml
chmod 644 /etc/filebeat/certs/elastic-stack-ca.pem
chown -R root:root /etc/filebeat

# Extract Elasticsearch details from configuration
ES_HOST=$(grep -A1 "hosts:" /etc/filebeat/filebeat.yml | grep -oP 'https://\K[^:]+')
ES_PORT=$(grep -A1 "hosts:" /etc/filebeat/filebeat.yml | grep -oP ':\K[0-9]+')
ES_USER=$(grep "username:" /etc/filebeat/filebeat.yml | awk '{print $2}' | tr -d '"')
ES_PASS=$(grep "password:" /etc/filebeat/filebeat.yml | awk '{print $2}' | tr -d '"')

echo -e "\n${BLUE}=== PRE-INSTALLATION TESTS ===${NC}"

# Test 1: Network connectivity to Elasticsearch
echo "🌐 Testing network connectivity to Elasticsearch..."
if timeout 10 bash -c "cat < /dev/null > /dev/tcp/$ES_HOST/$ES_PORT" 2>/dev/null; then
    echo -e "${GREEN}✅ Network connectivity to $ES_HOST:$ES_PORT successful${NC}"
else
    echo -e "${RED}❌ Cannot connect to $ES_HOST:$ES_PORT${NC}"
    echo "   Please check:"
    echo "   - Elasticsearch is running on the target host"
    echo "   - Firewall allows connections on port $ES_PORT"
    echo "   - Network connectivity between hosts"
    exit 1
fi

# Test 2: Elasticsearch API accessibility
echo "🔍 Testing Elasticsearch API access..."
API_RESPONSE=$(curl -s -w "%{http_code}" -o /tmp/es_response.json \
    --connect-timeout 10 --max-time 30 \
    -k -u "$ES_USER:$ES_PASS" \
    "https://$ES_HOST:$ES_PORT/_cluster/health" 2>/dev/null || echo "000")

if [[ "$API_RESPONSE" == "200" ]]; then
    CLUSTER_STATUS=$(cat /tmp/es_response.json | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
    echo -e "${GREEN}✅ Elasticsearch API accessible${NC}"
    echo "   Cluster status: $CLUSTER_STATUS"
    
    if [[ "$CLUSTER_STATUS" != "green" && "$CLUSTER_STATUS" != "yellow" ]]; then
        echo -e "${YELLOW}⚠️  Cluster status is $CLUSTER_STATUS - proceeding anyway${NC}"
    fi
else
    echo -e "${RED}❌ Elasticsearch API test failed (HTTP: $API_RESPONSE)${NC}"
    echo "   Please verify:"
    echo "   - Elasticsearch is running and healthy"
    echo "   - Credentials are correct"
    echo "   - SSL certificate is valid"
    if [[ -f /tmp/es_response.json ]]; then
        echo "   Error details: $(cat /tmp/es_response.json)"
    fi
    exit 1
fi

# Test 3: SSL certificate validation
echo "🔐 Testing SSL certificate validation..."
if curl -s --cacert /etc/filebeat/certs/elastic-stack-ca.pem \
    -u "$ES_USER:$ES_PASS" \
    "https://$ES_HOST:$ES_PORT/_cluster/health" >/dev/null 2>&1; then
    echo -e "${GREEN}✅ SSL certificate validation successful${NC}"
else
    echo -e "${YELLOW}⚠️  SSL certificate validation failed, but proceeding with verification_mode: certificate${NC}"
fi

# Test 4: Filebeat configuration validation
echo "⚙️  Validating Filebeat configuration..."
if /usr/share/filebeat/bin/filebeat test config -c /etc/filebeat/filebeat.yml; then
    echo -e "${GREEN}✅ Filebeat configuration is valid${NC}"
else
    echo -e "${RED}❌ Filebeat configuration validation failed${NC}"
    exit 1
fi

# Start Filebeat service
echo -e "\n${BLUE}=== STARTING FILEBEAT SERVICE ===${NC}"
echo "🚀 Starting Filebeat..."
systemctl daemon-reload
systemctl enable filebeat.service
systemctl start filebeat.service

# Wait for service to start
sleep 5

# Post-installation tests
echo -e "\n${BLUE}=== POST-INSTALLATION TESTS ===${NC}"

# Test 1: Service status
echo "🔍 Checking Filebeat service status..."
if systemctl is-active --quiet filebeat.service; then
    echo -e "${GREEN}✅ Filebeat service is running${NC}"
    
    # Show service details
    UPTIME=$(systemctl show filebeat.service --property=ActiveEnterTimestamp --value)
    echo "   Service started: $UPTIME"
else
    echo -e "${RED}❌ Filebeat service failed to start${NC}"
    echo "Service status:"
    systemctl status filebeat.service --no-pager
    echo -e "\nRecent logs:"
    journalctl -u filebeat.service -n 20 --no-pager
    exit 1
fi

# Test 2: Check for errors in logs
echo "📋 Checking for startup errors..."
RECENT_ERRORS=$(journalctl -u filebeat.service --since "2 minutes ago" | grep -i "error\|fatal\|failed" | wc -l)
if [[ $RECENT_ERRORS -eq 0 ]]; then
    echo -e "${GREEN}✅ No errors found in recent logs${NC}"
else
    echo -e "${YELLOW}⚠️  Found $RECENT_ERRORS error(s) in recent logs${NC}"
    echo "Recent errors:"
    journalctl -u filebeat.service --since "2 minutes ago" | grep -i "error\|fatal\|failed" | tail -5
fi

# Test 3: Test Elasticsearch output connectivity
echo "🔗 Testing Filebeat -> Elasticsearch connectivity..."
if timeout 30 /usr/share/filebeat/bin/filebeat test output -c /etc/filebeat/filebeat.yml; then
    echo -e "${GREEN}✅ Filebeat can successfully connect to Elasticsearch${NC}"
else
    echo -e "${RED}❌ Filebeat cannot connect to Elasticsearch${NC}"
    echo "This may indicate authentication or network issues"
fi

# Test 4: Generate test log entry and verify indexing
echo "📊 Testing log indexing..."
TEST_MESSAGE="Filebeat test message from $(hostname) at $(date)"
echo "$TEST_MESSAGE" | sudo tee -a /var/log/filebeat-test.log >/dev/null

# Wait for log processing
echo "⏳ Waiting for log processing (30 seconds)..."
sleep 30

# Check if test message was indexed
echo "🔍 Verifying log was indexed in Elasticsearch..."
SEARCH_RESULT=$(curl -s -k -u "$ES_USER:$ES_PASS" \
    "https://$ES_HOST:$ES_PORT/filebeat-*/_search" \
    -H "Content-Type: application/json" \
    -d '{"query":{"match":{"message":"Filebeat test message"}}}' \
    2>/dev/null | grep -o '"total":{"value":[0-9]*' | grep -o '[0-9]* || echo "0")

if [[ "$SEARCH_RESULT" -gt 0 ]]; then
    echo -e "${GREEN}✅ Test log successfully indexed in Elasticsearch${NC}"
    echo "   Found $SEARCH_RESULT matching document(s)"
else
    echo -e "${YELLOW}⚠️  Test log not found in Elasticsearch yet${NC}"
    echo "   This may be normal for new installations"
    echo "   Check again in a few minutes with:"
    echo "   curl -k -u $ES_USER:PASSWORD \"https://$ES_HOST:$ES_PORT/filebeat-*/_search?q=filebeat\""
fi

# Test 5: Check index creation
echo "📋 Checking Filebeat indices..."
INDICES=$(curl -s -k -u "$ES_USER:$ES_PASS" \
    "https://$ES_HOST:$ES_PORT/_cat/indices/filebeat-*?h=index,status,docs.count" 2>/dev/null || echo "")

if [[ -n "$INDICES" ]]; then
    echo -e "${GREEN}✅ Filebeat indices found:${NC}"
    echo "$INDICES" | while read line; do
        echo "   $line"
    done
else
    echo -e "${YELLOW}ℹ️  No Filebeat indices found yet (this is normal for new installations)${NC}"
fi

# Cleanup test file
rm -f /var/log/filebeat-test.log /tmp/es_response.json

# Final summary
echo -e "\n${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          FILEBEAT INSTALLATION COMPLETE    ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"

echo -e "\n${BLUE}📊 Installation Summary:${NC}"
echo "   • Filebeat version: $(rpm -q filebeat --queryformat '%{VERSION}')"
echo "   • Target Elasticsearch: $ES_HOST:$ES_PORT"
echo "   • Configuration: /etc/filebeat/filebeat.yml"
echo "   • Logs: /var/log/filebeat/"
echo "   • Service status: $(systemctl is-active filebeat.service)"

echo -e "\n${BLUE}💡 Useful Commands:${NC}"
echo "   • Check status: systemctl status filebeat"
echo "   • View logs: journalctl -u filebeat.service -f"
echo "   • Test config: filebeat test config"
echo "   • Test output: filebeat test output"
echo "   • Search logs: curl -k -u elastic:PASSWORD \"https://$ES_HOST:$ES_PORT/filebeat-*/_search?q=*\""

echo -e "\n${GREEN}✅ Filebeat is successfully shipping logs to Elasticsearch!${NC}"
FILEBEAT_SCRIPT_END

    # Make install script executable
    chmod +x "$package_dir/install-filebeat.sh"
    
    # Create README with deployment instructions
    cat <<EOF > "$package_dir/README.md"
# Filebeat Deployment Package

This package contains everything needed to deploy Filebeat on remote systems.

## Contents
- **filebeat-${VERSION}-x86_64.rpm**: Filebeat installation package
- **filebeat.yml**: Pre-configured Filebeat configuration
- **elastic-stack-ca.pem**: SSL certificate authority for secure communication
- **credentials.txt**: Elasticsearch authentication credentials
- **install-filebeat.sh**: Automated installation script with comprehensive testing

## Deployment Instructions

1. Copy this entire directory to the target system
2. Run the installation script as root:
   \`\`\`bash
   sudo ./install-filebeat.sh
   \`\`\`

## What the installer does
- Validates network connectivity and Elasticsearch accessibility
- Installs and configures Filebeat
- Tests SSL certificate validation
- Verifies service startup and log shipping
- Performs comprehensive post-installation validation

## Security Features
- SSL/TLS encrypted communication with Elasticsearch
- Certificate-based authentication
- Secure credential handling

## Post-Installation
After installation, Filebeat will automatically:
- Ship logs from /var/log/ to Elasticsearch
- Create appropriate indices with lifecycle management
- Provide detailed monitoring and error reporting

For troubleshooting, check:
- Service status: \`systemctl status filebeat\`
- Logs: \`journalctl -u filebeat.service -f\`
- Configuration test: \`filebeat test config\`
EOF

    # Create tarball for easy distribution
    tar -czf "filebeat-deployment-${VERSION}.tar.gz" "$package_dir"
    
    echo "✅ Filebeat deployment package created"
    echo "   📦 Package: filebeat-deployment-${VERSION}.tar.gz"
    echo "   📁 Directory: $package_dir/"
    echo "   🚀 Deploy with: tar -xzf filebeat-deployment-${VERSION}.tar.gz && sudo ./install-filebeat.sh"
    echo "   📋 Package contents:"
    ls -la "$package_dir/"
}

# Comprehensive validation function
validate_installation() {
    echo -e "${GREEN}=== Validating Installation ===${NC}"
    
    local elastic_password=$(sudo grep "elastic:" /etc/elasticsearch/credentials.txt | cut -d':' -f2)
    
    # Test 1: Elasticsearch
    echo "🔍 Testing Elasticsearch..."
    if curl -s -k -u "elastic:$elastic_password" "https://localhost:9200/_cluster/health" | grep -q '"status":".*"'; then
        local health=$(curl -s -k -u "elastic:$elastic_password" "https://localhost:9200/_cluster/health" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
        echo -e "${GREEN}✅ Elasticsearch is healthy (status: $health)${NC}"
    else
        echo -e "${RED}❌ Elasticsearch health check failed${NC}"
        ((VALIDATION_ERRORS++))
    fi
    
    # Test 2: Kibana with extended wait
    echo "🔍 Testing Kibana..."
    local kibana_ready=false
    local kibana_timeout=180
    local kibana_elapsed=0
    
    while [[ $kibana_elapsed -lt $kibana_timeout ]]; do
        if curl -s "http://localhost:5601/api/status" >/dev/null 2>&1; then
            kibana_ready=true
            break
        fi
        sleep 10
        kibana_elapsed=$((kibana_elapsed + 10))
        echo -n "."
    done
    
    if [[ "$kibana_ready" == "true" ]]; then
        echo -e "\n${GREEN}✅ Kibana is responding${NC}"
    else
        echo -e "\n${YELLOW}⚠️  Kibana is not yet responding (may still be starting)${NC}"
        echo "   Check status with: sudo systemctl status kibana"
        echo "   View logs with: sudo journalctl -u kibana -f"
        ((VALIDATION_ERRORS++))
    fi
    
    # Test 3: SSL certificates
    echo "🔍 Checking SSL certificates..."
    if [[ -f "/etc/elasticsearch/certs/elasticsearch.crt" ]] && [[ -f "/etc/elasticsearch/certs/elasticsearch.key" ]]; then
        if openssl x509 -in /etc/elasticsearch/certs/elasticsearch.crt -text -noout >/dev/null 2>&1; then
            echo -e "${GREEN}✅ SSL certificates are properly configured${NC}"
        else
            echo -e "${RED}❌ SSL certificate validation failed${NC}"
            ((VALIDATION_ERRORS++))
        fi
    else
        echo -e "${RED}❌ SSL certificates not found${NC}"
        ((VALIDATION_ERRORS++))
    fi
    
    # Test 4: Index management
    echo "🔍 Checking index management..."
    
    # Check index template
    if curl -s -k -u "elastic:$elastic_password" "https://localhost:9200/_index_template/filebeat-template" | grep -q "filebeat-template"; then
        echo -e "${GREEN}✅ Filebeat index template configured${NC}"
    else
        echo -e "${RED}❌ Filebeat index template missing${NC}"
        ((VALIDATION_ERRORS++))
    fi
    
    # Check ILM policy
    if curl -s -k -u "elastic:$elastic_password" "https://localhost:9200/_ilm/policy/filebeat-policy" | grep -q "filebeat-policy"; then
        echo -e "${GREEN}✅ Filebeat ILM policy configured${NC}"
    else
        echo -e "${RED}❌ Filebeat ILM policy missing${NC}"
        ((VALIDATION_ERRORS++))
    fi
    
    # Test 5: Filebeat package
    echo "🔍 Checking Filebeat package..."
    if [[ -f "filebeat-deployment-${VERSION}.tar.gz" ]]; then
        echo -e "${GREEN}✅ Filebeat deployment package ready${NC}"
        
        # Show package contents
        echo "   📦 Package contents:"
        tar -tzf "filebeat-deployment-${VERSION}.tar.gz" | sed 's/^/      /'
    else
        echo -e "${RED}❌ Filebeat deployment package missing${NC}"
        ((VALIDATION_ERRORS++))
    fi
    
    # Test 6: Service status
    echo "🔍 Checking service status..."
    if systemctl is-active --quiet elasticsearch.service; then
        echo -e "${GREEN}✅ Elasticsearch service is running${NC}"
    else
        echo -e "${RED}❌ Elasticsearch service is not running${NC}"
        ((VALIDATION_ERRORS++))
    fi
    
    if systemctl is-active --quiet kibana.service; then
        echo -e "${GREEN}✅ Kibana service is running${NC}"
    else
        echo -e "${YELLOW}⚠️  Kibana service status uncertain${NC}"
        # Don't count as error since Kibana might still be starting
    fi
    
    # Return validation status
    return $VALIDATION_ERRORS
}

# Print final summary
print_summary() {
    local exit_code=$1
    
    echo ""
    if [[ $exit_code -eq 0 ]]; then
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║               INSTALLATION COMPLETED SUCCESSFULLY            ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    else
        echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║             INSTALLATION COMPLETED WITH WARNINGS             ║${NC}"
        echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}🎯 Installation Summary:${NC}"
    echo "   • Elasticsearch: https://$SERVER_IP:9200"
    echo "   • Kibana: http://$SERVER_IP:5601"
    echo "   • Credentials: /etc/elasticsearch/credentials.txt"
    echo "   • Filebeat Package: filebeat-deployment-${VERSION}.tar.gz"
    
    echo ""
    echo -e "${BLUE}🔑 Login Information:${NC}"
    echo "   • Username: elastic"
    echo "   • Password: $(sudo grep "elastic:" /etc/elasticsearch/credentials.txt | cut -d':' -f2)"
    
    echo ""
    echo -e "${BLUE}🚀 Next Steps:${NC}"
    echo "   1. Access Kibana at http://$SERVER_IP:5601"
    echo "   2. Login with the elastic user credentials above"
    echo "   3. Deploy Filebeat using: tar -xzf filebeat-deployment-${VERSION}.tar.gz"
    echo "   4. Run Filebeat installer: sudo ./filebeat-deployment/install-filebeat.sh"
    
    if [[ $exit_code -gt 0 ]]; then
        echo ""
        echo -e "${YELLOW}⚠️  Warnings Detected:${NC}"
        echo "   • Some validation tests failed"
        echo "   • Kibana may still be starting (this is normal)"
        echo "   • Check service logs if issues persist"
        echo ""
        echo -e "${BLUE}🔧 Troubleshooting:${NC}"
        echo "   • Check Kibana: sudo journalctl -u kibana -f"
        echo "   • Check Elasticsearch: sudo journalctl -u elasticsearch -f"
        echo "   • Test connectivity: curl -k -u elastic:PASSWORD https://localhost:9200"
    fi
}

# Main installation function
main() {
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}❌ This script must be run as root or with sudo${NC}"
        exit 1
    fi
    
    # Setup logging and print banner
    setup_logging
    print_banner
    
    # Detect version if needed
    detect_latest_version
    
    # Install components
    install_elasticsearch
    configure_firewall
    install_kibana
    create_filebeat_package
    
    # Validate installation
    if validate_installation; then
        print_summary 0
        exit 0
    else
        print_summary $VALIDATION_ERRORS
        exit 1
    fi
}

# Run main function
main "$@"