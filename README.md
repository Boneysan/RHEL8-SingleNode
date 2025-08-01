# Secure Elastic Stack Single-Node Installer

A comprehensive, production-ready installer for Elasticsearch, Kibana, and Filebeat with enterprise-grade security, SSL encryption, and automated deployment capabilities.

## 🚀 Features

- **Secure Single-Node Elasticsearch** with X-Pack security enabled
- **SSL/TLS Encryption** for all communications
- **Automated Certificate Generation** with proper hostname/IP validation
- **Kibana Integration** with secure Elasticsearch connection
- **Filebeat Deployment Package** with comprehensive testing
- **Index Lifecycle Management (ILM)** for automated log rotation
- **Firewall Auto-Configuration** for remote access
- **Production Optimizations** including memory tuning and system limits
- **Comprehensive Validation** with detailed error reporting
- **Offline Installation Support** with package downloader

## 📋 System Requirements

### Hardware
- **RAM**: Minimum 4GB, Recommended 8GB+
- **Disk**: 20GB+ free space
- **CPU**: 2+ cores recommended

### Operating System
- **RHEL/CentOS 8+**
- **Rocky Linux 8+**
- **AlmaLinux 8+**
- Root or sudo access required

### Network
- **Ports**: 9200 (Elasticsearch), 5601 (Kibana)
- **Internet access** for downloads (unless using offline installation)

## 📁 Repository Contents

```
elastic-stack-installer/
├── install-elastic-stack.sh      # Main installer script
├── download-elastic-packages.sh   # Package downloader for offline installation
├── cleanup-elastic.sh             # Complete removal script
├── force-cleanup.sh               # Aggressive cleanup for stuck installations
└── README.md                      # This file
```

## 🔧 Quick Start

### Standard Installation (Online)

```bash
# Download and run the main installer
chmod +x install-elastic-stack.sh
sudo ./install-elastic-stack.sh
```

### Offline Installation

```bash
# Step 1: Download packages (requires internet)
chmod +x download-elastic-packages.sh
./download-elastic-packages.sh

# Step 2: Copy packages to installer directory
cp elastic-packages/*.rpm .

# Step 3: Run installer (no internet required)
sudo ./install-elastic-stack.sh
```

## 📊 Installation Process

The installer performs the following steps:

### 1. **System Preparation**
- Sets system limits and memory map count
- Configures heap sizes based on available RAM
- Applies security optimizations

### 2. **Elasticsearch Installation**
- Downloads/installs Elasticsearch RPM
- Generates SSL certificates with proper SAN entries
- Creates secure configuration with X-Pack security
- Sets up strong passwords for system users
- Configures Index Lifecycle Management policies

### 3. **Kibana Installation**
- Downloads/installs Kibana RPM
- Configures secure connection to Elasticsearch
- Sets up encryption keys for saved objects
- Optimizes for production use

### 4. **Firewall Configuration**
- Automatically opens required ports (9200, 5601)
- Supports both firewalld and UFW
- Gracefully handles systems without firewalls

### 5. **Filebeat Package Creation**
- Downloads Filebeat RPM
- Generates pre-configured deployment package
- Creates comprehensive installation script with testing
- Packages everything for easy distribution

### 6. **Validation & Testing**
- Tests Elasticsearch cluster health
- Verifies Kibana accessibility
- Validates SSL certificate configuration
- Confirms index management setup
- Provides detailed troubleshooting information

## 🔐 Security Features

### SSL/TLS Encryption
- **Certificate Authority (CA)** generated during installation
- **Node certificates** with proper hostname/IP validation
- **HTTP and Transport layer** encryption enabled
- **Certificate verification** for all connections

### Authentication & Authorization
- **Built-in users** with strong passwords
- **Role-based access control** enabled
- **API key authentication** supported
- **Secure credential storage** with restricted permissions

### Network Security
- **Firewall integration** with automatic port configuration
- **Certificate-based authentication** for inter-node communication
- **Configurable network binding** (defaults to all interfaces)

## 📦 Filebeat Deployment

The installer creates a complete Filebeat deployment package:

```
filebeat-deployment-8.11.0.tar.gz
└── filebeat-deployment/
    ├── filebeat-8.11.0-x86_64.rpm    # Filebeat package
    ├── filebeat.yml                   # Pre-configured settings
    ├── elastic-stack-ca.pem           # SSL certificate
    ├── credentials.txt                # Authentication credentials
    ├── install-filebeat.sh            # Installation script
    └── README.md                      # Deployment instructions
```

### Filebeat Installation Features
- **Pre-installation testing** (network, API, SSL validation)
- **Automatic service configuration** and startup
- **Log indexing verification** with test message
- **Comprehensive post-installation validation**
- **Detailed error reporting** and troubleshooting

### Deploy Filebeat to Remote Systems

```bash
# Extract deployment package
tar -xzf filebeat-deployment-8.11.0.tar.gz

# Copy to target system and run
scp -r filebeat-deployment/ user@target-server:
ssh user@target-server
cd filebeat-deployment/
sudo ./install-filebeat.sh
```

## 🛠️ Advanced Configuration

### Custom Version Installation

```bash
# Install specific version
VERSION=8.12.0 sudo ./install-elastic-stack.sh

# Download specific version for offline installation
./download-elastic-packages.sh 8.12.0
```

### Memory Configuration
The installer automatically configures heap sizes:
- **16GB+ RAM**: 8GB heap
- **8-16GB RAM**: 4GB heap
- **4-8GB RAM**: 2GB heap  
- **<4GB RAM**: 1GB heap

### Log Sources Configuration
Default Filebeat configuration monitors:
- **System logs**: `/var/log/*.log`, `/var/log/messages`, `/var/log/secure`
- **Web server logs**: `/var/log/httpd/*.log`, `/var/log/nginx/*.log`
- **Custom paths**: Easily configurable in `filebeat.yml`

## 🔍 Accessing Your Data

### Kibana Web Interface
1. **URL**: `http://your-server-ip:5601`
2. **Username**: `elastic`
3. **Password**: Found in `/etc/elasticsearch/credentials.txt`

### Setting Up Data Views in Kibana
1. Navigate to **"Discover"**
2. Click **"Create data view"**
3. **Index pattern**: `filebeat-*`
4. **Timestamp field**: `@timestamp`
5. **Save** and start exploring your logs

### Useful Kibana Searches
```bash
# Find specific log types
log_type:system

# Search in specific files
log.file.path:"/var/log/secure"

# Search for sudo activities
message:sudo

# Find errors
message:error OR message:failed
```

## 📊 Index Lifecycle Management

Automatic log management with:
- **Hot phase**: 7 days, 5GB max, 1M docs max
- **Warm phase**: 7+ days, reduced replicas
- **Cold phase**: 30+ days, minimal resources
- **Delete phase**: 90+ days (configurable)

## 🧹 Maintenance & Cleanup

### Complete Removal

```bash
# Standard cleanup
chmod +x cleanup-elastic.sh
sudo ./cleanup-elastic.sh

# Aggressive cleanup for stuck installations
chmod +x force-cleanup.sh
sudo ./force-cleanup.sh

# Reboot recommended after cleanup
sudo reboot
```

### Monitoring & Logs

```bash  
# Check service status
sudo systemctl status elasticsearch kibana

# View service logs
sudo journalctl -u elasticsearch -f
sudo journalctl -u kibana -f

# Check cluster health
curl -k -u elastic:PASSWORD https://localhost:9200/_cluster/health?pretty

# View indices
curl -k -u elastic:PASSWORD https://localhost:9200/_cat/indices?v
```

## 🚨 Troubleshooting

### Common Issues

#### Kibana Not Starting
```bash
# Check Kibana logs
sudo journalctl -u kibana -f

# Kibana can take 3-5 minutes to fully start on first boot
# Wait and check again
curl http://localhost:5601/api/status
```

#### Elasticsearch Connection Issues
```bash
# Verify Elasticsearch is running
sudo systemctl status elasticsearch

# Check cluster health
curl -k -u elastic:PASSWORD https://localhost:9200/_cluster/health

# Check certificates
openssl x509 -in /etc/elasticsearch/certs/elasticsearch.crt -text -noout
```

#### Firewall Issues
```bash
# Check if ports are open
sudo firewall-cmd --list-ports

# Manually open ports
sudo firewall-cmd --permanent --add-port=9200/tcp --add-port=5601/tcp
sudo firewall-cmd --reload
```

### Log Locations
- **Installation logs**: `/var/log/elastic-install.log`
- **Elasticsearch logs**: `/var/log/elasticsearch/`
- **Kibana logs**: `/var/log/kibana/`
- **Filebeat logs**: `/var/log/filebeat/`

### Getting Help
- **Credentials**: `/etc/elasticsearch/credentials.txt`
- **Configuration**: `/etc/elasticsearch/elasticsearch.yml`
- **Certificates**: `/etc/elasticsearch/certs/`

## 🔄 Version Compatibility

| Elastic Stack | RHEL/CentOS | Status |
|---------------|-------------|---------|
| 8.11.x        | 8.x, 9.x    | ✅ Tested |
| 8.10.x        | 8.x, 9.x    | ✅ Compatible |
| 8.9.x         | 8.x         | ✅ Compatible |
| 7.x           | 7.x, 8.x    | ⚠️ Not tested |

## 📈 Performance Tuning

### Production Recommendations
- **Dedicated nodes** for heavy workloads
- **SSD storage** for data directories
- **Separate data/log volumes** for better I/O
- **Memory**: 50% of RAM for Elasticsearch heap (max 32GB)
- **CPU**: 2+ cores minimum, 8+ recommended

### Scaling Considerations
- **Single-node** suitable for up to 50GB/day log ingestion
- **Multi-node cluster** recommended for larger deployments
- **Index sharding** based on data volume and retention

## 🤝 Contributing

Contributions welcome! Please:
1. Test changes thoroughly
2. Update documentation
3. Follow existing code style
4. Add appropriate error handling

## 📜 License

This project is provided as-is for educational and production use. Elasticsearch, Kibana, and Filebeat are products of Elastic N.V. and subject to their respective licenses.

## 🔗 Useful Links

- **Elastic Documentation**: https://www.elastic.co/guide/
- **Elasticsearch Reference**: https://www.elastic.co/guide/en/elasticsearch/reference/current/
- **Kibana User Guide**: https://www.elastic.co/guide/en/kibana/current/
- **Filebeat Reference**: https://www.elastic.co/guide/en/beats/filebeat/current/
- **Security Configuration**: https://www.elastic.co/guide/en/elasticsearch/reference/current/security-settings.html

---

**🎉 Ready to deploy your secure Elastic Stack? Start with `sudo ./install-elastic-stack.sh`!** 🚀