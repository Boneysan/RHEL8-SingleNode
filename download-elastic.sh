#!/usr/bin/env bash
#
# Elastic Stack Downloader Script
# Downloads Elasticsearch, Kibana, and Filebeat RPM packages
#

set -euo pipefail

# Color definitions
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
DEFAULT_VERSION="8.11.0"
VERSION="${1:-$DEFAULT_VERSION}"
ARCH="x86_64"
DOWNLOAD_DIR="elastic-packages"

# Package information
declare -A PACKAGES=(
    ["elasticsearch"]="https://artifacts.elastic.co/downloads/elasticsearch"
    ["kibana"]="https://artifacts.elastic.co/downloads/kibana"
    ["filebeat"]="https://artifacts.elastic.co/downloads/beats/filebeat"
)

# Print banner
print_banner() {
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                Elastic Stack Package Downloader              ║${NC}"
    echo -e "${BLUE}║                                                              ║${NC}"
    echo -e "${BLUE}║  Downloads: Elasticsearch, Kibana, and Filebeat RPMs        ║${NC}"
    echo -e "${BLUE}║  Version: $VERSION${NC}"
    echo -e "${BLUE}║                                                              ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Show usage information
show_usage() {
    echo "Usage: $0 [VERSION]"
    echo ""
    echo "Downloads Elasticsearch, Kibana, and Filebeat RPM packages"
    echo ""
    echo "Arguments:"
    echo "  VERSION    Elastic Stack version to download (default: $DEFAULT_VERSION)"
    echo ""
    echo "Examples:"
    echo "  $0                    # Download version $DEFAULT_VERSION"
    echo "  $0 8.12.0            # Download specific version"
    echo "  $0 latest            # Download latest available version"
    echo ""
    echo "Downloaded files will be saved to: ./$DOWNLOAD_DIR/"
}

# Auto-detect latest version
detect_latest_version() {
    echo "🔍 Auto-detecting latest Elastic Stack version..."
    
    # Try to get latest version from Elasticsearch download page
    local latest_version=$(curl -s https://artifacts.elastic.co/downloads/elasticsearch/ 2>/dev/null | \
        grep -oP 'elasticsearch-\K[0-9]+\.[0-9]+\.[0-9]+' | \
        sort -V | tail -1 || echo "")
    
    if [[ -n "$latest_version" ]]; then
        VERSION="$latest_version"
        echo -e "${GREEN}✅ Latest version detected: $VERSION${NC}"
    else
        echo -e "${YELLOW}⚠️  Could not auto-detect latest version, using default: $DEFAULT_VERSION${NC}"
        VERSION="$DEFAULT_VERSION"
    fi
}

# Validate version format
validate_version() {
    if [[ "$VERSION" == "latest" ]]; then
        detect_latest_version
        return 0
    fi
    
    # Check if version matches pattern X.Y.Z
    if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${RED}❌ Invalid version format: $VERSION${NC}"
        echo "Version must be in format X.Y.Z (e.g., 8.11.0) or 'latest'"
        exit 1
    fi
}

# Check if file already exists
check_existing_file() {
    local filename="$1"
    local filepath="$DOWNLOAD_DIR/$filename"
    
    if [[ -f "$filepath" ]]; then
        local filesize=$(stat -c%s "$filepath" 2>/dev/null || echo "0")
        if [[ $filesize -gt 1000000 ]]; then  # File is larger than 1MB
            echo -e "${YELLOW}📦 File already exists: $filename ($(du -h "$filepath" | cut -f1))${NC}"
            read -p "Do you want to re-download? (y/N): " redownload
            if [[ ! "$redownload" =~ ^[Yy]$ ]]; then
                return 1  # Skip download
            fi
        fi
    fi
    return 0  # Proceed with download
}

# Download a package
download_package() {
    local package_name="$1"
    local base_url="$2"
    local filename="${package_name}-${VERSION}-${ARCH}.rpm"
    local url="${base_url}/${filename}"
    local filepath="$DOWNLOAD_DIR/$filename"
    
    echo -e "${BLUE}📥 Downloading $package_name...${NC}"
    echo "   URL: $url"
    
    # Check if file already exists
    if ! check_existing_file "$filename"; then
        echo -e "${GREEN}✅ Skipping $filename (already exists)${NC}"
        return 0
    fi
    
    # Download with progress bar and resume capability
    if curl -L --fail --create-dirs --output "$filepath" \
           --progress-bar --continue-at - "$url"; then
        
        # Verify download
        local filesize=$(stat -c%s "$filepath" 2>/dev/null || echo "0")
        if [[ $filesize -gt 1000000 ]]; then
            echo -e "${GREEN}✅ Downloaded: $filename ($(du -h "$filepath" | cut -f1))${NC}"
            
            # Verify it's actually an RPM file
            if file "$filepath" | grep -q "RPM"; then
                echo "   📦 Package verified as valid RPM"
            else
                echo -e "${YELLOW}⚠️  Warning: File may not be a valid RPM package${NC}"
            fi
        else
            echo -e "${RED}❌ Download failed: File too small or corrupt${NC}"
            rm -f "$filepath"
            return 1
        fi
    else
        echo -e "${RED}❌ Download failed: $filename${NC}"
        echo "   Check if version $VERSION exists or try a different version"
        return 1
    fi
}

# Verify all downloads
verify_downloads() {
    echo -e "\n${BLUE}🔍 Verifying downloads...${NC}"
    
    local all_good=true
    for package_name in "${!PACKAGES[@]}"; do
        local filename="${package_name}-${VERSION}-${ARCH}.rpm"
        local filepath="$DOWNLOAD_DIR/$filename"
        
        if [[ -f "$filepath" ]]; then
            local filesize=$(stat -c%s "$filepath" 2>/dev/null || echo "0")
            if [[ $filesize -gt 1000000 ]]; then
                echo -e "${GREEN}✅ $filename ($(du -h "$filepath" | cut -f1))${NC}"
            else
                echo -e "${RED}❌ $filename (file too small or missing)${NC}"
                all_good=false
            fi
        else
            echo -e "${RED}❌ $filename (not found)${NC}"
            all_good=false
        fi
    done
    
    return $([ "$all_good" = true ])
}

# Calculate total download size (estimate)
estimate_download_size() {
    echo -e "${BLUE}📊 Estimated download sizes:${NC}"
    echo "   • Elasticsearch: ~600MB"
    echo "   • Kibana: ~300MB" 
    echo "   • Filebeat: ~50MB"
    echo "   • Total: ~950MB"
    echo ""
}

# Main download function
download_all_packages() {
    echo -e "${GREEN}🚀 Starting downloads for Elastic Stack $VERSION...${NC}"
    echo ""
    
    # Create download directory
    mkdir -p "$DOWNLOAD_DIR"
    
    # Download each package
    local failed_downloads=()
    for package_name in "${!PACKAGES[@]}"; do
        if ! download_package "$package_name" "${PACKAGES[$package_name]}"; then
            failed_downloads+=("$package_name")
        fi
        echo ""
    done
    
    # Report results
    if [[ ${#failed_downloads[@]} -eq 0 ]]; then
        echo -e "${GREEN}✅ All packages downloaded successfully!${NC}"
        return 0
    else
        echo -e "${RED}❌ Failed to download: ${failed_downloads[*]}${NC}"
        return 1
    fi
}

# Generate checksums
generate_checksums() {
    echo -e "${BLUE}🔐 Generating checksums...${NC}"
    
    if command -v sha256sum >/dev/null 2>&1; then
        local checksum_file="$DOWNLOAD_DIR/SHA256SUMS"
        (cd "$DOWNLOAD_DIR" && sha256sum *.rpm > SHA256SUMS 2>/dev/null)
        if [[ -f "$checksum_file" ]]; then
            echo -e "${GREEN}✅ Checksums saved to: $checksum_file${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  sha256sum not available, skipping checksum generation${NC}"
    fi
}

# Print summary
print_summary() {
    local exit_code=$1
    
    echo ""
    if [[ $exit_code -eq 0 ]]; then
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                    DOWNLOAD COMPLETED                        ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    else
        echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║                DOWNLOAD COMPLETED WITH ERRORS                ║${NC}"
        echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}📁 Download location: $(pwd)/$DOWNLOAD_DIR/${NC}"
    echo -e "${BLUE}📦 Package version: $VERSION${NC}"
    
    if [[ -d "$DOWNLOAD_DIR" ]]; then
        echo ""
        echo -e "${BLUE}📋 Downloaded files:${NC}"
        ls -lh "$DOWNLOAD_DIR"/*.rpm 2>/dev/null | while read -r line; do
            echo "   $line"
        done || echo "   No RPM files found"
    fi
    
    echo ""
    echo -e "${BLUE}🚀 Next steps:${NC}"
    echo "   1. Copy files to your target system"
    echo "   2. Run the Elastic Stack installer script"
    echo "   3. Use these files as local packages (no internet required)"
    
    if [[ $exit_code -eq 0 ]]; then
        echo ""
        echo -e "${GREEN}✅ Ready for offline installation!${NC}"
    fi
}

# Main execution
main() {
    # Handle help flag
    if [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]]; then
        show_usage
        exit 0
    fi
    
    # Print banner
    print_banner
    
    # Validate version
    validate_version
    
    # Show estimated download size
    estimate_download_size
    
    # Confirm download
    echo -e "${YELLOW}📥 About to download Elastic Stack $VERSION packages${NC}"
    read -p "Continue? (Y/n): " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        echo "Download cancelled."
        exit 0
    fi
    
    echo ""
    
    # Download packages
    if download_all_packages; then
        verify_downloads
        generate_checksums
        print_summary 0
        exit 0
    else
        verify_downloads || true
        print_summary 1
        exit 1
    fi
}

# Run main function
main "$@"