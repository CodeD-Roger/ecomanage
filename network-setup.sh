#!/bin/bash

# Exit on any error
set -e

# Trap to clean up on error or interruption
cleanup() {
    echo -e "${RED}❌ Script interrupted. Cleaning up temporary files...${NC}"
    [ -f "/tmp/odoo-dns.conf.tmp" ] && rm -f /tmp/odoo-dns.conf.tmp
    [ -f "/tmp/odoo-nginx.conf.tmp" ] && rm -f /tmp/odoo-nginx.conf.tmp
    [ -f "/tmp/resolv.conf.tmp" ] && rm -f /tmp/resolv.conf.tmp
    [ -f "/tmp/selfsigned.key.tmp" ] && rm -f /tmp/selfsigned.key.tmp
    [ -f "/tmp/selfsigned.crt.tmp" ] && rm -f /tmp/selfsigned.crt.tmp
    [ -f "/tmp/webmin-setup-repo.sh" ] && rm -f /tmp/webmin-setup-repo.sh
    exit 1
}
trap cleanup SIGINT SIGTERM

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
FORCE=false
DRY_RUN=false
ODOO_PORT=8069
DEFAULT_IP=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v "127.0.0.1" | head -1)

# Parse command-line arguments
while [[ "$1" == --* ]]; do
    case "$1" in
        --force)
            FORCE=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help)
            echo -e "${YELLOW}Usage: $0 [--force] [--dry-run]${NC}"
            echo -e "  --force     Overwrite existing configuration files without prompt"
            echo -e "  --dry-run   Show what would be done without applying changes"
            exit 0
            ;;
        *)
            echo -e "${RED}❌ Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Function to check if a command exists
check_command() {
    if ! command -v "$1" &> /dev/null; then
        if [ "$DRY_RUN" = true ]; then
            echo -e "${YELLOW}⚠ Would install $1 (dry-run mode).${NC}"
        else
            echo -e "${YELLOW}⚠ Installing $1...${NC}"
            apt-get update && apt-get install -y "$1"
        fi
    else
        echo -e "${GREEN}✅ $1 is already installed.${NC}"
    fi
}

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        echo -e "${RED}❌ Invalid IP address format: $ip${NC}"
        return 1
    fi
}

# Function to validate domain name
validate_domain() {
    local domain=$1
    if [[ $domain =~ ^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z0-9-]+$ ]]; then
        return 0
    else
        echo -e "${RED}❌ Invalid domain name format: $domain (e.g., mcctconsulting.local, erp.lan)${NC}"
        return 1
    fi
}

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}❌ This script must be run as root (use sudo).${NC}"
    exit 1
fi

# Function to check and configure port 53
check_port_53() {
    if lsof -i :53 &> /dev/null; then
        echo -e "${YELLOW}⚠ Port 53 is in use. Checking for conflicting services...${NC}"
        if systemctl is-active --quiet systemd-resolved; then
            echo -e "${YELLOW}⚠ systemd-resolved is running and occupying port 53. Disabling it...${NC}"
            if [ "$DRY_RUN" = true ]; then
                echo -e "${YELLOW}Dry-run: Would stop and disable systemd-resolved and update /etc/resolv.conf.${NC}"
            else
                # Stop and disable systemd-resolved
                systemctl stop systemd-resolved
                systemctl disable systemd-resolved
                echo -e "${GREEN}✅ systemd-resolved stopped and disabled.${NC}"

                # Check if /etc/resolv.conf is a symlink and replace it with a static file
                if [ -L /etc/resolv.conf ]; then
                    echo -e "${YELLOW}⚠ /etc/resolv.conf is a symlink. Replacing with static file...${NC}"
                    rm -f /etc/resolv.conf
                fi

                # Create new /etc/resolv.conf with dnsmasq and fallback DNS
                echo -e "${YELLOW}⚠ Updating /etc/resolv.conf with local dnsmasq and fallback DNS...${NC}"
                echo -e "nameserver 127.0.0.1\nnameserver 8.8.8.8\nnameserver 8.8.4.4" > /tmp/resolv.conf.tmp
                mv /tmp/resolv.conf.tmp /etc/resolv.conf
                chmod 644 /etc/resolv.conf
                echo -e "${GREEN}✅ /etc/resolv.conf updated to use dnsmasq and Google DNS as fallback.${NC}"
            fi
        else
            echo -e "${RED}❌ Port 53 is in use by another service (e.g., bind9, unbound). Check with 'sudo lsof -i :53' and stop it manually.${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}✅ Port 53 is free.${NC}"
    fi

    # Verify DNS resolution
    if [ "$DRY_RUN" != "true" ]; then
        echo -e "${YELLOW}🔍 Verifying DNS resolution...${NC}"
        if command -v dig &> /dev/null; then
            if dig +short google.com | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
                echo -e "${GREEN}✅ DNS resolution successful (google.com resolved).${NC}"
            else
                echo -e "${RED}❌ DNS resolution failed. Check /etc/resolv.conf or dnsmasq configuration.${NC}"
                exit 1
            fi
        else
            echo -e "${YELLOW}⚠ dig not installed. Skipping DNS resolution test.${NC}"
        fi
    fi
}

# Prompt for Odoo IP
echo -e "${YELLOW}Enter the IP address of the Odoo server (default: $DEFAULT_IP):${NC}"
read -p "> " ODOO_IP
ODOO_IP=${ODOO_IP:-$DEFAULT_IP}
if ! validate_ip "$ODOO_IP"; then
    exit 1
fi

# Prompt for local domain
echo -e "${YELLOW}Enter the local domain name (e.g., mcctconsulting.local, erp.lan):${NC}"
read -p "> " LOCAL_DOMAIN
if ! validate_domain "$LOCAL_DOMAIN"; then
    exit 1
fi

# Create safe domain name for filenames
SAFE_DOMAIN=$(echo "$LOCAL_DOMAIN" | sed 's/\./_/g')

# Check if Odoo is running
echo -e "${GREEN}🔍 Checking if Odoo is running on localhost:$ODOO_PORT...${NC}"
if nc -z localhost $ODOO_PORT 2>/dev/null; then
    echo -e "${GREEN}✅ Odoo is active on port $ODOO_PORT.${NC}"
else
    echo -e "${RED}❌ Odoo is not running on port $ODOO_PORT. Please start Odoo and try again.${NC}"
    exit 1
fi

# Install dependencies
echo -e "${GREEN}📦 Checking and installing dependencies...${NC}"
check_command dnsmasq
check_command nginx
check_command dnsutils
check_command openssl
check_command certbot
check_command python3-certbot-nginx

# Check port 53 before configuring dnsmasq
check_port_53

# Configure dnsmasq
DNS_CONF="/etc/dnsmasq.d/odoo-dns.conf"
if [ -f "$DNS_CONF" ] && [ "$FORCE" != "true" ]; then
    echo -e "${YELLOW}⚠ $DNS_CONF already exists. Overwrite? (y/N)${NC}"
    read -p "> " OVERWRITE
    if [[ ! "$OVERWRITE" =~ ^[yY]$ ]]; then
        echo -e "${RED}❌ Aborting to avoid overwriting existing DNS configuration.${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}⚙ Configuring dnsmasq...${NC}"
DNS_CONFIG=$(cat <<EOF
address=/$LOCAL_DOMAIN/$ODOO_IP
server=8.8.8.8
server=8.8.4.4
EOF
)
if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}Dry-run: Would write to $DNS_CONF:${NC}\n$DNS_CONFIG"
else
    echo "$DNS_CONFIG" > /tmp/odoo-dns.conf.tmp
    mv /tmp/odoo-dns.conf.tmp "$DNS_CONF"
    if ! systemctl restart dnsmasq; then
        echo -e "${RED}❌ Failed to restart dnsmasq. Check logs with 'journalctl -u dnsmasq'.${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ dnsmasq configured and restarted.${NC}"
fi

# Verify dnsmasq is listening on port 53
if [ "$DRY_RUN" != "true" ]; then
    if lsof -i :53 | grep -q "dnsmasq"; then
        echo -e "${GREEN}✅ dnsmasq is listening on port 53.${NC}"
    else
        echo -e "${RED}❌ dnsmasq is not listening on port 53. Check logs with 'journalctl -u dnsmasq'.${NC}"
        exit 1
    fi
fi

# Configure HTTPS
echo -e "${GREEN}📦 Configuring HTTPS for $LOCAL_DOMAIN...${NC}"
SSL_CERT="/etc/ssl/$SAFE_DOMAIN/selfsigned.crt"
SSL_KEY="/etc/ssl/$SAFE_DOMAIN/selfsigned.key"
USE_SELFSIGNED=false

if [[ "$LOCAL_DOMAIN" =~ \.(local|lan|internal)$ ]]; then
    echo -e "${YELLOW}⚠ $LOCAL_DOMAIN uses a non-public TLD. Generating self-signed certificate...${NC}"
    if [ "$DRY_RUN" = true ]; then
        echo -e "${YELLOW}Dry-run: Would generate self-signed certificate for $LOCAL_DOMAIN in /etc/ssl/$SAFE_DOMAIN/.${NC}"
    else
        # Create directory for certificates
        mkdir -p "/etc/ssl/$SAFE_DOMAIN"
        chmod 755 "/etc/ssl/$SAFE_DOMAIN"

        # Generate self-signed certificate with OpenSSL
        if ! openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "/tmp/selfsigned.key.tmp" \
            -out "/tmp/selfsigned.crt.tmp" \
            -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=$LOCAL_DOMAIN"; then
            echo -e "${RED}❌ Failed to generate self-signed certificate.${NC}"
            exit 1
        fi
        mv "/tmp/selfsigned.key.tmp" "$SSL_KEY"
        mv "/tmp/selfsigned.crt.tmp" "$SSL_CERT"
        chmod 644 "$SSL_CERT"
        chmod 600 "$SSL_KEY"
        echo -e "${GREEN}✅ Self-signed certificate generated in /etc/ssl/$SAFE_DOMAIN/.${NC}"
        USE_SELFSIGNED=true
    fi
else
    echo -e "${GREEN}⚙ Attempting to configure HTTPS with Certbot for $LOCAL_DOMAIN...${NC}"
    if [ "$DRY_RUN" = true ]; then
        echo -e "${YELLOW}Dry-run: Would run certbot --nginx -d $LOCAL_DOMAIN --non-interactive --agree-tos -m admin@$LOCAL_DOMAIN --redirect${NC}"
    else
        if certbot --nginx -d "$LOCAL_DOMAIN" --non-interactive --agree-tos -m "admin@$LOCAL_DOMAIN" --redirect; then
            echo -e "${GREEN}✅ SSL certificate issued and NGINX configured for HTTPS with automatic HTTP-to-HTTPS redirection.${NC}"
            SSL_CERT="/etc/letsencrypt/live/$LOCAL_DOMAIN/fullchain.pem"
            SSL_KEY="/etc/letsencrypt/live/$LOCAL_DOMAIN/privkey.pem"
        else
            echo -e "${RED}❌ Certbot failed to issue a certificate for $LOCAL_DOMAIN. Possible reasons: domain not publicly resolvable or rate limits exceeded.${NC}"
            echo -e "${YELLOW}📌 Falling back to self-signed certificate for HTTPS...${NC}"
            # Generate self-signed certificate as fallback
            mkdir -p "/etc/ssl/$SAFE_DOMAIN"
            chmod 755 "/etc/ssl/$SAFE_DOMAIN"
            if ! openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout "/tmp/selfsigned.key.tmp" \
                -out "/tmp/selfsigned.crt.tmp" \
                -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=$LOCAL_DOMAIN"; then
                echo -e "${RED}❌ Failed to generate self-signed certificate.${NC}"
                exit 1
            fi
            mv "/tmp/selfsigned.key.tmp" "$SSL_KEY"
            mv "/tmp/selfsigned.crt.tmp" "$SSL_CERT"
            chmod 644 "$SSL_CERT"
            chmod 600 "$SSL_KEY"
            echo -e "${GREEN}✅ Self-signed certificate generated in /etc/ssl/$SAFE_DOMAIN/ as fallback.${NC}"
            USE_SELFSIGNED=true
        fi
    fi
fi

# Configure NGINX
NGINX_CONF="/etc/nginx/sites-available/odoo-$SAFE_DOMAIN.conf"
NGINX_LINK="/etc/nginx/sites-enabled/odoo-$SAFE_DOMAIN.conf"
if [ -f "$NGINX_CONF" ] && [ "$FORCE" != "true" ]; then
    echo -e "${YELLOW}⚠ $NGINX_CONF already exists. Overwrite? (y/N)${NC}"
    read -p "> " OVERWRITE
    if [[ ! "$OVERWRITE" =~ ^[yY]$ ]]; then
        echo -e "${RED}❌ Aborting to avoid overwriting existing NGINX configuration.${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}⚙ Configuring NGINX reverse proxy...${NC}"
NGINX_CONFIG=$(cat <<EOF
server {
    listen 80;
    server_name $LOCAL_DOMAIN;

    # Redirect HTTP to HTTPS
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl;
    server_name $LOCAL_DOMAIN;

    ssl_certificate $SSL_CERT;
    ssl_certificate_key $SSL_KEY;

    location / {
        proxy_pass http://127.0.0.1:$ODOO_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
    }
}
EOF
)
if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}Dry-run: Would write to $NGINX_CONF:${NC}\n$NGINX_CONFIG"
else
    echo "$NGINX_CONFIG" > /tmp/odoo-nginx.conf.tmp
    mv /tmp/odoo-nginx.conf.tmp "$NGINX_CONF"
    ln -sf "$NGINX_CONF" "$NGINX_LINK"

    # Verify certificate files exist before testing NGINX
    if [ "$USE_SELFSIGNED" = true ]; then
        if [ ! -f "$SSL_CERT" ] || [ ! -f "$SSL_KEY" ]; then
            echo -e "${RED}❌ Certificate files ($SSL_CERT or $SSL_KEY) not found.${NC}"
            exit 1
        fi
    fi

    # Test NGINX configuration
    if ! nginx -t; then
        echo -e "${RED}❌ NGINX configuration test failed. Check $NGINX_CONF for errors.${NC}"
        echo -e "${YELLOW}Try running 'nginx -t' to debug or fix the configuration manually.${NC}"
        exit 1
    fi

    # Reload NGINX
    if ! systemctl reload nginx; then
        echo -e "${RED}❌ Failed to reload NGINX. Check logs with 'journalctl -u nginx'.${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ NGINX configured and reloaded.${NC}"

    # Verify NGINX is listening on port 443
    if ! ss -tuln | grep -q :443; then
        echo -e "${YELLOW}⚠ NGINX not listening on port 443. Restarting NGINX...${NC}"
        if ! systemctl restart nginx; then
            echo -e "${RED}❌ Failed to restart NGINX. Check logs with 'journalctl -u nginx'.${NC}"
            exit 1
        fi
        echo -e "${GREEN}✅ NGINX restarted and listening on port 443.${NC}"
    else
        echo -e "${GREEN}✅ NGINX is listening on port 443.${NC}"
    fi
fi

# Add alias to /etc/hosts (optional)
if [ "$DRY_RUN" != "true" ]; then
    echo -e "${YELLOW}✨ Would you like to add an alias for $LOCAL_DOMAIN to /etc/hosts on this machine? (y/N)${NC}"
    read -p "> " ADD_HOSTS
    if [[ "$ADD_HOSTS" =~ ^[yY]$ ]]; then
        if grep -q "$LOCAL_DOMAIN" /etc/hosts; then
            echo -e "${YELLOW}⚠ Entry for $LOCAL_DOMAIN already exists in /etc/hosts. Skipping.${NC}"
        else
            echo "$ODOO_IP $LOCAL_DOMAIN" >> /etc/hosts
            echo -e "${GREEN}✅ Added $ODOO_IP $LOCAL_DOMAIN to /etc/hosts.${NC}"
        fi
    fi
fi

# Configure UFW firewall
echo -e "${GREEN}🔒 Configuring UFW firewall...${NC}"
check_command ufw
if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}Dry-run: Would configure UFW to allow ports 22 (SSH), 80 (HTTP), 443 (HTTPS), 53 (DNS), 61905/udp (WireGuard), 10000/tcp (Webmin).${NC}"
else
    # Reset UFW to avoid duplicate rules
    ufw --force reset
    echo -e "${GREEN}✅ UFW reset to clear existing rules.${NC}"

    # Allow necessary ports for both IPv4 and IPv6
    ufw allow 22/tcp comment "SSH"
    ufw allow 80/tcp comment "HTTP"
    ufw allow 443/tcp comment "HTTPS"
    ufw allow 53 comment "DNS"
    ufw allow 61905/udp comment "WireGuard VPN"
    ufw allow 10000/tcp comment "Webmin"
    echo -e "${GREEN}✅ Ports 22 (SSH), 80 (HTTP), 443 (HTTPS), 53 (DNS), 61905/udp (WireGuard), and 10000/tcp (Webmin) allowed.${NC}"

    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing

    # Enable UFW
    if ufw --force enable; then
        echo -e "${GREEN}✅ UFW enabled with secure configuration.${NC}"
    else
        echo -e "${RED}❌ Failed to enable UFW. Check logs with 'ufw status' or 'journalctl -u ufw'.${NC}"
        exit 1
    fi
fi

# Install Webmin and Usermin
echo -e "${GREEN}📦 Installing Webmin and Usermin...${NC}"
if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}Dry-run: Would install Webmin and Usermin.${NC}"
else
    # Download Webmin setup script to /tmp
    curl -o /tmp/webmin-setup-repo.sh https://raw.githubusercontent.com/webmin/webmin/master/webmin-setup-repo.sh
    # Run the setup script
    if ! sh /tmp/webmin-setup-repo.sh; then
        echo -e "${RED}❌ Failed to set up Webmin repository. Check network or script URL.${NC}"
        exit 1
    fi
    # Install Webmin and Usermin
    if ! apt-get install --yes --install-recommends webmin usermin; then
        echo -e "${RED}❌ Failed to install Webmin and Usermin. Check apt-get logs.${NC}"
        exit 1
    fi
    # Clean up
    rm -f /tmp/webmin-setup-repo.sh
    echo -e "${GREEN}✅ Webmin and Usermin installed successfully.${NC}"
fi

# Get server IP for display
SERVER_IP=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v "127.0.0.1" | head -1)

# Final instructions
echo -e "${GREEN}🎉 Setup complete!${NC}"
if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}Dry-run mode: No changes were made to the system.${NC}"
fi
echo -e "\n🔗 URL to access Odoo: https://$LOCAL_DOMAIN"
echo -e "\n📌 For other machines to access this domain, they must either:"
echo -e "  1. Configure their DNS to use this server (IP: $SERVER_IP)"
echo -e "  2. Add the following line to their /etc/hosts file:"
echo -e "     $ODOO_IP $LOCAL_DOMAIN"
if [ "$USE_SELFSIGNED" = true ]; then
    echo -e "\n⚠ Using a self-signed certificate. You may need to accept a security warning in your browser."
fi
echo -e "\n🔒 Ensure Odoo is running on port $ODOO_PORT and is accessible."
echo -e "\n🔍 Verify DNS resolution with: nslookup $LOCAL_DOMAIN"
echo -e "\n🔐 Verify HTTPS setup with: curl -I https://$LOCAL_DOMAIN"
echo -e "\n🔥 Verify firewall status with: ufw status"
