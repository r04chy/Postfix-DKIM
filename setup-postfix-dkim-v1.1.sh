#!/bin/bash

#############################################
# Postfix + OpenDKIM Automated Setup Script
# For Ubuntu 24.04 LTS - Fixed Version
# Author: Roachy
# Version: 1.1
# NOTE - this script is mostly destructive and will fuck any existing mail config. 
#############################################



set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Function to validate domain name
validate_domain() {
    local domain=$1
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        return 1
    fi
    return 0
}

# Function to generate random selector
generate_selector() {
    echo "$(date +%Y%m%d)"
}

# Main setup function
main_setup() {
    clear
    echo "============================================"
    echo "  Postfix + OpenDKIM Automated Setup v1.1"
    echo "  Ubuntu 24.04 LTS"
    echo "============================================"
    echo

    # Get domain name
    while true; do
        read -p "Enter your domain name (e.g., example.com): " DOMAIN
        if validate_domain "$DOMAIN"; then
            break
        else
            print_error "Invalid domain name. Please try again."
        fi
    done

    # Get hostname
    read -p "Enter your mail server hostname (e.g., mail.$DOMAIN) [mail.$DOMAIN]: " HOSTNAME
    HOSTNAME=${HOSTNAME:-mail.$DOMAIN}

    # Get selector name
    DEFAULT_SELECTOR=$(generate_selector)
    read -p "Enter DKIM selector name [$DEFAULT_SELECTOR]: " SELECTOR
    SELECTOR=${SELECTOR:-$DEFAULT_SELECTOR}

    echo
    print_info "Configuration Summary:"
    echo "  Domain: $DOMAIN"
    echo "  Hostname: $HOSTNAME"
    echo "  DKIM Selector: $SELECTOR"
    echo
    read -p "Continue with installation? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_warning "Installation cancelled"
        exit 1
    fi

    # Update system
    print_info "Updating system packages..."
    apt-get update -qq
    apt-get upgrade -y -qq

    # Install required packages
    print_info "Installing Postfix, OpenDKIM and dependencies..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        postfix \
        opendkim \
        opendkim-tools \
        mailutils \
        ca-certificates

    # Stop services during configuration
    print_info "Stopping services for configuration..."
    systemctl stop postfix 2>/dev/null || true
    systemctl stop opendkim 2>/dev/null || true

    # Configure OpenDKIM FIRST (before Postfix)
    print_info "Configuring OpenDKIM..."
    
    # Backup original configuration
    cp /etc/opendkim.conf /etc/opendkim.conf.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true

    # Create OpenDKIM directory structure
    print_info "Creating OpenDKIM directory structure..."
    mkdir -p /etc/opendkim/keys/$DOMAIN
    mkdir -p /var/spool/postfix/opendkim
    mkdir -p /run/opendkim
    
    # Generate DKIM keys FIRST
    print_info "Generating DKIM keys (2048-bit RSA)..."
    cd /etc/opendkim/keys/$DOMAIN
    opendkim-genkey -s $SELECTOR -d $DOMAIN -b 2048
    
    # Set proper permissions on keys
    chown -R opendkim:opendkim /etc/opendkim
    chmod 600 /etc/opendkim/keys/$DOMAIN/$SELECTOR.private
    chmod 644 /etc/opendkim/keys/$DOMAIN/$SELECTOR.txt
    
    # Configure TrustedHosts
    cat > /etc/opendkim/TrustedHosts <<EOF
127.0.0.1
localhost
::1
$HOSTNAME
$DOMAIN
*.$DOMAIN
EOF

    # Configure KeyTable
    echo "$SELECTOR._domainkey.$DOMAIN $DOMAIN:$SELECTOR:/etc/opendkim/keys/$DOMAIN/$SELECTOR.private" > /etc/opendkim/KeyTable
    
    # Configure SigningTable  
    cat > /etc/opendkim/SigningTable <<EOF
*@$DOMAIN $SELECTOR._domainkey.$DOMAIN
*@$HOSTNAME $SELECTOR._domainkey.$DOMAIN
EOF

    # Configure OpenDKIM main configuration
    cat > /etc/opendkim.conf <<EOF
# OpenDKIM Configuration File
# Mode: Sign and Verify
Mode                    sv
Syslog                  yes
SyslogSuccess           yes
LogWhy                  yes

# Signing Options
Canonicalization        relaxed/simple
SubDomains              no
OversignHeaders         From

# User and Permissions
UserID                  opendkim:opendkim
UMask                   007

# Socket for Postfix connection
Socket                  local:/var/spool/postfix/opendkim/opendkim.sock

# Host Lists
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts

# Signing Keys
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable

# Other Settings
PidFile                 /run/opendkim/opendkim.pid
SignatureAlgorithm      rsa-sha256
AutoRestart             yes
AutoRestartRate         10/1h
Background              yes
DNSTimeout              5
EOF

    # Add postfix user to opendkim group
    usermod -a -G opendkim postfix
    
    # Set proper ownership for socket directory
    chown opendkim:postfix /var/spool/postfix/opendkim
    chmod 750 /var/spool/postfix/opendkim

    # Configure systemd for OpenDKIM
    print_info "Configuring systemd override for OpenDKIM..."
    mkdir -p /etc/systemd/system/opendkim.service.d/
    cat > /etc/systemd/system/opendkim.service.d/override.conf <<EOF
[Unit]
After=network.target nss-lookup.target

[Service]
Type=forking
PIDFile=/run/opendkim/opendkim.pid
ExecStartPre=/bin/mkdir -p /var/spool/postfix/opendkim
ExecStartPre=/bin/chown opendkim:postfix /var/spool/postfix/opendkim
ExecStartPre=/bin/chmod 750 /var/spool/postfix/opendkim
ExecStart=/usr/sbin/opendkim -x /etc/opendkim.conf
Restart=on-failure
RestartSec=10s
EOF

    # Reload systemd
    systemctl daemon-reload

    # Start OpenDKIM FIRST
    print_info "Starting OpenDKIM service..."
    systemctl start opendkim
    sleep 3
    
    # Verify OpenDKIM is running
    if ! systemctl is-active --quiet opendkim; then
        print_error "OpenDKIM failed to start. Checking logs..."
        journalctl -xeu opendkim --no-pager | tail -20
        exit 1
    fi
    
    # Verify socket exists
    if [ ! -S /var/spool/postfix/opendkim/opendkim.sock ]; then
        print_error "OpenDKIM socket not created!"
        exit 1
    fi
    
    print_success "OpenDKIM is running and socket created"

    # Now configure Postfix
    print_info "Configuring Postfix..."
    
    # Backup original configuration
    cp /etc/postfix/main.cf /etc/postfix/main.cf.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true

    # Configure main.cf
    cat > /etc/postfix/main.cf <<EOF
# Basic Configuration
smtpd_banner = \$myhostname ESMTP \$mail_name
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 3.6

# TLS parameters
smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
smtpd_tls_security_level=may
smtp_tls_CApath=/etc/ssl/certs
smtp_tls_security_level=may
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache
smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache

# Network Configuration
myhostname = $HOSTNAME
myorigin = /etc/mailname
mydestination = \$myhostname, $DOMAIN, localhost.$DOMAIN, localhost
relayhost = 
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all

# Recipient Restrictions (without SASL)
smtpd_recipient_restrictions = 
    permit_mynetworks,
    reject_unauth_destination

# CRITICAL: Milter Configuration for OpenDKIM
milter_default_action = accept
milter_protocol = 6
smtpd_milters = local:opendkim/opendkim.sock
non_smtpd_milters = local:opendkim/opendkim.sock

# Message Size Limit (50MB)
message_size_limit = 52428800

# Alias Configuration
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
EOF

    # Set mailname
    echo "$DOMAIN" > /etc/mailname

    # Update aliases
    print_info "Updating aliases..."
    newaliases

    # Start Postfix
    print_info "Starting Postfix service..."
    systemctl start postfix
    
    # Enable services
    systemctl enable opendkim
    systemctl enable postfix

    # Wait for services to stabilize
    sleep 3

    # Check service status
    print_info "Checking service status..."
    if systemctl is-active --quiet postfix; then
        print_success "Postfix is running"
    else
        print_error "Postfix failed to start. Check logs: journalctl -xeu postfix"
    fi

    if systemctl is-active --quiet opendkim; then
        print_success "OpenDKIM is running"
        # Verify socket is accessible to Postfix
        if [ -S /var/spool/postfix/opendkim/opendkim.sock ]; then
            print_success "OpenDKIM socket is available"
        else
            print_warning "Socket may not be accessible"
        fi
    else
        print_error "OpenDKIM failed to start. Check logs: journalctl -xeu opendkim"
    fi

    # Test configuration
    print_info "Testing OpenDKIM configuration..."
    opendkim-testkey -d $DOMAIN -s $SELECTOR -k /etc/opendkim/keys/$DOMAIN/$SELECTOR.private

    # Extract and display DNS records
    print_info "Generating required DNS records..."
    echo
    echo "============================================"
    echo "  REQUIRED DNS RECORDS"
    echo "============================================"
    echo

    # Get DKIM public key
    DKIM_RECORD=$(cat /etc/opendkim/keys/$DOMAIN/$SELECTOR.txt | tr -d '\n' | sed 's/.*"v=DKIM1;/v=DKIM1;/' | sed 's/".*//')
    
    # Get server IP
    SERVER_IP=$(hostname -I | awk '{print $1}')
    
    print_success "Add the following DNS records to your domain:"
    echo
    echo "1. MX Record:"
    echo "   Type: MX"
    echo "   Name: @"
    echo "   Priority: 10"
    echo "   Value: $HOSTNAME"
    echo
    echo "2. A Record (for mail server):"
    echo "   Type: A"
    echo "   Name: $(echo $HOSTNAME | sed "s/\.$DOMAIN//")"
    echo "   Value: $SERVER_IP"
    echo
    echo "3. SPF Record:"
    echo "   Type: TXT"
    echo "   Name: @"
    echo "   Value: \"v=spf1 mx a:$HOSTNAME ip4:$SERVER_IP -all\""
    echo
    echo "4. DKIM Record:"
    echo "   Type: TXT"
    echo "   Name: $SELECTOR._domainkey"
    echo "   Value: \"$DKIM_RECORD\""
    echo
    echo "5. DMARC Record (recommended):"
    echo "   Type: TXT"
    echo "   Name: _dmarc"
    echo "   Value: \"v=DMARC1; p=none; rua=mailto:dmarc@$DOMAIN; fo=1\""
    echo
    echo "6. Reverse DNS (PTR Record):"
    echo "   Configure with your hosting provider"
    echo "   IP $SERVER_IP should point to: $HOSTNAME"
    echo

    # Save DNS records to file
    DNS_FILE="/root/dns_records_$DOMAIN.txt"
    cat > $DNS_FILE <<EOF
DNS Records for $DOMAIN
Generated: $(date)
Server IP: $SERVER_IP
================================

1. MX Record:
   Type: MX
   Name: @
   Priority: 10
   Value: $HOSTNAME

2. A Record:
   Type: A
   Name: $(echo $HOSTNAME | sed "s/\.$DOMAIN//")
   Value: $SERVER_IP

3. SPF Record:
   Type: TXT
   Name: @
   Value: "v=spf1 mx a:$HOSTNAME ip4:$SERVER_IP -all"

4. DKIM Record:
   Type: TXT
   Name: $SELECTOR._domainkey
   Value: "$DKIM_RECORD"

5. DMARC Record:
   Type: TXT
   Name: _dmarc
   Value: "v=DMARC1; p=none; rua=mailto:dmarc@$DOMAIN; fo=1"

6. PTR Record:
   Configure with hosting provider
   $SERVER_IP -> $HOSTNAME
EOF

    print_success "DNS records saved to: $DNS_FILE"
    echo

    # Send test email
    print_info "Sending test email to verify DKIM signing..."
    TEST_EMAIL="root@$DOMAIN"
    echo "This is a test email to verify DKIM signing" | mail -s "DKIM Test from $HOSTNAME" -a "From: $TEST_EMAIL" $TEST_EMAIL 2>/dev/null || true
    
    # Check if mail was signed
    sleep 2
    print_info "Checking mail log for DKIM signing..."
    if grep -q "DKIM-Signature field added" /var/log/mail.log 2>/dev/null; then
        print_success "DKIM signatures are being added!"
    else
        print_warning "Could not verify DKIM signing in logs yet"
    fi

    # Testing commands
    echo "============================================"
    echo "  TESTING & VERIFICATION"
    echo "============================================"
    echo
    echo "1. Test DKIM key (after DNS propagation):"
    echo "   opendkim-testkey -d $DOMAIN -s $SELECTOR -vvv"
    echo
    echo "2. Verify DKIM is signing emails:"
    echo "   grep 'DKIM-Signature' /var/log/mail.log"
    echo
    echo "3. Send test email with specific From address:"
    echo "   echo 'Test' | mail -s 'Test' -a 'From: user@$DOMAIN' recipient@gmail.com"
    echo
    echo "4. Check full mail headers:"
    echo "   tail -f /var/log/mail.log"
    echo
    echo "5. Verify DNS record (after propagation):"
    echo "   host -t TXT $SELECTOR._domainkey.$DOMAIN"
    echo
    echo "6. Test services:"
    echo "   systemctl status opendkim"
    echo "   systemctl status postfix"
    echo

    print_success "Setup completed successfully!"
    print_warning "Important: Emails must be sent with From: addresses matching $DOMAIN"
    print_warning "DNS propagation may take up to 48 hours"
    print_info "To send properly signed email: echo 'body' | mail -s 'subject' -a 'From: user@$DOMAIN' recipient@example.com"
}

# Run the script
check_root
main_setup
