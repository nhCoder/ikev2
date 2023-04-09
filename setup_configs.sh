#!/bin/bash

# Update the system
apt-get update && apt-get upgrade -y

# Install necessary software
apt-get install -y strongswan strongswan-plugin-eap-mschapv2 moreutils iptables-persistent

# Set up VPN configuration
cat > /etc/ipsec.conf <<EOF
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%any
    leftid=@your_vpn_server_domain_or_ip
    leftauth=psk
    leftsubnet=0.0.0.0/0
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip=10.10.10.0/24
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=never
    eap_identity=%identity
EOF

# Set up VPN secrets
cat > /etc/ipsec.secrets <<EOF
: PSK "your_pre_shared_key"
your_username %any% : EAP "your_password"
EOF

# Enable packet forwarding
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.conf
sysctl -p

# Configure iptables
iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -m policy --dir out --pol ipsec -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE
iptables -A FORWARD -s 10.10.10.0/24 -j ACCEPT

# Save iptables rules
iptables-save > /etc/iptables/rules.v4

# Restart the VPN server
systemctl restart strongswan

# Enable the VPN server at startup
systemctl enable strongswan

# Generate client configuration files
mkdir -p /etc/ipsec/clients

# iOS configuration
cat > /etc/ipsec/clients/ios_config.mobileconfig <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>IKEv2</key>
            <dict>
                <key>AuthName</key>
                <string>your_username</string>
                <key>AuthPassword</key>
                <string>your_password</string>
                <key>AuthenticationMethod</key>
                <string>None</string>
                <key>ChildSecurityAssociationParameters</key>
                <dict>
                    <key>EncryptionAlgorithm</key>
                    <string>AES-256</string>
                    <key>IntegrityAlgorithm</key>
                    <string>SHA2-256</string>
                </dict>
                <key>DeadPeerDetectionRate</key>
                <string>Medium</string>
                <key>DisableMOBIKE</key>
                <integer>0</integer>
                <key>DisableRedirect</key>
                <integer>0</integer>
                <key>EnableCertificateRevocationCheck</key>
                <integer>0</integer>
                <key>EnablePFS</key>
                <integer>0</integer>
                <key>IKESecurityAssociationParameters</key>
                <dict>
                    <key>EncryptionAlgorithm</key>
                    <string>AES-256</string>
                    <key>IntegrityAlgorithm</key>
                    <string>SHA2-256</string>
                    <key>DiffieHellmanGroup</key>
                    <integer>14</integer>
                </dict>
                <key>LocalIdentifier</key>
                <string>your_vpn_server_domain_or_ip</string>
                <key>PayloadCertificateUUID</key>
                <string></string>
                <key>RemoteAddress</key>
                <string>your_vpn_server_domain_or_ip</string>
                <key>RemoteIdentifier</key>
                <string>your_vpn_server_domain_or_ip</string>
                <key>UseConfigurationAttributeInternalIPSubnet</key>
                <integer>0</integer>
            </dict>
            <key>PayloadDescription</key>
            <string>Configures VPN settings</string>
            <key>PayloadDisplayName</key>
            <string>VPN</string>
            <key>PayloadIdentifier</key>
            <string>com.apple.vpn.managed</string>
            <key>PayloadOrganization</key>
            <string></string>
            <key>PayloadType</key>
            <string>com.apple.vpn.managed</string>
            <key>PayloadUUID</key>
            <string>$(uuidgen)</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>IKEv2 VPN</string>
    <key>PayloadIdentifier</key>
    <string>$(uuidgen)</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>$(uuidgen)</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
EOF

# Android configuration
cat > /etc/ipsec/clients/android_config.sswan <<EOF
{
    "uuid": "$(uuidgen)",
    "name": "IKEv2 VPN",
    "type": "ikev2-eap",
    "remote": {
        "addr": "your_vpn_server_domain_or_ip",
        "send_certreq": false
    },
    "local": {
        "auth": "eap",
        "eap_id": "your_username"
    },
    "eap": {
        "username": "your_username",
        "password": "your_password"
    },
    "ike_proposals": "aes256-sha256-modp2048",
    "esp_proposals": "aes256-sha256-modp2048"
}
EOF

echo "iOS configuration file: /etc/ipsec/clients/ios_config.mobileconfig"
echo "Android configuration file: /etc/ipsec/clients/android_config.sswan"

