#!/bin/bash

# Update the system
# apt-get update && apt-get upgrade -y

# Install necessary software
# apt-get install -y strongswan strongswan-plugin-eap-mschapv2 moreutils iptables-persistent

# Set up VPN configuration


HOST=$(curl -s https://api.ipify.org)
VPN_USERNAME="vpn"
VPN_PASSWORD="your_password"

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
    leftid=$HOST
    leftauth=pubkey
    leftsendcert=never
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
$VPN_USERNAME %any% : EAP "$VPN_PASSWORD"
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

# Print connection details for iOS and Android
echo "Connection details:"
echo "Server: your_vpn_server_domain_or_ip"
echo "Type: IKEv2"
echo "Username: your_username"
echo "Password: your_password"
