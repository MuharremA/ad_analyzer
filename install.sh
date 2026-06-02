#!/bin/bash
apt-get update -qq
apt-get install -y nmap ldap-utils python3-pip python3-venv
python3 -m venv venv
source venv/bin/activate
pip install -q ldap3
echo "[+] Installation complete!"
