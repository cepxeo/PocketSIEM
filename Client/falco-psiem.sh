#!/bin/bash

curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg

sudo bash -c 'cat > /etc/apt/sources.list.d/falcosecurity.list <<EOL
deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main
EOL'

sudo apt-get update -y
sudo apt-get install -y dkms make linux-headers-$(uname -r) dialog
echo "Choose Kmod"
sudo apt-get install -y falco

wget https://raw.githubusercontent.com/cepxeo/PocketSIEM/main/Client/falco.yaml
echo "Enter psiem domain name:"
read domainname
sed -i "s/MYDOMAIN.COM/${domainname}/" falco.yaml
sudo mv falco.yaml /etc/falco/
echo "Run sudo systemctl status falco"
