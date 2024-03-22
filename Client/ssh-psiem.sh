#! /bin/bash

mkdir -p ~/apps/ssh && cd ~/apps/ssh
wget https://raw.githubusercontent.com/cepxeo/PocketSIEM/main/Client/ssh_logins_psiem.py -O ssh.py

echo "Enter psiem domain name:"
read domainname
sed -i "s/MYDOMAIN.COM/https:\/\/${domainname}/" ~/apps/ssh/ssh.py
echo "Enter token value:"
read token
sed -i "s/YOUR_TOKEN/${token}/" ~/apps/ssh/ssh.py

echo "Clearing auth.log"
sudo truncate /var/log/auth.log --size 0

echo "Giving user the read righs to auth.log"
sudo chmod +r /var/log/auth.log

echo "Adjusting time format in rsyslog"
sudo sed -i "s/\$ActionFileDefaultTemplate/\#\$ActionFileDefaultTemplate/" /etc/rsyslog.conf
sudo service rsyslog restart

random_minute=$(shuf -i 1-59 -n 1)
#(crontab -l ; echo "${random_minute} * * * * python3 /home/${USER}/apps/ssh/ssh.py all all off") | crontab -
echo "${random_minute} * * * * python3 /home/${USER}/apps/ssh/ssh.py all all off" | crontab -

echo "0 1 * * * chmod +r /var/log/auth.log" | sudo crontab -u root -

echo "done"