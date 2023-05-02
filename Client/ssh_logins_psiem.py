#!/usr/bin/env python

import re
import sys
import os.path
import os
from datetime import datetime
import requests
import socket

# !! IMPORTANT!!
# Change rsyslog date format and restart the service
# sudo sed -i "s/\$ActionFileDefaultTemplate/\#\$ActionFileDefaultTemplate/" /etc/rsyslog.conf
# sudo service rsyslog restart
# Fill in the values below:
HOSTNAME = "MYDOMAIN.COM"
TOKEN = "YOUR_TOKEN"

def usage():
    print("Usage: " + sys.argv[0] + " [AUTHENTICATION METHOD] [SCOPE] [DEBUG]")
    print("Usage: " + sys.argv[0] + " [pubkey|password|all] [valid|failed|invalid|all] verbose|off")
    print("Example: " + sys.argv[0] + " pubkey failed off")
    sys.exit()

def send_log(date, osuser, logon_type, process_name):
    response = requests.post(HOSTNAME + "/logins", verify=False, data={
        "date": date,
        "host": str(socket.gethostname()),
        "osuser": osuser,
        "logon_type": logon_type,
        "process_name": process_name,
        },headers={
        'x-access-tokens': TOKEN
        })
    print(response.status_code)
    
def log_line_parser(line):
    global debug
    if "message repeated" in line:
        return
    match0 = re.search('([^\s]+)', line)
    match1 = re.search('for(.+?)from', line)
    match2 = re.search('from(.+?)port', line)
    match3 = re.search('sshd\[.*\]:(.+)for', line)
    timestamp = match0.group().split(".")[0].replace("T", " ")
    username = match1.group(1).replace("invalid user ","")
    ipaddress = match2.group(1)
    auth_result = match3.group(1)
    if debug:
        print(line, end = '')
    else:
        print(timestamp + auth_result + username + ipaddress)
        send_log(timestamp, username, ipaddress, auth_result)

def log_reset_line_parser(line):
    global debug
    try:
        match0 = re.search('([^\s]+)', line)
        match1 = re.search('by(.+?)user', line)
        match2 = re.search('user(.+?)port', line)
        timestamp = match0.group().split(".")[0].replace("T", " ")
        auth_result = match1.group(1)
        username = match2.group(1).split()[0]
        ipaddress = match2.group(1).split()[1]
    except:
        if debug:
            print("Can not parse connection reset line")
        return

    if "authenticating" in auth_result:
        auth_result = "Invalid credentials"
    elif "invalid" in auth_result:
        auth_result = "Invalid user"
    if debug:
        print(line, end = '')
    else:
        print(timestamp, auth_result, username, ipaddress)
        send_log(timestamp, username, ipaddress, auth_result)

def log_file_parser(log_type, log_scope):
    centos_ssh_log_file_path = "/var/log/secure"
    ubuntu_ssh_log_file_path = "/var/log/auth.log"

    ssh_log_files = [centos_ssh_log_file_path, ubuntu_ssh_log_file_path]

    password_valid_login = "sshd\[.*\]*Accepted password"
    password_failed_login = "sshd\[.*\]*Failed password"
    pubkey_valid_login = "sshd\[.*\]*Accepted publickey"
    pubkey_failed_login = "sshd\[.*\]*Failed publickey"
    invalid_login = "sshd\[.*\]*for invalid user"
    connection_reset = "sshd\[.*\]*Connection reset"

    for log_file in ssh_log_files:
        if os.path.isfile(log_file):
            with open(log_file, "r") as file:
                for line in file:

                    if log_scope == 'valid' or log_scope == 'all':
                        if log_type == 'password' or log_type == 'all':
                            for match in re.finditer(password_valid_login, line, re.S):
                                log_line_parser(line)
                        if log_type == 'pubkey' or log_type == 'all':
                            for match in re.finditer(pubkey_valid_login, line, re.S):
                                log_line_parser(line)

                    if log_scope == 'failed' or log_scope == 'all':
                        if log_type == 'password' or log_type == 'all':
                            for match in re.finditer(password_failed_login, line, re.S):
                                log_line_parser(line)
                        if log_type == 'pubkey' or log_type == 'all':
                            for match in re.finditer(pubkey_failed_login, line, re.S):
                                log_line_parser(line)

                    if log_scope == 'invalid' or log_scope == 'all':
                        #for match in re.finditer(invalid_login, line, re.S):
                        #    log_line_parser(line)
                        for match in re.finditer(connection_reset, line, re.S):
                            log_reset_line_parser(line)
            file.close()
            os.system('sudo truncate /var/log/auth.log --size 0')

if __name__ == '__main__':
    if len(sys.argv) > 3:
        log_type   = sys.argv[1]
        log_scope  = sys.argv[2]
        verbose    = sys.argv[3]

        if verbose == 'verbose':
            debug = True
        else:
            debug = False
        log_file_parser(log_type, log_scope)

    else:
        usage()
