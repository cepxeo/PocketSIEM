from celery import shared_task
import whois

from database.models import db, Network, Alert
from . import sigma_parse

evil_patterns = []
evil_patterns = sigma_parse.load_rules(evil_patterns, "rules")
print ("[+] Loaded " + str(len(evil_patterns)) + " evil commands patterns.")

trusted_ips = []
internal_ips = ['10', '192', '127', '172', '169', '240', '255']
trusted_orgs = ['microsoft.com','markmonitor.com']

@shared_task
def sleep_test():
    import time
    time.sleep(5)
    return ""

@shared_task
def check_log(date, host, image, command_line):
    for pattern in evil_patterns:
        full_pattern_array = pattern.split("%")

        # Check for antipattern
        if len(full_pattern_array) > 1:
            if full_pattern_array[1] in command_line:
                continue
            pattern_array = full_pattern_array[0].split("*")
        else:
            pattern_array = pattern.split("*")

        pattern_array = [i for i in pattern_array if i]
        match_pattern =  all(elem.casefold() in command_line.casefold() for elem in pattern_array)
        filter_trash = all(len(elem) > 1 for elem in pattern_array)

        if match_pattern and filter_trash:
            print("[!!] Event alert triggered by the rule: %s" % pattern)
            print("[!!] Malicious command: %s" % command_line)
            newAlert = Alert(date=date, host=host, image=image, field4=pattern, field5=command_line)
            db.session.add(newAlert)
            db.session.commit()

@shared_task
def check_whois(date, host, image, dest_ip, dest_port):
    # Checking the whois service for known orgs for given IPs
    # Wouldn't run if service runs in the isolated segment. Also skip the checks if IP is a typical internal one.
    #if current_app.config['ONLINE_CHECKS'] == 'True' and dest_ip.split(".")[0] not in internal_ips:      
    if dest_ip.split(".")[0] not in internal_ips:
        if dest_ip in trusted_ips:
            return ""
        else:
            w = whois.whois(dest_ip)
            whois_emails = w.emails
            for trusted_org in trusted_orgs:
                # If IP belongs to trusted org, don't add it to the DB and append the trusted IPs list
                if whois_emails != None and list(filter(lambda x: trusted_org in x, whois_emails)):
                    trusted_ips.append(dest_ip)
                    return ""
            # If IP is not trusted and not internal, print it
            if whois_emails != None:
                print(f"{dest_ip} for process {image} belongs to {whois_emails}")
            
    newNetwork = Network(date=date, host=host, image=image, field4=dest_ip, field5=dest_port)
    db.session.add(newNetwork)
    db.session.commit()