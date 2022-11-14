from celery import shared_task
import whois

from database.models import db, Network, Alert
from . import load_simple_rules
from . import load_sysmon_rules

""" This module contains tasks offloaded to Celery, such as:

Loading malicious patterns from simple list and parsed Sigma rules list
Checking each incoming log for matching malicious patterns
Writing an alert the the Alert DB table

Filtering out trusted IP addresses, such as the internal ones or 
belonging to known companies to reduce false positives.
"""

evil_patterns = []
evil_patterns = load_simple_rules.load_rules(evil_patterns, "detect/rules/rules_simple.txt")
print ("[+] Loaded " + str(len(evil_patterns)) + " simple patterns")

proc_creation_patterns = []
proc_creation_patterns = load_sysmon_rules.load_rules(proc_creation_patterns, "detect/rules/rules_process_creation.txt", 2)
print ("[+] Loaded " + str(len(proc_creation_patterns)) + " process creation rules")

reg_manip_patterns = []
reg_manip_patterns = load_sysmon_rules.load_rules(reg_manip_patterns, "detect/rules/rules_registry_manipulation.txt", 1)
print ("[+] Loaded " + str(len(reg_manip_patterns)) + " registry manipulation rules")

file_manip_patterns = []
file_manip_patterns = load_sysmon_rules.load_rules(file_manip_patterns, "detect/rules/rules_file_manipulation.txt", 1)
print ("[+] Loaded " + str(len(file_manip_patterns)) + " file manipulation rules")

network_conn_patterns = []
network_conn_patterns = load_sysmon_rules.load_rules(network_conn_patterns, "detect/rules/rules_network_connection.txt", 1)
print ("[+] Loaded " + str(len(network_conn_patterns)) + " network connection rules")

trusted_ips = []
internal_ips = ['10', '192', '127', '172', '169', '240', '255']
trusted_orgs = ['microsoft.com','markmonitor.com', 'yandex.net']

@shared_task
def sleep_test():
    import time
    time.sleep(5)
    return ""

@shared_task
def check_log(date, host, image, details):

    """ Checking incoming log to match any of the known malicious patterns
    from the list (rules/commands.txt)
    """

    for pattern in evil_patterns:
        # Check for antipatterns
        full_pattern_array = pattern.split("%")
        if len(full_pattern_array) > 1:
            if any(anti_pattern.casefold() in details.casefold() for anti_pattern in full_pattern_array[1].split("*")):
                continue
            pattern_array = full_pattern_array[0].split("*")
        else:
            pattern_array = pattern.split("*")

        pattern_array = [i for i in pattern_array if i]
        match_pattern =  all(elem.casefold() in details.casefold() for elem in pattern_array)
        filter_trash = all(len(elem) > 1 for elem in pattern_array)

        if match_pattern and filter_trash:
            print(f"[!!] Event alert triggered by the rule: {pattern}")
            print(f"[!!] Malicious command: {details}")
            newAlert = Alert(date=date, host=host, image=image, field4=pattern, field5=details)
            db.session.add(newAlert)
            db.session.commit()

def run_check(rules_dict, field_names, or_field_names, date, host, image, details):

    """ Execute the check and save an alert in DB
    """
    for rule in rules_dict:
        flags = 0
        for key in rule.keys():
            for field in field_names.keys():
                if key[:3] == 'NOT':
                    if key.replace("NOT ", "").replace("AND ", "") == field and not all(item.casefold() in field_names[field].casefold() for item in rule[key]):
                        flags += 1
                if key.replace("AND ", "") == field and all(item.casefold() in field_names[field].casefold() for item in rule[key]):
                    flags += 1

            for field in or_field_names.keys():
                if key[:3] == 'NOT':
                    if key.replace("NOT ", "").replace("AND ", "") == field and not any(item.casefold() in or_field_names[field].casefold() for item in rule[key]):
                        flags += 1
                if key.replace("AND ", "") == field and any(item.casefold() in or_field_names[field].casefold() for item in rule[key]):
                    flags += 1

        if flags == len(rule.keys()):
            print(f"[!!] Event alert triggered by the process creation rule: {rule}")
            print(f"[!!] Malicious command: {details}")
            str_rule = str(rule)
            newAlert = Alert(date=date, host=host, image=image, field4=str_rule, field5=details)
            db.session.add(newAlert)
            db.session.commit()
            return

@shared_task
def check_process(date, host, image, command_line, parent_image, parent_command_line, description, product, original_file_name, process_user):
    field_names = {'ParentCommandLine':parent_command_line, 'ParentImage':parent_image, 'Image':image, 'CommandLine':command_line, 
        'OriginalFileName':original_file_name,'Description':description,'Product':product,'User':process_user}
    or_field_names = {'OR ParentCommandLine':parent_command_line, 'OR ParentImage':parent_image, 'OR Image':image, 'OR CommandLine':command_line, 
        'OR OriginalFileName':original_file_name,'Description':description,'Product':product,'User':process_user}

    run_check(proc_creation_patterns, field_names, or_field_names, date, host, image, command_line)

@shared_task
def check_registry(date, host, image, details):
    field_names = {'TargetObject':details, 'NewName':details, 'Image':image, 'Details':details, 'EventType':details}
    or_field_names = {'OR TargetObject':details, 'OR NewName':details, 'OR Image':image, 'OR Details':details, 'OR EventType':details}

    run_check(reg_manip_patterns, field_names, or_field_names, date, host, image, details)

@shared_task
def check_files(date, host, image, filename, osuser):
    field_names = {'Image':image, 'TargetFilename':filename, 'User':osuser}
    or_field_names = {'OR Image':image, 'OR TargetFilename':filename, 'OR User':osuser}

    run_check(file_manip_patterns, field_names, or_field_names, date, host, image, filename)

@shared_task
def check_network(date, host, image, dest_ip, dest_port):
    field_names = {'Image':image, 'DestinationIP':dest_ip, 'DestinationHostname':dest_ip, 'DestinationPort':dest_port}
    or_field_names = {'OR Image':image, 'OR DestinationIP':dest_ip, 'OR DestinationHostname':dest_ip, 'OR DestinationPort':dest_port}

    run_check(network_conn_patterns, field_names, or_field_names, date, host, image, dest_ip)

@shared_task
def check_whois(date, host, image, dest_ip, dest_port):
    """Checking the whois service for known orgs for given IPs

    Wouldn't run if service runs in the isolated segment. Also skip the checks if IP is a typical internal one.
    """

    #if current_app.config['ONLINE_CHECKS'] == 'True' and dest_ip.split(".")[0] not in internal_ips:      
    if dest_ip.split(".")[0] not in internal_ips and dest_ip not in trusted_ips:
        w = whois.whois(dest_ip)
        whois_emails = w.emails
        for trusted_org in trusted_orgs:
            # If IP belongs to trusted org, don't add it to the DB and append the trusted IPs list
            if whois_emails != None and list(filter(lambda x: trusted_org in x, whois_emails)):
                trusted_ips.append(dest_ip)
                return
        # If IP is not trusted and not internal, print it
        if whois_emails != None:
            print(f"{dest_ip} for process {image} belongs to {whois_emails}")
        
        newNetwork = Network(date=date, host=host, image=image, field4=dest_ip, field5=dest_port)
        db.session.add(newNetwork)
        db.session.commit()