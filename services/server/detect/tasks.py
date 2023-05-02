from celery import shared_task
import whois
import logging

from database.models import db, Network, Alert
from . import load_simple_rules
from . import load_sysmon_rules

""" This module contains tasks offloaded to Celery, such as:

Loading malicious patterns from simple list and parsed Sigma rules list;
Checking each incoming log for matching malicious patterns;
Writing an alert to the Alert table;
Filtering out trusted IP addresses, such as the internal ones or 
belonging to known companies to reduce output.
"""

evil_patterns = []
evil_patterns = load_simple_rules.load_rules(evil_patterns, "detect/rules/rules_simple.txt")
logging.info("[+] Loaded " + str(len(evil_patterns)) + " simple patterns")

proc_creation_patterns = []
proc_creation_patterns = load_sysmon_rules.load_rules(proc_creation_patterns, "detect/rules/rules_process_creation.txt", 2)
logging.info("[+] Loaded " + str(len(proc_creation_patterns)) + " process creation rules")

reg_manip_patterns = []
reg_manip_patterns = load_sysmon_rules.load_rules(reg_manip_patterns, "detect/rules/rules_registry_manipulation.txt", 1)
logging.info("[+] Loaded " + str(len(reg_manip_patterns)) + " registry manipulation rules")

file_manip_patterns = []
file_manip_patterns = load_sysmon_rules.load_rules(file_manip_patterns, "detect/rules/rules_file_manipulation.txt", 1)
logging.info("[+] Loaded " + str(len(file_manip_patterns)) + " file manipulation rules")

network_conn_patterns = []
network_conn_patterns = load_sysmon_rules.load_rules(network_conn_patterns, "detect/rules/rules_network_connection.txt", 1)
logging.info("[+] Loaded " + str(len(network_conn_patterns)) + " network connection rules")

trusted_ips = []
internal_ips = ['10', '192', '127', '172', '169', '240', '255']
trusted_orgs = ['microsoft.com','markmonitor.com', 'yandex.net']

@shared_task
def sleep_test():
    import time
    time.sleep(5)
    return ""

@shared_task
def check_log(date, host, image, details) -> None:
    """ Checks incoming log to match any of the known malicious patterns
    from the simple rules list (rules/commands.txt).
    Expects received log fields.
    If details field contains any of the rule string, the Alert is raised and saved to DB
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
            logging.warning(f"[!!] Event alert triggered by the rule: {pattern}")
            logging.warning(f"[!!] Malicious command: {details}")
            newAlert = Alert(date=date, host=host, image=image, field4=pattern, field5=details)
            db.session.add(newAlert)
            db.session.commit()

def _run_check(rules_dict, field_names, date, host, image, details) -> None:
    """ Executes the check and saves an alert in DB
    """
    for rule in rules_dict:
        pattern_flags = 0
        for key in rule.keys():
            if "OR " in key:
                for field in field_names.keys():
                    if key[:3] == 'NOT':
                        if key.split()[-1] == field and not any(item.casefold() in field_names[field].casefold() for item in rule[key]):
                            pattern_flags += 1
                    else:
                        if key.split()[-1] == field and any(item.casefold() in field_names[field].casefold() for item in rule[key]):
                            pattern_flags += 1
            else:
                for field in field_names.keys():
                    if key[:3] == 'NOT':
                        if key.split()[-1] == field and not all(item.casefold() in field_names[field].casefold() for item in rule[key]):
                            pattern_flags += 1
                    else:
                        if key.split()[-1] == field and all(item.casefold() in field_names[field].casefold() for item in rule[key]):
                            pattern_flags += 1

        if pattern_flags == len(rule.keys()):
            logging.warning(f"[!!] Event alert triggered by the process creation rule: {rule}")
            logging.warning(f"[!!] Malicious command: {details}")
            str_rule = str(rule)
            newAlert = Alert(date=date, host=host, image=image, field4=str_rule, field5=details)
            db.session.add(newAlert)
            db.session.commit()
            break

@shared_task
def check_process(date, host, image, command_line, parent_image, parent_command_line, description, original_file_name, process_user) -> None:
    field_names = {'ParentCommandLine':parent_command_line, 'ParentImage':parent_image, 'Image':image, 'CommandLine':command_line, 
        'OriginalFileName':original_file_name,'Description':description,'User':process_user}
    _run_check(proc_creation_patterns, field_names, date, host, image, command_line)

@shared_task
def check_registry(date, host, image, details) -> None:
    field_names = {'TargetObject':details, 'NewName':details, 'Image':image, 'Details':details, 'EventType':details}
    _run_check(reg_manip_patterns, field_names, date, host, image, details)

@shared_task
def check_files(date, host, image, filename, osuser) -> None:
    field_names = {'Image':image, 'TargetFilename':filename, 'User':osuser}
    _run_check(file_manip_patterns, field_names, date, host, image, filename)

@shared_task
def check_network(date, host, image, dest_ip, dest_port) -> None:
    field_names = {'Image':image, 'DestinationIP':dest_ip, 'DestinationHostname':dest_ip, 'DestinationPort':dest_port}
    _run_check(network_conn_patterns, field_names, date, host, image, dest_ip)

@shared_task
def check_whois(date, host, image, dest_ip, dest_port) -> None:
    """Checks the whois service for known orgs for given IPs
    Skips the checks if IP is a typical internal or trusted one.
    TODO: Wouldn't run if service runs in the isolated segment.
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
            logging.warning(f"{dest_ip} for process {image} belongs to {whois_emails}")
        
        newNetwork = Network(date=date, host=host, image=image, field4=dest_ip, field5=dest_port)
        db.session.add(newNetwork)
        db.session.commit()