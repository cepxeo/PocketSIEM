from flask import Blueprint, current_app, request, abort
from functools import wraps
import logging
import jwt
import whois

from database.models import db, User, Login, Process, File, Network, Event, Alert
from api import sigma_parse

api = Blueprint('api', __name__)

logger = logging.getLogger('waitress')
logger.setLevel(logging.INFO)

trusted_ips = []
internal_ips = ['10', '192', '127', '172', '169', '240', '255']
trusted_orgs = ['microsoft.com','markmonitor.com']

evil_patterns = []
evil_patterns = sigma_parse.load_rules(evil_patterns, "rules")
print ("[+] Loaded " + str(len(evil_patterns)) + " evil commands patterns.")

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']
        if not token:
            return abort(403, "Token is missing")    
        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['id']).first()
        except:
            return abort(403, "Token is invalid")
        return f(current_user, *args, **kwargs)
    return decorator

@api.route('/healthcheck')
@token_required
def healthcheck(current_user):
    return ""

# Logins logs
# ----------------------------------------------------
@api.route('/logins', methods=['POST'])
@token_required
def insert_login_logs(current_user):
    date = request.form["date"]
    host = request.form["host"]
    osuser = request.form["osuser"]
    logon_type = request.form["logon_type"]
    process_name = request.form["process_name"]

    newLogin = Login(date=date, host=host, image=osuser, field4=logon_type, field5=process_name)
    db.session.add(newLogin)
    db.session.commit()

    logger.debug("[+] Received logins from Host: %s" % host,)
    return ""

# Process creation logs
# ----------------------------------------------------
@api.route('/processes', methods=['POST'])
@token_required
def insert_process_logs(current_user):
    date = request.form["date"]
    host = request.form["host"]
    image = request.form["image"]
    company = request.form["company"]
    command_line = request.form["command_line"]

    # Check if command_line field matches any malicious pattern 
    alert = sigma_parse.check_log(evil_patterns, command_line)
    if alert:
        logger.info("[!!] Event alert triggered by the rule: %s" % alert)
        logger.info("[!!] Malicious command: %s" % command_line)
        newAlert = Alert(date=date, host=host, image=image, field4=alert, field5=command_line)
        db.session.add(newAlert)
        db.session.commit()
    
    newProcess = Process(date=date, host=host, image=image, field4=company, field5=command_line)
    db.session.add(newProcess)
    db.session.commit()

    logger.debug("[+] Received process from Host: %s" % host,)
    return ""

# Files
# ----------------------------------------------------
@api.route('/files', methods=['POST'])
@token_required
def insert_files_logs(current_user):
    date = request.form["date"]
    host = request.form["host"]
    image = request.form["image"]    
    filename = request.form["filename"]
    osuser = request.form["osuser"]

    # Check if details field matches any malicious pattern 
    alert = sigma_parse.check_log(evil_patterns, filename)
    if alert:
        logger.info("[!!] Event alert triggered by the rule: %s" % alert)
        logger.info("[!!] Malicious command: %s" % filename)
        newAlert = Alert(date=date, host=host, image=image, field4=alert, field5=filename)
        db.session.add(newAlert)
        db.session.commit()

    newFile = File(date=date, host=host, image=image, field4=filename, field5=osuser)
    db.session.add(newFile)
    db.session.commit()

    logger.debug("[+] Received file log from Host: %s" % host,)
    return ""

# Network logs
# ----------------------------------------------------
@api.route('/net', methods=['POST'])
@token_required
def insert_net_logs(current_user):
    date = request.form["date"]
    host = request.form["host"]
    image = request.form["image"]
    dest_ip = request.form["dest_ip"]
    dest_port = request.form["dest_port"]

    # Checking the whois service for known orgs for given IPs
    # Wouldn't run if service runs in the isolated segment. Also skip the checks if IP is a typical internal one.
    if current_app.config['ONLINE_CHECKS'] == 'True' and dest_ip.split(".")[0] not in internal_ips:      
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
                logger.info(f"{dest_ip} for process {image} belongs to {whois_emails}")
            
    newNetwork = Network(date=date, host=host, image=image, field4=dest_ip, field5=dest_port)
    db.session.add(newNetwork)
    db.session.commit()

    logger.debug("[+] Received network log from Host: %s" % host,)
    return ""

# Events
# ----------------------------------------------------
@api.route('/events', methods=['POST'])
@token_required
def insert_events_logs(current_user):
    date = request.form["date"]
    host = request.form["host"]
    image = request.form["image"]  
    event = request.form["event"]  
    details = request.form["details"]

    # Check if details field matches any malicious pattern 
    alert = sigma_parse.check_log(evil_patterns, details)
    if alert:
        logger.info("[!!] Event alert triggered by the rule: %s" % alert)
        logger.info("[!!] Malicious command: %s" % details)
        newAlert = Alert(date=date, host=host, image=image, field4=alert, field5=details)
        db.session.add(newAlert)
        db.session.commit()

    newEvent = Event(date=date, host=host, image=image, field4=event, field5=details)
    db.session.add(newEvent)
    db.session.commit()

    logger.debug("[+] Received event from Host: %s" % host,)
    return ""