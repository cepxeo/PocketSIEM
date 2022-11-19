from flask import Blueprint, current_app, request, abort, jsonify
from functools import wraps
import logging
import jwt

from database.models import db, User, Login, Process, File, Event
from detect import tasks

api = Blueprint('api', __name__)

logger = logging.getLogger('waitress')
logger.setLevel(logging.INFO)

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

@api.route('/celery')
@token_required
def run_task():
    task = tasks.sleep_test.delay()
    return jsonify({"task_id": task.id}), 202

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
    parent_image = request.form["parent_image"]
    parent_command_line = request.form["parent_command_line"]
    description = request.form["description"]
    product = request.form["product"]
    original_file_name = request.form["original_file_name"]
    process_user = request.form["process_user"]

    tasks.check_log.delay(date, host, image, command_line)
    tasks.check_process.delay(date, host, image, command_line, parent_image, parent_command_line, description, product, original_file_name, process_user)
    
    newProcess = Process(date=date, host=host, image=image, field4=company, field5=command_line, \
        parent_image=parent_image, parent_command_line=parent_command_line, description=description, \
        product=product, original_file_name=original_file_name, process_user=process_user)
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

    tasks.check_log.delay(date, host, image, filename)
    tasks.check_files.delay(date, host, image, filename, osuser)

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

    tasks.check_whois.delay(date, host, image, dest_ip, dest_port)
    tasks.check_network.delay(date, host, image, dest_ip, dest_port)

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

    tasks.check_log.delay(date, host, image, details)
    tasks.check_registry.delay(date, host, image, details)

    newEvent = Event(date=date, host=host, image=image, field4=event, field5=details)
    db.session.add(newEvent)
    db.session.commit()

    logger.debug("[+] Received event from Host: %s" % host,)
    return ""