from flask import Blueprint, current_app, request, abort, jsonify
from functools import wraps
import logging
import jwt

from database.models import db, User, Login, Process, File, Event
from detect import tasks

from api.winlog import SysmonProcessLog, SysmonFileLog, SysmonNetLog

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
    process = SysmonProcessLog.parse_obj(request.form)
    process.check_log()
    process.save_log()

    logger.debug("[+] Received process from Host: %s" % process.host,)
    return ""

# Files
# ----------------------------------------------------
@api.route('/files', methods=['POST'])
@token_required
def insert_files_logs(current_user):
    file = SysmonFileLog.parse_obj(request.form)
    file.check_log()
    file.save_log()

    logger.debug("[+] Received file log from Host: %s" % file.host,)
    return ""

# Network logs
# ----------------------------------------------------
@api.route('/net', methods=['POST'])
@token_required
def insert_net_logs(current_user):
    net = SysmonNetLog.parse_obj(request.form)
    net.check_log()
    net.save_log()

    logger.debug("[+] Received network log from Host: %s" % net.host,)
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