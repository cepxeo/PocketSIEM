from flask import Blueprint, current_app, request, abort
from functools import wraps
import jwt

from api.winlog import WinLoginLog, SysmonProcessLog, SysmonFileLog, SysmonNetLog, SysmonEventLog
from database.models import User

api = Blueprint('api', __name__)

# Check token
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
@api.route('/logins', methods=['POST'])
@token_required
def insert_login_logs(current_user):
    login = WinLoginLog(request.form)
    login.save_log()
    return ""

# Process creation logs
@api.route('/processes', methods=['POST'])
@token_required
def insert_process_logs(current_user):
    process = SysmonProcessLog.parse_obj(request.form)
    process.check_log()
    process.save_log()
    return ""

# Files
@api.route('/files', methods=['POST'])
@token_required
def insert_files_logs(current_user):
    file = SysmonFileLog.parse_obj(request.form)
    file.check_log()
    file.save_log()
    return ""

# Network logs
@api.route('/net', methods=['POST'])
@token_required
def insert_net_logs(current_user):
    net = SysmonNetLog.parse_obj(request.form)
    net.check_log()
    return ""

# Events
@api.route('/events', methods=['POST'])
@token_required
def insert_events_logs(current_user):
    event = SysmonEventLog.parse_obj(request.form)
    event.check_log()
    event.save_log()
    return ""