from flask import Blueprint, current_app, request, abort
from functools import wraps
import logging
import jwt

from api.winlog import WinLog, SSHLoginLog
from api.falcolog import FalcoLog
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
        return f(*args, **kwargs)
    return decorator

@api.route('/healthcheck')
@token_required
def healthcheck():
    return ""

# Windows logs
@api.route('/winlog', methods=['POST'])
@token_required
def insert_win_logs():
    win_logs = WinLog.parse_obj(request.get_json())
    win_logs.save_log()
    return ""

# Logins logs
@api.route('/sshlogin', methods=['POST'])
@token_required
def insert_login_logs():
    sshlogin = SSHLoginLog.parse_obj(request.form)
    sshlogin.save_log()
    return ""

@api.route('/falcolog', methods=['POST'])
def falco_logs():
    logging.info(request.get_json())
    falco_logs = FalcoLog.parse_obj(request.get_json())
    falco_logs.save_log()
    return ""