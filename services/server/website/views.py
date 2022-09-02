from flask import Blueprint, request, jsonify, g, url_for, render_template, redirect, session
from datetime import datetime, timedelta
from functools import wraps

from database.models import User, Login, Process, File, Network, Event, Alert
from database import dbs

website = Blueprint('website', __name__)

false_positives = []
default_date_range = '7'

ROWS_PER_PAGE = 100

@website.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@website.before_request
def load_user():
    user_id = session.get('user_id')
    if user_id:
        g.user = User.query.get(user_id)
    else:
        g.user = None

def require_login(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if not g.user:
            return redirect(url_for('auth.log_in'))
        return f(*args, **kwargs)
    return wrap

@website.route('/')
def index():
    return redirect(url_for('website.alerts'))

# ----------------------------------------------------
# Logins logs
# ----------------------------------------------------

@website.route('/logins', methods=['GET'])
@require_login
def login():
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = default_date_range
        template = 'events.html'

    page = request.args.get('page', 1, type=int)
    logs = Login.query.filter(Login.date >= datetime.today() - timedelta(days=int(range))).paginate(page=page, per_page=ROWS_PER_PAGE)

    return render_template(
        template, logs=logs, 
        header1="Date", header2="Host", header3="User", header4="Logon Type", header5="Process Name", 
        field1="log.host",
        event='website.login_host_logs', false_positives=false_positives)
        

@website.route("/logins/hosts", methods=["GET"])
@require_login
def get_all_login_hosts():
    
    logs = dbs.get_login_hosts(conn)
    return jsonify(logs)

@website.route("/logins/<host>", methods=["GET"])
@require_login
def login_host_logs(host):
    
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = default_date_range
        template = 'events.html'

    page = request.args.get('page', 1, type=int)
    logs = Login.query.filter(Login.host == host).filter(Login.date >= datetime.today() - timedelta(days=int(range))).paginate(page=page, per_page=ROWS_PER_PAGE)

    return render_template(
        template, logs=logs, 
        header1="Date", header2="Host", header3="User", header4="Logon Type", header5="Process Name", 
        event='website.login', false_positives=false_positives)

# ----------------------------------------------------
# Process creation logs
# ----------------------------------------------------

@website.route('/processes', methods=['GET'])
@require_login
def process():
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = default_date_range
        template = 'events.html'

    page = request.args.get('page', 1, type=int)
    logs = Process.query.filter(Process.date >= datetime.today() - timedelta(days=int(range))).paginate(page=page, per_page=ROWS_PER_PAGE)
    
    return render_template(
            template, logs=logs,
            header1="Date", header2="Host", header3="Image", header4="Company", header5="Command line", 
            field1="log.host",
            event='website.process_host_logs', false_positives=false_positives)

@website.route("/processes/hosts", methods=["GET"])
@require_login
def get_all_process_hosts():
    
    logs = dbs.get_proc_hosts(conn)
    return jsonify(logs)

@website.route("/processes/<host>", methods=["GET"])
@require_login
def process_host_logs(host):
    
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = default_date_range
        template = 'events.html'
    
    page = request.args.get('page', 1, type=int)
    logs = Process.query.filter(Process.host == host).filter(Process.date >= datetime.today() - timedelta(days=int(range))).paginate(page=page, per_page=ROWS_PER_PAGE)
    
    return render_template(
        template, logs=logs, 
        header1="Date", header2="Host", header3="Image", header4="Company", header5="Command line", 
        event='website.process', false_positives=false_positives)
        
# ----------------------------------------------------
# File creation logs
# ----------------------------------------------------

@website.route('/files', methods=['GET'])
@require_login
def files():
    
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = default_date_range
        template = 'events.html'

    page = request.args.get('page', 1, type=int)
    logs = File.query.filter(File.date >= datetime.today() - timedelta(days=int(range))).paginate(page=page, per_page=ROWS_PER_PAGE)

    return render_template(
            template, logs=logs,
            header1="Date", header2="Host", header3="Image", header4="File Name", header5="User",
            event='website.files_host_logs', false_positives=false_positives)

@website.route("/files/hosts", methods=["GET"])
@require_login
def get_all_files_hosts():
    
    logs = dbs.get_files_hosts(conn)
    return jsonify(logs)

@website.route("/files/<host>", methods=["GET"])
@require_login
def files_host_logs(host):
    
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = default_date_range
        template = 'events.html'
    
    page = request.args.get('page', 1, type=int)
    logs = File.query.filter(File.host == host).filter(Login.host == host).filter(File.date >= datetime.today() - timedelta(days=int(range))).paginate(page=page, per_page=ROWS_PER_PAGE)

    return render_template(
        template, logs=logs, 
        header1="Date", header2="Host", header3="Image", header4="File Name", header5="User",
        event='website.files', false_positives=false_positives)

# ----------------------------------------------------
# Network logs
# ----------------------------------------------------

@website.route('/net', methods=['GET'])
@require_login
def net():
    
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = default_date_range
        template = 'events.html'

    page = request.args.get('page', 1, type=int)
    logs = Network.query.filter(Network.date >= datetime.today() - timedelta(days=int(range))).paginate(page=page, per_page=ROWS_PER_PAGE)

    return render_template(
            template, logs=logs,
            header1="Date", header2="Host", header3="Image", header4="Dest IP", header5="Dest Port", 
            event='website.net_host_logs', false_positives=false_positives)

@website.route("/net/hosts", methods=["GET"])
@require_login
def get_all_net_hosts():
    
    logs = dbs.get_network_hosts(conn)
    return jsonify(logs)

@website.route("/net/<host>", methods=["GET"])
@require_login
def net_host_logs(host):
    
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = default_date_range
        template = 'events.html'

    page = request.args.get('page', 1, type=int)
    logs = Network.query.filter(Network.host == host).filter(Network.date >= datetime.today() - timedelta(days=int(range))).paginate(page=page, per_page=ROWS_PER_PAGE)

    return render_template(
        template, logs=logs, 
        header1="Date", header2="Host", header3="Image", header4="Dest IP", header5="Dest Port", 
        event='website.net', false_positives=false_positives)

# ----------------------------------------------------
# Events
# ----------------------------------------------------

@website.route('/events', methods=['GET'])
@require_login
def events():
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = default_date_range
        template = 'events.html'

    page = request.args.get('page', 1, type=int)
    logs = Event.query.filter(Event.date >= datetime.today() - timedelta(days=int(range))).paginate(page=page, per_page=ROWS_PER_PAGE)

    return render_template(
            template, logs=logs, 
            header1="Date", header2="Host", header3="Image", header4="Event", header5="Details", 
            event='website.events_host_logs', false_positives=false_positives)

@website.route("/events/hosts", methods=["GET"])
@require_login
def get_all_events_hosts():
    
    logs = dbs.get_events_hosts(conn)
    return jsonify(logs)

@website.route("/events/<host>", methods=["GET"])
@require_login
def events_host_logs(host):
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = default_date_range
        template = 'events.html'
    
    page = request.args.get('page', 1, type=int)
    logs = Event.query.filter(Event.host == host).filter(Event.date >= datetime.today() - timedelta(days=int(range))).paginate(page=page, per_page=ROWS_PER_PAGE)

    return render_template(
        template, logs=logs, 
        header1="Date", header2="Host", header3="Image", header4="Event", header5="Details", 
        event='website.events', false_positives=false_positives)

# Alerts
# ----------------------------------------------------
@website.route('/alerts', methods=['GET'])
@require_login
def alerts():
    
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = default_date_range
        template = 'events.html'

    page = request.args.get('page', 1, type=int)
    logs = Alert.query.filter(Alert.date >= datetime.today() - timedelta(days=int(range))).paginate(page=page, per_page=ROWS_PER_PAGE)

    return render_template(
            template, logs=logs, 
            header1="Date", header2="Host", header3="Image", header4="Rule", header5="Details", 
            event='website.host_alerts')

@website.route("/alerts/hosts", methods=["GET"])
@require_login
def alerts_hosts():
    
    logs = dbs.get_alerts_hosts(conn)
    return jsonify(logs)

@website.route("/alerts/<host>", methods=["GET"])
@require_login
def host_alerts(host):
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = default_date_range
        template = 'events.html'
    
    page = request.args.get('page', 1, type=int)
    logs = Alert.query.filter(Alert.host == host).filter(Login.host == host).filter(Alert.date >= datetime.today() - timedelta(days=int(range))).paginate(page=page, per_page=ROWS_PER_PAGE)

    return render_template(
        template, logs=logs, 
        header1="Date", header2="Host", header3="Image", header4="Rule", header5="Details", 
        event='website.alerts')

# ----------------------------------------------------
# False positives filter
# ----------------------------------------------------

@website.route("/false", methods=["GET"])
@require_login
def false_process():
    image  = request.args.get('image', None)
    send_to  = request.args.get('send_to', None)
    false_positives.append(image)
    return redirect(url_for(send_to.split('_')[0]))

@website.route("/clearfilter", methods=["GET"])
@require_login
def clear_filter():
    false_positives.clear()
    return redirect(url_for('website.alerts'))

@website.route("/showfilter", methods=["GET"])
@require_login
def show_filter():
    return render_template('filter.html', items=false_positives)

@website.route("/removeitem", methods=["GET"])
@require_login
def remove_item():
    item  = request.args.get('item', None)
    false_positives.remove(item)
    return redirect(url_for('website.show_filter'))

@website.route("/savefilter", methods=["GET"])
@require_login
def save_filter(host):
    # ToDo
    return ""
