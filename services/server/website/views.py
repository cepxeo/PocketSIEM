from flask import Blueprint, request, jsonify, g, url_for, render_template, redirect, session
from datetime import datetime, timedelta
from functools import wraps

from database.models import db, User, Login, Process, File, Network, Event, Alert, Filter
from sqlalchemy import not_, or_

website = Blueprint('website', __name__)

false_positives = [x[0] for x in db.session.query(Filter.item)]
if false_positives == []:
    false_positives = ['']
    
DEFAULT_DATE_RANGE = '7'
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

# Logins logs
@website.route('/logins', methods=['GET'])
@require_login
def login():
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = DEFAULT_DATE_RANGE
        template = 'events.html'

    page = request.args.get('page', 1, type=int)
    logs = Login.query.filter(
        Login.date >= datetime.today() - timedelta(days=int(range))
        ).filter(not_(or_(*[Login.image.like(item) for item in false_positives]))
        ).order_by(Login.date.desc()).paginate(page=page, per_page=ROWS_PER_PAGE)

    hosts = [x[0] for x in db.session.query(Login.host).distinct()]
    return render_template(
        template, logs=logs, hosts=hosts,
        header1="Date", header2="Host", header3="User", header4="Logon Type", header5="Process Name",
        hostroute='website.login_host_logs', selfroute='website.login')

@website.route("/logins/<host>", methods=["GET"])
@require_login
def login_host_logs(host):
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = DEFAULT_DATE_RANGE
        template = 'events.html'

    page = request.args.get('page', 1, type=int)

    logs = Login.query.filter(Login.host == host).filter(
        Login.date >= datetime.today() - timedelta(days=int(range))
        ).filter(not_(or_(*[Login.image.like(item) for item in false_positives]))
        ).order_by(Login.date.desc()).paginate(page=page, per_page=ROWS_PER_PAGE)

    hosts = [x[0] for x in db.session.query(Login.host).distinct()]
    return render_template(
        template, logs=logs, hosts=hosts, currenthost = host,
        header1="Date", header2="Host", header3="User", header4="Logon Type", header5="Process Name", 
        hostroute='website.login_host_logs', selfroute='website.login_host_logs')

# Process creation logs
@website.route('/processes', methods=['GET'])
@require_login
def process():
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = DEFAULT_DATE_RANGE
        template = 'events.html'

    page = request.args.get('page', 1, type=int)

    logs = Process.query.filter(
        Process.date >= datetime.today() - timedelta(days=int(range))
        ).filter(not_(or_(*[Process.image.like(item) for item in false_positives]))
        ).order_by(Process.date.desc()).paginate(page=page, per_page=ROWS_PER_PAGE)

    hosts = [x[0] for x in db.session.query(Process.host).distinct()]
    return render_template(
            template, logs=logs, hosts=hosts,
            header1="Date", header2="Host", header3="Image", header4="Company", header5="Command line",
            hostroute='website.process_host_logs', selfroute='website.process')

@website.route("/processes/<host>", methods=["GET"])
@require_login
def process_host_logs(host):
    page = request.args.get('page', 1, type=int)
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = DEFAULT_DATE_RANGE
        template = 'events.html'    
    
    logs = Process.query.filter(Process.host == host).filter(
        Process.date >= datetime.today() - timedelta(days=int(range))
        ).filter(not_(or_(*[Process.image.like(item) for item in false_positives]))
        ).order_by(Process.date.desc()).paginate(page=page, per_page=ROWS_PER_PAGE)

    hosts = [x[0] for x in db.session.query(Process.host).distinct()]    
    return render_template(
        template, logs=logs, hosts=hosts, currenthost = host,
        header1="Date", header2="Host", header3="Image", header4="Company", header5="Command line", 
        hostroute='website.process_host_logs', selfroute='website.process_host_logs')
        
# File creation logs
@website.route('/files', methods=['GET'])
@require_login
def files():
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = DEFAULT_DATE_RANGE
        template = 'events.html'

    page = request.args.get('page', 1, type=int)
    logs = File.query.filter(
        File.date >= datetime.today() - timedelta(days=int(range))
        ).filter(not_(or_(*[File.image.like(item) for item in false_positives]))
        ).order_by(File.date.desc()).paginate(page=page, per_page=ROWS_PER_PAGE)

    hosts = [x[0] for x in db.session.query(File.host).distinct()]

    return render_template(
            template, logs=logs, hosts=hosts,
            header1="Date", header2="Host", header3="Image", header4="File Name", header5="User",
            hostroute='website.files_host_logs', selfroute='website.files')

@website.route("/files/<host>", methods=["GET"])
@require_login
def files_host_logs(host): 
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = DEFAULT_DATE_RANGE
        template = 'events.html'
    
    page = request.args.get('page', 1, type=int)

    logs = File.query.filter(File.host == host).filter(
        File.date >= datetime.today() - timedelta(days=int(range))
        ).filter(not_(or_(*[File.image.like(item) for item in false_positives]))
        ).order_by(File.date.desc()).paginate(page=page, per_page=ROWS_PER_PAGE)

    hosts = [x[0] for x in db.session.query(File.host).distinct()]
    return render_template(
        template, logs=logs, hosts=hosts, currenthost = host,
        header1="Date", header2="Host", header3="Image", header4="File Name", header5="User",
        hostroute='website.files_host_logs', selfroute='website.files_host_logs')

# Network logs
@website.route('/net', methods=['GET'])
@require_login
def net():
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = DEFAULT_DATE_RANGE
        template = 'events.html'

    page = request.args.get('page', 1, type=int)
    logs = Network.query.filter(
        Network.date >= datetime.today() - timedelta(days=int(range))
        ).filter(not_(or_(*[Network.image.like(item) for item in false_positives]))
        ).order_by(Network.date.desc()).paginate(page=page, per_page=ROWS_PER_PAGE)

    hosts = [x[0] for x in db.session.query(Network.host).distinct()]
    return render_template(
            template, logs=logs, hosts=hosts,
            header1="Date", header2="Host", header3="Image", header4="Dest IP", header5="Dest Port", 
            hostroute='website.net_host_logs', selfroute='website.net')

@website.route("/net/<host>", methods=["GET"])
@require_login
def net_host_logs(host):
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = DEFAULT_DATE_RANGE
        template = 'events.html'

    page = request.args.get('page', 1, type=int)
    logs = Network.query.filter(Network.host == host).filter(
        Network.date >= datetime.today() - timedelta(days=int(range))
        ).filter(not_(or_(*[Network.image.like(item) for item in false_positives]))
        ).order_by(Network.date.desc()).paginate(page=page, per_page=ROWS_PER_PAGE)

    hosts = [x[0] for x in db.session.query(Network.host).distinct()]
    return render_template(
        template, logs=logs, hosts=hosts, currenthost = host,
        header1="Date", header2="Host", header3="Image", header4="Dest IP", header5="Dest Port", 
        hostroute='website.net_host_logs', selfroute='website.net_host_logs')

# Events
@website.route('/events', methods=['GET'])
@require_login
def events():
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = DEFAULT_DATE_RANGE
        template = 'events.html'

    page = request.args.get('page', 1, type=int)
    logs = Event.query.filter(
        Event.date >= datetime.today() - timedelta(days=int(range))
        ).filter(not_(or_(*[Event.image.like(item) for item in false_positives]))
        ).order_by(Event.date.desc()).paginate(page=page, per_page=ROWS_PER_PAGE)

    hosts = [x[0] for x in db.session.query(Event.host).distinct()]
    return render_template(
            template, logs=logs, hosts = hosts,
            header1="Date", header2="Host", header3="Image", header4="Event", header5="Details", 
            hostroute='website.events_host_logs', selfroute='website.events')

@website.route("/events/<host>", methods=["GET"])
@require_login
def events_host_logs(host):
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = DEFAULT_DATE_RANGE
        template = 'events.html'
    
    page = request.args.get('page', 1, type=int)

    logs = Event.query.filter(Event.host == host).filter(
        Event.date >= datetime.today() - timedelta(days=int(range))
        ).filter(not_(or_(*[Event.image.like(item) for item in false_positives]))
        ).order_by(Event.date.desc()).paginate(page=page, per_page=ROWS_PER_PAGE)

    hosts = [x[0] for x in db.session.query(Event.host).distinct()]
    return render_template(
        template, logs=logs, hosts=hosts, currenthost = host,
        header1="Date", header2="Host", header3="Image", header4="Event", header5="Details", 
        hostroute='website.events_host_logs', selfroute='website.events_host_logs')

# Alerts
@website.route('/alerts', methods=['GET'])
@require_login
def alerts():
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = DEFAULT_DATE_RANGE
        template = 'events.html'

    page = request.args.get('page', 1, type=int)

    logs = Alert.query.filter(
        Alert.date >= datetime.today() - timedelta(days=int(range))
        ).order_by(Alert.date.desc()).paginate(page=page, per_page=ROWS_PER_PAGE)

    hosts = [x[0] for x in db.session.query(Alert.host).distinct()]
    return render_template(
            template, logs=logs, hosts=hosts,
            header1="Date", header2="Host", header3="Image", header4="Rule", header5="Details", 
            hostroute='website.host_alerts', selfroute='website.alerts')

@website.route("/alerts/<host>", methods=["GET"])
@require_login
def host_alerts(host):
    range = request.args.get('range', None)
    if range:
        template = 'events_range.html'
    else:
        range = DEFAULT_DATE_RANGE
        template = 'events.html'
    
    page = request.args.get('page', 1, type=int)

    logs = Alert.query.filter(Alert.host == host).filter(
        Alert.date >= datetime.today() - timedelta(days=int(range))
        ).order_by(Alert.date.desc()).paginate(page=page, per_page=ROWS_PER_PAGE)
    
    hosts = [x[0] for x in db.session.query(Alert.host).distinct()]
    return render_template(
        template, logs=logs, hosts=hosts, currenthost = host,
        header1="Date", header2="Host", header3="Image", header4="Rule", header5="Details", 
        hostroute='website.host_alerts', selfroute='website.host_alerts')

# False positives filter
@website.route("/false", methods=["GET"])
@require_login
def false_process():
    image  = request.args.get('image', None)
    send_to  = request.args.get('send_to', None)
    host  = request.args.get('host', None)
    false_positives.append("%" + image.split('\\')[-1])
    if 'host' in send_to:
        return redirect(url_for(send_to, host = host))
    return redirect(url_for(send_to.split('_')[0]))

@website.route("/clearfilter", methods=["GET"])
@require_login
def clear_filter():
    Filter.query.delete()
    false_positives.clear()
    false_positives.append('')
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
def save_filter():
    Filter.query.delete()
    for item in false_positives:
        newFilter = Filter(item=item)
        db.session.add(newFilter)
    db.session.commit()
    return redirect(url_for('website.show_filter'))

@website.route("/clearalerts", methods=["GET"])
@require_login
def clear_alerts():
    Alert.query.delete()
    return redirect(url_for('website.alerts'))