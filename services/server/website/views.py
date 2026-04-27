from flask import Blueprint, request, jsonify, g, url_for, render_template, redirect, session
from datetime import datetime, timedelta
from functools import wraps

from database.models import db, User, Login, Process, File, Network, Event, Alert, Filter, ConnLog
from sqlalchemy import String, cast, not_, or_

website = Blueprint('website', __name__)

false_positives = [x[0] for x in db.session.query(Filter.item)]
if false_positives == []:
    false_positives = ['']
    
DEFAULT_DATE_RANGE = '7'
ROWS_PER_PAGE = 100

def page_template(full_template, range_template):
    wants_partial = (
        request.args.get('partial') == '1' or
        request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    )
    if wants_partial:
        return range_template
    return full_template

def current_date_range():
    selected_range = request.args.get('range', DEFAULT_DATE_RANGE)
    try:
        if int(selected_range) < 1:
            raise ValueError
    except (TypeError, ValueError):
        selected_range = DEFAULT_DATE_RANGE
    return selected_range

def current_search():
    return request.args.get('q', '').strip()

def route_query_args(**updates):
    route_values = dict(request.view_args or {})
    query_values = {
        key: value
        for key, value in request.args.items()
        if key not in ('page', 'partial')
    }

    for key, value in updates.items():
        if value in (None, ''):
            query_values.pop(key, None)
        else:
            query_values[key] = value

    route_values.update(query_values)
    return route_values

def escaped_like(term):
    return (
        term
        .replace('\\', '\\\\')
        .replace('%', '\\%')
        .replace('_', '\\_')
    )

def apply_search_filter(query, model):
    search = current_search()
    if not search:
        return query

    pattern = f'%{escaped_like(search)}%'
    search_filters = [
        cast(column, String).ilike(pattern, escape='\\')
        for column in model.__table__.columns
    ]
    return query.filter(or_(*search_filters))

def apply_false_positive_filter(query, model):
    if not hasattr(model, 'image'):
        return query

    filters = [
        model.image.like(item)
        for item in false_positives
        if item is not None
    ]
    if not filters:
        return query
    return query.filter(not_(or_(*filters)))

def paginated_logs(model, host=None, apply_false_positives=True):
    page = request.args.get('page', 1, type=int)
    query = model.query

    if host is not None:
        query = query.filter(model.host == host)

    query = query.filter(
        model.date >= datetime.today() - timedelta(days=int(current_date_range()))
    )

    if apply_false_positives:
        query = apply_false_positive_filter(query, model)

    query = apply_search_filter(query, model)
    return query.order_by(model.date.desc()).paginate(page=page, per_page=ROWS_PER_PAGE)

@website.context_processor
def inject_frontend_state():
    return {
        'current_range': current_date_range(),
        'current_search': current_search(),
        'route_query_args': route_query_args,
    }

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
    template = page_template('events.html', 'events_range.html')
    logs = paginated_logs(Login)

    hosts = [x[0] for x in db.session.query(Login.host).distinct()]
    return render_template(
        template, logs=logs, hosts=hosts,
        header1="Date", header2="Host", header3="User", header4="Logon Type", header5="Process Name",
        hostroute='website.login_host_logs', selfroute='website.login')

@website.route("/logins/<host>", methods=["GET"])
@require_login
def login_host_logs(host):
    template = page_template('events.html', 'events_range.html')
    logs = paginated_logs(Login, host)

    hosts = [x[0] for x in db.session.query(Login.host).distinct()]
    return render_template(
        template, logs=logs, hosts=hosts, currenthost = host,
        header1="Date", header2="Host", header3="User", header4="Logon Type", header5="Process Name", 
        hostroute='website.login_host_logs', selfroute='website.login_host_logs')

# Process creation logs
@website.route('/processes', methods=['GET'])
@require_login
def process():
    template = page_template('events.html', 'events_range.html')
    logs = paginated_logs(Process)

    hosts = [x[0] for x in db.session.query(Process.host).distinct()]
    return render_template(
            template, logs=logs, hosts=hosts,
            header1="Date", header2="Host", header3="Image", header4="Company", header5="Command line",
            hostroute='website.process_host_logs', selfroute='website.process')

@website.route("/processes/<host>", methods=["GET"])
@require_login
def process_host_logs(host):
    template = page_template('events.html', 'events_range.html')
    logs = paginated_logs(Process, host)

    hosts = [x[0] for x in db.session.query(Process.host).distinct()]    
    return render_template(
        template, logs=logs, hosts=hosts, currenthost = host,
        header1="Date", header2="Host", header3="Image", header4="Company", header5="Command line", 
        hostroute='website.process_host_logs', selfroute='website.process_host_logs')
        
# File creation logs
@website.route('/files', methods=['GET'])
@require_login
def files():
    template = page_template('events.html', 'events_range.html')
    logs = paginated_logs(File)

    hosts = [x[0] for x in db.session.query(File.host).distinct()]

    return render_template(
            template, logs=logs, hosts=hosts,
            header1="Date", header2="Host", header3="Image", header4="File Name", header5="User",
            hostroute='website.files_host_logs', selfroute='website.files')

@website.route("/files/<host>", methods=["GET"])
@require_login
def files_host_logs(host): 
    template = page_template('events.html', 'events_range.html')
    logs = paginated_logs(File, host)

    hosts = [x[0] for x in db.session.query(File.host).distinct()]
    return render_template(
        template, logs=logs, hosts=hosts, currenthost = host,
        header1="Date", header2="Host", header3="Image", header4="File Name", header5="User",
        hostroute='website.files_host_logs', selfroute='website.files_host_logs')

# Network logs
@website.route('/net', methods=['GET'])
@require_login
def net():
    template = page_template('events.html', 'events_range.html')
    logs = paginated_logs(Network)

    hosts = [x[0] for x in db.session.query(Network.host).distinct()]
    return render_template(
            template, logs=logs, hosts=hosts,
            header1="Date", header2="Host", header3="Image", header4="Dest IP", header5="Dest Port", 
            hostroute='website.net_host_logs', selfroute='website.net')

@website.route("/net/<host>", methods=["GET"])
@require_login
def net_host_logs(host):
    template = page_template('events.html', 'events_range.html')
    logs = paginated_logs(Network, host)

    hosts = [x[0] for x in db.session.query(Network.host).distinct()]
    return render_template(
        template, logs=logs, hosts=hosts, currenthost = host,
        header1="Date", header2="Host", header3="Image", header4="Dest IP", header5="Dest Port", 
        hostroute='website.net_host_logs', selfroute='website.net_host_logs')

# Events
@website.route('/events', methods=['GET'])
@require_login
def events():
    template = page_template('events.html', 'events_range.html')
    logs = paginated_logs(Event)

    hosts = [x[0] for x in db.session.query(Event.host).distinct()]
    return render_template(
            template, logs=logs, hosts = hosts,
            header1="Date", header2="Host", header3="Image", header4="Event", header5="Details", 
            hostroute='website.events_host_logs', selfroute='website.events')

@website.route("/events/<host>", methods=["GET"])
@require_login
def events_host_logs(host):
    template = page_template('events.html', 'events_range.html')
    logs = paginated_logs(Event, host)

    hosts = [x[0] for x in db.session.query(Event.host).distinct()]
    return render_template(
        template, logs=logs, hosts=hosts, currenthost = host,
        header1="Date", header2="Host", header3="Image", header4="Event", header5="Details", 
        hostroute='website.events_host_logs', selfroute='website.events_host_logs')

# Alerts
@website.route('/alerts', methods=['GET'])
@require_login
def alerts():
    template = page_template('events.html', 'events_range.html')
    logs = paginated_logs(Alert, apply_false_positives=False)

    hosts = [x[0] for x in db.session.query(Alert.host).distinct()]
    return render_template(
            template, logs=logs, hosts=hosts,
            header1="Date", header2="Host", header3="Image", header4="Rule", header5="Details", 
            hostroute='website.host_alerts', selfroute='website.alerts')

@website.route("/alerts/<host>", methods=["GET"])
@require_login
def host_alerts(host):
    template = page_template('events.html', 'events_range.html')
    logs = paginated_logs(Alert, host, apply_false_positives=False)
    
    hosts = [x[0] for x in db.session.query(Alert.host).distinct()]
    return render_template(
        template, logs=logs, hosts=hosts, currenthost = host,
        header1="Date", header2="Host", header3="Image", header4="Rule", header5="Details", 
        hostroute='website.host_alerts', selfroute='website.host_alerts')

# Connection logs
@website.route('/connlogs', methods=['GET'])
@require_login
def conn_logs():
    template = page_template('conn_logs.html', 'conn_logs_range.html')
    logs = paginated_logs(ConnLog, apply_false_positives=False)

    hosts = [x[0] for x in db.session.query(ConnLog.host).distinct()]
    return render_template(
            template, logs=logs, hosts=hosts,
            header1="Date", header2="Host", header3="Type", 
            hostroute='website.host_conn_logs', selfroute='website.conn_logs')

@website.route("/connlogs/<host>", methods=["GET"])
@require_login
def host_conn_logs(host):
    template = page_template('conn_logs.html', 'conn_logs_range.html')
    logs = paginated_logs(ConnLog, host, apply_false_positives=False)
    
    hosts = [x[0] for x in db.session.query(ConnLog.host).distinct()]
    return render_template(
        template, logs=logs, hosts=hosts, currenthost = host,
        header1="Date", header2="Host", header3="Type", 
        hostroute='website.host_conn_logs', selfroute='website.conn_logs')

# False positives filter
@website.route("/false", methods=["GET"])
@require_login
def false_process():
    image  = request.args.get('image', None)
    send_to  = request.args.get('send_to', None)
    host  = request.args.get('host', None)
    selected_range = request.args.get('range', None)
    search = request.args.get('q', None)
    redirect_args = {}
    if selected_range:
        redirect_args['range'] = selected_range
    if search:
        redirect_args['q'] = search

    false_positives.append("%" + image.split('\\')[-1])
    if 'host' in send_to:
        return redirect(url_for(send_to, host=host, **redirect_args))
    return redirect(url_for(send_to.split('_')[0], **redirect_args))

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
    try:
        db.session.query(Alert).delete()
        db.session.commit()
        return redirect(url_for('website.alerts'))
    except Exception as e:
        db.session.rollback()
        print (f'Failed to clean alerts table. {str(e)}')
        return redirect(url_for('website.alerts'))
