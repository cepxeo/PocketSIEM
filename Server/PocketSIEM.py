from flask import Flask, request, jsonify, render_template_string, abort, g, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from flask_cors import CORS
import sigma_parse
import time
import dbs
import secrets
import string
import jwt


evil_patterns_process = []
evil_patterns_process = sigma_parse.load_rules(evil_patterns_process, "rules")
print ("[+] Loaded " + str(len(evil_patterns_process)) + " evil commands patterns.")

app = Flask(__name__)
CORS(app)
database = r"sqlite.db"

app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sqlite.db'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

db = SQLAlchemy(app)
auth = HTTPBasicAuth()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(128))

    def hash_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_auth_token(self, expires_in=6000000):
        return jwt.encode(
            {'id': self.id, 'exp': time.time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],
                              algorithms=['HS256'])
        except:
            return
        return User.query.get(data['id'])

@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

@auth.get_user_roles
def get_user_roles(user):
    if user['username'] == 'admin':
        return 'admin'
    return 'user'

@app.route('/users', methods=['POST'])
@auth.login_required(role=['admin'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        return "Username or password missing"
    if User.query.filter_by(username=username).first() is not None:
        return "Username " + user.username + " already exists"
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username}), 201,
            {'Location': url_for('get_user', id=user.id, _external=True)})


@app.route('/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/check')
def get_check():
    return "OK"

# Logins logs
# ----------------------------------------------------
@app.route('/logins', methods=['POST'])
@auth.login_required
def insert_login_logs():
    conn = dbs.create_connection(database)
    date = request.form["date"]
    host = request.form["host"]
    user = request.form["user"]
    logon_type = request.form["logon_type"]
    dbs.insert_login_logs(conn, (date,host,user,logon_type))
    conn.commit()
    #print("[+] Received logons from Host: %s" % host,)
    return ""

@app.route("/logins/hosts", methods=["GET"])
@auth.login_required
def get_all_login_hosts():
    conn = dbs.create_connection(database)
    logs = dbs.get_login_hosts(conn)
    return jsonify(logs)

@app.route("/logins/<host>", methods=["GET"])
@auth.login_required
def gett_login_host_logs(host):
    conn = dbs.create_connection(database)
    logs = dbs.get_login_host_logs(conn, (host,))
    return render_template_string('''

    <h4>Last 8 days</h4>
    <table>
            <tr>
                <td> Date </td> 
                <td> Host </td>
                <td> User </td>
                <td> Logon_Type </td>
            </tr>


    {% for date, host, user, logon_type in logs %}

            <tr>
                <td>{{ date }}</td> 
                <td>{{ host }}</td>
                <td>{{ user }}</td> 
                <td>{{ logon_type }}</td> 
            </tr>

    {% endfor %}


    </table>
''', logs=logs)

@app.route("/logins", methods=["GET"])
@auth.login_required
def gett_login_logs():
    conn = dbs.create_connection(database)
    logs = dbs.get_login_logs(conn)
    return render_template_string('''

    <h4>Today</h4>
    <table>
            <tr>
                <td> Date </td> 
                <td> Host </td>
                <td> User </td>
                <td> Logon_Type </td>
            </tr>


    {% for date, host, user, logon_type in logs %}

            <tr>
                <td>{{ date }}</td> 
                <td>{{ host }}</td>
                <td>{{ user }}</td> 
                <td>{{ logon_type }}</td> 
            </tr>

    {% endfor %}


    </table>
''', logs=logs)


# Process creation logs
# ----------------------------------------------------
@app.route('/processes', methods=['POST'])
@auth.login_required
def insert_process_logs():
    conn = dbs.create_connection(database)
    date = request.form["date"]
    host = request.form["host"]
    image = request.form["image"]
    company = request.form["company"]
    command_line = request.form["command_line"]
    alert = sigma_parse.check_log(evil_patterns_process, command_line)
    if alert:
        dbs.insert_alerts(conn, (date,host,image,alert,command_line))
        print("[!!] Alert triggered by the rule: %s" % alert)
        print("[!!] Malicious command: %s" % command_line)
    dbs.insert_proc_logs(conn, (date,host,image,company,command_line))
    conn.commit()
    #print("[+] Received processes from Host: %s" % host,)
    return ""

@app.route("/processes/hosts", methods=["GET"])
@auth.login_required
def get_all_process_hosts():
    conn = dbs.create_connection(database)
    logs = dbs.get_proc_hosts(conn)
    return jsonify(logs)

@app.route("/processes/<host>", methods=["GET"])
@auth.login_required
def gett_process_host_logs(host):
    conn = dbs.create_connection(database)
    logs = dbs.get_process_host_logs(conn, (host,))
    #return jsonify(logs)
    return render_template_string('''

    <h4>Last 8 days</h4>
    <table>
            <tr>
                <td> Date </td> 
                <td> Host </td>
                <td> Image </td>
                <td> Company </td>
                <td> Command line </td>
            </tr>


    {% for date, host, image, company, command_line in logs %}

            <tr>
                <td>{{ date }}</td> 
                <td>{{ host }}</td>
                <td>{{ image }}</td> 
                <td>{{ company }}</td> 
                <td>{{ command_line }}</td> 
            </tr>

    {% endfor %}


    </table>
''', logs=logs)

@app.route("/processes", methods=["GET"])
@auth.login_required
def gett_process_logs():
    conn = dbs.create_connection(database)
    logs = dbs.get_process_logs(conn)
    return render_template_string('''

<h4>Today</h4>
    <table>
            <tr>
                <td> Date </td> 
                <td> Host </td>
                <td> Image </td>
                <td> Company </td>
                <td> Command line </td>
            </tr>


    {% for date, host, image, company, command_line in logs %}

            <tr>
                <td>{{ date }}</td> 
                <td>{{ host }}</td>
                <td>{{ image }}</td> 
                <td>{{ company }}</td> 
                <td>{{ command_line }}</td> 
            </tr>

    {% endfor %}


    </table>
''', logs=logs)

# Network logs
# ----------------------------------------------------
@app.route('/net', methods=['POST'])
@auth.login_required
def insert_net_logs():
    conn = dbs.create_connection(database)
    date = request.form["date"]
    host = request.form["host"]
    image = request.form["image"]
    dest_ip = request.form["dest_ip"]
    dest_port = request.form["dest_port"]
    dbs.insert_network_logs(conn, (date,host,image,dest_ip,dest_port))
    conn.commit()
    #print("[+] Received network logs from Host: %s" % host,)
    return ""

@app.route("/net/hosts", methods=["GET"])
@auth.login_required
def get_all_net_hosts():
    conn = dbs.create_connection(database)
    logs = dbs.get_network_hosts(conn)
    return jsonify(logs)

@app.route("/net/<host>", methods=["GET"])
@auth.login_required
def gett_net_host_logs(host):
    conn = dbs.create_connection(database)
    logs = dbs.get_network_host_logs(conn, (host,))
    #return jsonify(logs)
    return render_template_string('''
    <h4>Last 8 days</h4>
    <table>
            <tr>
                <td> Date </td> 
                <td> Host </td>
                <td> Image </td>
                <td> Dest IP </td>
                <td> Dest Port </td>
            </tr>

    {% for date, host, image, dest_ip, dest_port in logs %}

            <tr>
                <td>{{ date }}</td> 
                <td>{{ host }}</td>
                <td>{{ image }}</td> 
                <td>{{ dest_ip }}</td> 
                <td>{{ dest_port }}</td> 
            </tr>

    {% endfor %}

    </table>
''', logs=logs)

@app.route("/net", methods=["GET"])
@auth.login_required
def gett_net_logs():
    conn = dbs.create_connection(database)
    logs = dbs.get_network_logs(conn)
    return render_template_string('''
    <h4>Today</h4>
    <table>
            <tr>
                <td> Date </td> 
                <td> Host </td>
                <td> Image </td>
                <td> Dest IP </td>
                <td> Dest Port </td>
            </tr>

    {% for date, host, image, dest_ip, dest_port in logs %}

            <tr>
                <td>{{ date }}</td> 
                <td>{{ host }}</td>
                <td>{{ image }}</td> 
                <td>{{ dest_ip }}</td> 
                <td>{{ dest_port }}</td> 
            </tr>

    {% endfor %}

    </table>
''', logs=logs)

# Events
# ----------------------------------------------------
@app.route('/events', methods=['POST'])
@auth.login_required
def insert_events_logs():
    conn = dbs.create_connection(database)
    date = request.form["date"]
    host = request.form["host"]
    event = request.form["event"]
    image = request.form["image"]    
    details = request.form["details"]
    dbs.insert_events_logs(conn, (date,host,event,image,details))
    conn.commit()
    #print("[+] Received events from Host: %s" % host,)
    return ""

@app.route("/events/hosts", methods=["GET"])
@auth.login_required
def get_all_events_hosts():
    conn = dbs.create_connection(database)
    logs = dbs.get_events_hosts(conn)
    return jsonify(logs)

@app.route("/events/<host>", methods=["GET"])
@auth.login_required
def gett_events_host_logs(host):
    conn = dbs.create_connection(database)
    logs = dbs.get_events_host_logs(conn, (host,))
    #return jsonify(logs)
    return render_template_string('''
    <h4>Last 8 days</h4>
    <table>
            <tr>
                <td> Date </td> 
                <td> Host </td>
                <td> Event </td>
                <td> Image </td>
                <td> Details </td>
            </tr>

    {% for date, host, event, image, details in logs %}

            <tr>
                <td>{{ date }}</td> 
                <td>{{ host }}</td>
                <td>{{ event }}</td> 
                <td>{{ image }}</td> 
                <td>{{ details }}</td> 
            </tr>

    {% endfor %}

    </table>
''', logs=logs)

@app.route("/events", methods=["GET"])
@auth.login_required
def gett_events_logs():
    conn = dbs.create_connection(database)
    logs = dbs.get_events_logs(conn)
    return render_template_string('''

    <table>
            <tr>
                <td> Date </td> 
                <td> Host </td>
                <td> Event </td>
                <td> Image </td>
                <td> Details </td>
            </tr>

    {% for date, host, event, image, details in logs %}

            <tr>
                <td>{{ date }}</td> 
                <td>{{ host }}</td>
                <td>{{ event }}</td> 
                <td>{{ image }}</td> 
                <td>{{ details }}</td> 
            </tr>

    {% endfor %}

    </table>
''', logs=logs)


# Alerts
# ----------------------------------------------------
@app.route("/alerts/hosts", methods=["GET"])
@auth.login_required
def gett_alerts_hosts():
    conn = dbs.create_connection(database)
    logs = dbs.get_alerts_hosts(conn)
    return jsonify(logs)

@app.route("/alerts/<host>", methods=["GET"])
@auth.login_required
def gett_host_alerts(host):
    conn = dbs.create_connection(database)
    logs = dbs.get_host_alerts(conn, (host,))
    return render_template_string('''
    <h4>Last 8 days</h4>
    <table>
            <tr>
                <td> Date </td> 
                <td> Host </td>
                <td> Image </td>
                <td> Rule </td>
                <td> Details </td>
            </tr>

    {% for date, host, image, rule, details in logs %}

            <tr>
                <td>{{ date }}</td> 
                <td>{{ host }}</td>
                <td>{{ image }}</td> 
                <td>{{ rule }}</td> 
                <td>{{ details }}</td> 
            </tr>

    {% endfor %}

    </table>
''', logs=logs)

@app.route("/alerts", methods=["GET"])
@auth.login_required
def gett_alerts():
    conn = dbs.create_connection(database)
    logs = dbs.get_alerts(conn)
    return render_template_string('''

    <table>
            <tr>
                <td> Date </td> 
                <td> Host </td>
                <td> Image </td>
                <td> Rule </td>
                <td> Details </td>
            </tr>

    {% for date, host, image, rule, details in logs %}

            <tr>
                <td>{{ date }}</td> 
                <td>{{ host }}</td>
                <td>{{ image }}</td> 
                <td>{{ rule }}</td> 
                <td>{{ details }}</td> 
            </tr>

    {% endfor %}

    </table>
''', logs=logs)

if __name__ == '__main__':

    def gen_admin(passw):
        username = 'admin'
        password = passw
        if User.query.filter_by(username=username).first() is not None:
            return False
        user = User(username=username)
        user.hash_password(password)
        db.session.add(user)
        db.session.commit()
        return True

    passw = ''.join(secrets.choice(string.ascii_uppercase + string.ascii_lowercase) for i in range(17))

    if gen_admin(passw):
        print ('''

        *****

        [+] admin user created with password: {passwd}

        *****

        '''.format(passwd=passw))

app.run(host='0.0.0.0', port=443, ssl_context=('cert.pem', 'key.pem'))
