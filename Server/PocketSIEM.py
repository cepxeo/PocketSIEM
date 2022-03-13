from flask import Flask, request, send_file, jsonify, render_template_string
import db
import sigma_parse
from flask_cors import CORS
from glob import glob

evil_patterns_process = []
evil_patterns_process = sigma_parse.load_rules(evil_patterns_process, "sigma/rules/windows/process_creation")
app = Flask(__name__)
CORS(app)
database = r"sqlite.db"


# Logins logs
# ----------------------------------------------------
@app.route('/logins', methods=['POST'])
def insert_login_logs():
    conn = db.create_connection(database)
    date = request.form["date"]
    host = request.form["host"]
    user = request.form["user"]
    logon_type = request.form["logon_type"]
    db.insert_login_logs(conn, (date,host,user,logon_type))
    conn.commit()
    print("[+] Received logons from Host: %s" % host,)
    return ""

@app.route("/logins/hosts", methods=["GET"])
def get_all_login_hosts():
    conn = db.create_connection(database)
    logs = db.get_login_hosts(conn)
    return jsonify(logs)

@app.route("/logins/<host>", methods=["GET"])
def gett_login_host_logs(host):
    conn = db.create_connection(database)
    logs = db.get_login_host_logs(conn, (host,))
    #return jsonify(logs)
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
def gett_login_logs():
    conn = db.create_connection(database)
    logs = db.get_login_logs(conn)
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
def insert_process_logs():
    conn = db.create_connection(database)
    date = request.form["date"]
    host = request.form["host"]
    image = request.form["image"]
    company = request.form["company"]
    command_line = request.form["command_line"]
    alert = sigma_parse.check_log(evil_patterns_process, command_line)
    if alert:
        print("[!!] Alert triggered by the rule: %s" % alert)
        print("[!!] Malicious command: %s" % command_line)
    db.insert_proc_logs(conn, (date,host,image,company,command_line))
    conn.commit()
    print("[+] Received processes from Host: %s" % host,)
    return ""

@app.route("/processes/hosts", methods=["GET"])
def get_all_process_hosts():
    conn = db.create_connection(database)
    logs = db.get_proc_hosts(conn)
    return jsonify(logs)

@app.route("/processes/<host>", methods=["GET"])
def gett_process_host_logs(host):
    conn = db.create_connection(database)
    logs = db.get_process_host_logs(conn, (host,))
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
def gett_process_logs():
    conn = db.create_connection(database)
    logs = db.get_process_logs(conn)
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
def insert_net_logs():
    conn = db.create_connection(database)
    date = request.form["date"]
    host = request.form["host"]
    image = request.form["image"]
    dest_ip = request.form["dest_ip"]
    dest_port = request.form["dest_port"]
    db.insert_network_logs(conn, (date,host,image,dest_ip,dest_port))
    conn.commit()
    print("[+] Received network logs from Host: %s" % host,)
    return ""

@app.route("/net/hosts", methods=["GET"])
def get_all_net_hosts():
    conn = db.create_connection(database)
    logs = db.get_network_hosts(conn)
    return jsonify(logs)

@app.route("/net/<host>", methods=["GET"])
def gett_net_host_logs(host):
    conn = db.create_connection(database)
    logs = db.get_network_host_logs(conn, (host,))
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
def gett_net_logs():
    conn = db.create_connection(database)
    logs = db.get_network_logs(conn)
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
def insert_events_logs():
    conn = db.create_connection(database)
    date = request.form["date"]
    host = request.form["host"]
    event = request.form["event"]
    image = request.form["image"]    
    details = request.form["details"]
    db.insert_events_logs(conn, (date,host,event,image,details))
    conn.commit()
    print("[+] Received events from Host: %s" % host,)
    return ""

@app.route("/events/hosts", methods=["GET"])
def get_all_events_hosts():
    conn = db.create_connection(database)
    logs = db.get_events_hosts(conn)
    return jsonify(logs)

@app.route("/events/<host>", methods=["GET"])
def gett_events_host_logs(host):
    conn = db.create_connection(database)
    logs = db.get_events_host_logs(conn, (host,))
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
def gett_events_logs():
    conn = db.create_connection(database)
    logs = db.get_events_logs(conn)
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

app.run(host='0.0.0.0', port=443, ssl_context=('cert.pem', 'key.pem'))
