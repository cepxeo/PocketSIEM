import psycopg2
from flask import current_app

def create_connection():
    conn = None
    conn = psycopg2.connect(
        host=current_app.config['DB_HOST'],
        port=current_app.config['DB_PORT'],
        database=current_app.config['DB_NAME'],
        user=current_app.config['DB_USER'],
        password=current_app.config['DB_PASSWORD'])
    return conn

def create_db(conn):
    createloginlogsTable="""CREATE TABLE IF NOT EXISTS logs (
            id serial PRIMARY KEY,
            date timestamp NOT NULL,
            host text NOT NULL,
            osuser text NOT NULL,
            logon_type text NOT NULL,
            process_name text NOT NULL);"""
    createsysmonproclogsTable="""CREATE TABLE IF NOT EXISTS sysmon_process (
            id serial PRIMARY KEY,
            date timestamp NOT NULL,
            host text NOT NULL,
            image text NOT NULL,
            company text NOT NULL,
            command_line text NOT NULL);"""
    createsysmonfileslogsTable="""CREATE TABLE IF NOT EXISTS sysmon_files (
            id serial PRIMARY KEY,
            date timestamp NOT NULL,
            host text NOT NULL,
            event text NOT NULL,
            image text,
            details text NOT NULL);"""
    createsysmonnetlogsTable="""CREATE TABLE IF NOT EXISTS sysmon_network (
            id serial PRIMARY KEY,
            date timestamp NOT NULL,
            host text NOT NULL,
            image text NOT NULL,
            dest_ip text NOT NULL,
            dest_port text NOT NULL);"""
    createsysmoneventslogsTable="""CREATE TABLE IF NOT EXISTS sysmon_events (
            id serial PRIMARY KEY,
            date timestamp NOT NULL,
            host text NOT NULL,
            event text NOT NULL,
            image text,
            details text NOT NULL);"""
    createalertsTable="""CREATE TABLE IF NOT EXISTS alerts (
            id serial PRIMARY KEY,
            date timestamp NOT NULL,
            host text NOT NULL,
            image text,
            rule text,
            details text NOT NULL);"""
    createusersTable="""CREATE TABLE IF NOT EXISTS users (
            id serial PRIMARY KEY,
            username text NOT NULL,
            password text NOT NULL,
            role text);"""

    try:
        c = conn.cursor()
        c.execute(createloginlogsTable)
        c.execute(createsysmonproclogsTable)
        c.execute(createsysmonfileslogsTable)
        c.execute(createsysmonnetlogsTable)
        c.execute(createsysmoneventslogsTable)
        c.execute(createalertsTable)
        c.close()
        conn.commit()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    finally:
        if conn is not None:
            conn.close()

# Logging logins
def insert_login_logs(conn, logs):
    sql = ''' INSERT INTO logs(date,host,osuser,logon_type,process_name)
              VALUES(%s,%s,%s,%s,%s) '''
    cur = conn.cursor()
    cur.execute(sql, logs)
    return cur.lastrowid

def get_login_hosts(conn):
    sql = """SELECT DISTINCT host 
             FROM logs"""
    cur = conn.cursor()
    cur.execute(sql)
    rows = cur.fetchall()
    return rows

def get_login_host_logs(conn, host, range):
    sql = """SELECT DISTINCT date, host, osuser, logon_type, process_name
              FROM logs 
              WHERE host = %s and date >= NOW() - INTERVAL '{} DAY'
              ORDER BY date DESC
              """.format(range)
    cur = conn.cursor()
    cur.execute(sql, host)
    return cur.fetchall()

def get_login_logs(conn,range):
    sql = """SELECT DISTINCT date, host, osuser, logon_type, process_name
              FROM logs
              WHERE date >= NOW() - INTERVAL '{} DAY'
              ORDER BY date DESC
              """.format(range)
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()

# Logging process creations
def insert_proc_logs(conn, logs):
    sql = ''' INSERT INTO sysmon_process(date,host,image,company,command_line)
              VALUES(%s,%s,%s,%s,%s) '''
    cur = conn.cursor()
    cur.execute(sql, logs)
    return cur.lastrowid

def get_proc_hosts(conn):
    sql = """SELECT DISTINCT host 
             FROM sysmon_process"""
    cur = conn.cursor()
    cur.execute(sql)
    rows = cur.fetchall()
    return rows

def get_process_host_logs(conn, host, range):   
    sql = """SELECT DISTINCT date,host,image,company,command_line
              FROM sysmon_process 
              WHERE host = %s and date >= NOW() - INTERVAL '{} DAY'
              ORDER BY date DESC
              """.format(range)
    cur = conn.cursor()
    cur.execute(sql, host)
    return cur.fetchall()

def get_process_logs(conn, range):
    sql = """SELECT DISTINCT date,host,image,company,command_line
              FROM sysmon_process
              WHERE date >= NOW() - INTERVAL '{} DAY'
              ORDER BY date DESC
              """.format(range)
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()

# Logging file creation
def insert_files_logs(conn, logs):
    sql = ''' INSERT INTO sysmon_files(date,host,event,image,details)
              VALUES(%s,%s,%s,%s,%s) '''
    cur = conn.cursor()
    cur.execute(sql, logs)
    return cur.lastrowid

def get_files_hosts(conn):
    sql = """SELECT DISTINCT host 
             FROM sysmon_files"""
    cur = conn.cursor()
    cur.execute(sql)
    rows = cur.fetchall()
    return rows

def get_files_host_logs(conn, host, range):
    sql = """SELECT DISTINCT date,host,event,image,details
              FROM sysmon_files 
              WHERE host = %s and date >= NOW() - INTERVAL '{} DAY'
              ORDER BY date DESC
              """.format(range)
    cur = conn.cursor()
    cur.execute(sql, host)
    return cur.fetchall()

def get_files_logs(conn,range):
    sql = """SELECT DISTINCT date,host,event,image,details
              FROM sysmon_files
              WHERE date >= NOW() - INTERVAL '{} DAY'
              ORDER BY date DESC
              """.format(range)
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()

# Logging network connections
def insert_network_logs(conn, logs):
    sql = ''' INSERT INTO sysmon_network(date,host,image,dest_ip,dest_port)
              VALUES(%s,%s,%s,%s,%s) '''
    cur = conn.cursor()
    cur.execute(sql, logs)
    return cur.lastrowid

def get_network_hosts(conn):
    sql = """SELECT DISTINCT host 
             FROM sysmon_network"""
    cur = conn.cursor()
    cur.execute(sql)
    rows = cur.fetchall()
    return rows

def get_network_host_logs(conn, host, range):
    sql = """SELECT DISTINCT date,host,image,dest_ip,dest_port
              FROM sysmon_network 
              WHERE host = %s and date >= NOW() - INTERVAL '{} DAY'
              ORDER BY date DESC
              """.format(range)
    cur = conn.cursor()
    cur.execute(sql, host)
    return cur.fetchall()

def get_network_logs(conn,range):
    sql = """SELECT DISTINCT date,host,image,dest_ip,dest_port
              FROM sysmon_network
              WHERE date >= NOW() - INTERVAL '{} DAY'
              ORDER BY date DESC
              """.format(range)
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()

# Logging events
def insert_events_logs(conn, logs):
    sql = ''' INSERT INTO sysmon_events(date,host,event,image,details)
              VALUES(%s,%s,%s,%s,%s) '''
    cur = conn.cursor()
    cur.execute(sql, logs)
    return cur.lastrowid

def get_events_hosts(conn):
    sql = """SELECT DISTINCT host 
             FROM sysmon_events"""
    cur = conn.cursor()
    cur.execute(sql)
    rows = cur.fetchall()
    return rows

def get_events_host_logs(conn, host, range):
    sql = """SELECT DISTINCT date,host,event,image,details
              FROM sysmon_events 
              WHERE host = %s and date >= NOW() - INTERVAL '{} DAY'
              ORDER BY date DESC
              """.format(range)
    cur = conn.cursor()
    cur.execute(sql, host)
    return cur.fetchall()

def get_events_logs(conn,range):
    sql = """SELECT DISTINCT date,host,event,image,details
              FROM sysmon_events
              WHERE date >= NOW() - INTERVAL '{} DAY'
              ORDER BY date DESC
              """.format(range)
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()

# Managing alerts
def insert_alerts(conn, alerts):
    sql = ''' INSERT INTO alerts(date,host,image,rule,details)
              VALUES(%s,%s,%s,%s,%s) '''
    cur = conn.cursor()
    cur.execute(sql, alerts)
    return cur.lastrowid

def get_alerts_hosts(conn):
    sql = """SELECT DISTINCT host 
             FROM alerts"""
    cur = conn.cursor()
    cur.execute(sql)
    rows = cur.fetchall()
    return rows

def get_host_alerts(conn, host, range):
    sql = """SELECT DISTINCT date,host,image,rule,details
              FROM alerts 
              WHERE host = %s and date >= NOW() - INTERVAL '{} DAY'
              ORDER BY date DESC
              """.format(range)
    cur = conn.cursor()
    cur.execute(sql, host)
    return cur.fetchall()

def get_alerts(conn,range):
    sql = """SELECT DISTINCT date,host,image,rule,details
              FROM alerts
              WHERE date >= NOW() - INTERVAL '{} DAY'
              ORDER BY date DESC
              """.format(range)
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()