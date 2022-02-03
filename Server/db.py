import sqlite3
import argparse
import os

def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Error as e:
        print(e)
    return conn

def create_db(conn):
    createloginlogsTable="""CREATE TABLE IF NOT EXISTS logs (
            id integer PRIMARY KEY,
            date text NOT NULL,
            host text NOT NULL,
            user text NOT NULL,
            logon_type text NOT NULL);"""
    createsysmonproclogsTable="""CREATE TABLE IF NOT EXISTS sysmon_process (
            id integer PRIMARY KEY,
            date text NOT NULL,
            host text NOT NULL,
            image text NOT NULL,
            company text NOT NULL,
            command_line text NOT NULL);"""
    createsysmonnetlogsTable="""CREATE TABLE IF NOT EXISTS sysmon_network (
            id integer PRIMARY KEY,
            date text NOT NULL,
            host text NOT NULL,
            image text NOT NULL,
            dest_ip NOT NULL,
            dest_port text NOT NULL);"""
    createsysmoneventslogsTable="""CREATE TABLE IF NOT EXISTS sysmon_events (
            id integer PRIMARY KEY,
            date text NOT NULL,
            host text NOT NULL,
            event text NOT NULL,
            image,
            details text NOT NULL);"""
    try:
        c = conn.cursor()
        c.execute(createloginlogsTable)
        c.execute(createsysmonproclogsTable)
        c.execute(createsysmonnetlogsTable)
        c.execute(createsysmoneventslogsTable)
    except Error as e:
        print(e)

# Logging logins
def insert_login_logs(conn, logs):
    sql = ''' INSERT INTO logs(date,host,user,logon_type)
              VALUES(?,?,?,?) '''
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

def get_login_host_logs(conn, host):
    sql = """SELECT DISTINCT date, host, user, logon_type
              FROM logs 
              WHERE host = ? AND date BETWEEN datetime('now', '-7 days') AND datetime('now', '+2 days')
              ORDER BY date DESC
              """
    cur = conn.cursor()
    cur.execute(sql, host)
    return cur.fetchall()

def get_login_logs(conn):
    sql = """SELECT DISTINCT date, host, user, logon_type
              FROM logs
              WHERE date BETWEEN datetime('now', 'start of day') AND datetime('now', '+2 days')
              ORDER BY date DESC
              """
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()

# Logging process creations
def insert_proc_logs(conn, logs):
    sql = ''' INSERT INTO sysmon_process(date,host,image,company,command_line)
              VALUES(?,?,?,?,?) '''
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

def get_process_host_logs(conn, host):
    sql = """SELECT DISTINCT date,host,image,company,command_line
              FROM sysmon_process 
              WHERE host = ? AND date BETWEEN datetime('now', '-7 days') AND datetime('now', '+2 days')
              group by command_line having count(command_line) < 10
              ORDER BY date DESC
              """
    cur = conn.cursor()
    cur.execute(sql, host)
    return cur.fetchall()

def get_process_logs(conn):
    sql = """SELECT DISTINCT date,host,image,company,command_line
              FROM sysmon_process 
              WHERE date BETWEEN datetime('now', 'start of day') AND datetime('now', '+2 days')
              group by command_line having count(command_line) < 10
              ORDER BY date DESC
              """
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()

# Logging network connections
def insert_network_logs(conn, logs):
    sql = ''' INSERT INTO sysmon_network(date,host,image,dest_ip,dest_port)
              VALUES(?,?,?,?,?) '''
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

def get_network_host_logs(conn, host):
    sql = """SELECT DISTINCT date,host,image,dest_ip,dest_port
              FROM sysmon_network 
              WHERE host = ? AND date BETWEEN datetime('now', '-7 days') AND datetime('now', '+2 days')
              ORDER BY date DESC
              """
    cur = conn.cursor()
    cur.execute(sql, host)
    return cur.fetchall()

def get_network_logs(conn):
    sql = """SELECT DISTINCT date,host,image,dest_ip,dest_port
              FROM sysmon_network
              WHERE date BETWEEN datetime('now', 'start of day') AND datetime('now', '+2 days')
              ORDER BY date DESC
              """
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()

# Logging events
def insert_events_logs(conn, logs):
    sql = ''' INSERT INTO sysmon_events(date,host,event,image,details)
              VALUES(?,?,?,?,?) '''
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

def get_events_host_logs(conn, host):
    sql = """SELECT DISTINCT date,host,event,image,details
              FROM sysmon_events 
              WHERE host = ? AND date BETWEEN datetime('now', '-7 days') AND datetime('now', '+2 days')
              ORDER BY date DESC
              """
    cur = conn.cursor()
    cur.execute(sql, host)
    return cur.fetchall()

def get_events_logs(conn):
    sql = """SELECT DISTINCT date,host,event,image,details
              FROM sysmon_events
              group by details having count(details) < 10
              ORDER BY date DESC
              """
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()

if __name__ == "__main__":
    database = r"sqlite.db"
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--create','-c', help='Create Database', action='store_true')
    group.add_argument('--insert','-i', help='Insert logs', action='store_true')
    group.add_argument('--get','-g', help='Get logs', action='store_true')
    group.add_argument('--getHosts','-l', help='Get all Hosts', action='store_true')

    parser.add_argument('--host','-L')
    parser.add_argument('--logs','-C')
    args = parser.parse_args()

    conn = create_connection(database)

    if (args.create):
        print("[+] Creating Database")
        create_db(conn)
    elif (args.insert):
        if(args.host is None and args.logs is None):
            parser.error("--insert requires --host, --logs.")
        else:
            print("[+] Inserting Data")
            insert_logs(conn, (args.host, args.logs))
            conn.commit()
    elif (args.get):
        if(args.host is None):
            parser.error("--get requires --host, --logs.")
        else:
            print("[+] Getting logs")
            print(get_logs(conn, (args.host,)))
    if (args.getHosts):
        print("[+] Getting All Hosts")
        print(get_hosts(conn))