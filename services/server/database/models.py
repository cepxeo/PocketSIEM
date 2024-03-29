from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False, server_default='')
    role = db.Column(db.String(255), nullable=False, server_default='User')

class Login(db.Model):
    __tablename__ = 'logins'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime)
    host = db.Column(db.String(200))
    image = db.Column(db.Text)
    field4 = db.Column(db.Text)
    field5 = db.Column(db.Text)

class Process(db.Model):
    __tablename__ = 'sysmon_process'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime)
    host = db.Column(db.String(200))
    image = db.Column(db.Text)
    field4 = db.Column(db.Text)
    field5 = db.Column(db.Text)
    parent_image = db.Column(db.Text)
    parent_command_line = db.Column(db.Text)
    description = db.Column(db.Text)
    product = db.Column(db.Text)
    original_file_name = db.Column(db.Text)
    process_user = db.Column(db.Text)

class File(db.Model):
    __tablename__ = 'sysmon_files'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime)
    host = db.Column(db.String(200))
    image = db.Column(db.Text)
    field4 = db.Column(db.Text)
    field5 = db.Column(db.Text)

class Network(db.Model):
    __tablename__ = 'sysmon_network'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime)
    host = db.Column(db.String(200))
    image = db.Column(db.Text)
    field4 = db.Column(db.Text)
    field5 = db.Column(db.Text)

class Event(db.Model):
    __tablename__ = 'sysmon_events'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime)
    host = db.Column(db.String(200))
    image = db.Column(db.Text)
    field4 = db.Column(db.Text)
    field5 = db.Column(db.Text)

class Alert(db.Model):
    __tablename__ = 'alerts'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime)
    host = db.Column(db.String(200))
    image = db.Column(db.Text)
    field4 = db.Column(db.Text)
    field5 = db.Column(db.Text)

class Filter(db.Model):
    __tablename__ = 'false_filter'
    id = db.Column(db.Integer, primary_key=True)
    item = db.Column(db.Text)

class ConnLog(db.Model):
    __tablename__ = 'conn_logs'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime)
    host = db.Column(db.String(200))
    log_type = db.Column(db.String(50))