from flask import Blueprint, current_app, request, jsonify, g, url_for, render_template, redirect, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import datetime
import jwt

from database.models import db, User

auth = Blueprint('auth', __name__)

@auth.before_request
def load_user():
    user_id = session.get('user_id')
    if user_id:
        g.user = User.query.get(user_id)
    else:
        g.user = None

def require_admin(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        user_id = session.get('user_id')
        if user_id:
            if g.user.role=="Admin":
                return view(**kwargs)
            return jsonify({'message': 'Access denied'})
        return redirect(url_for('auth.log_in'))
    return wrapped_view

# New users and access tokens creation by admin
# ----------------------------------------------------
@auth.route('/users', methods=['GET'])
@require_admin
def get_all_users(): 
   users = User.query.all()
   result = []  
   for user in users:  
       user_data = {}  
       user_data['id'] = user.id 
       user_data['name'] = user.username
       user_data['role'] = user.role
     
       result.append(user_data)  
   return jsonify({'users': result})

@auth.route('/token')
@require_admin
def get_auth_token():
    token = jwt.encode({'id' : g.user.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=45000)}, current_app.config['SECRET_KEY'], "HS256")
    return jsonify({'token' : token.decode('ascii')})

# User sign up
# ----------------------------------------------------

@auth.route('/sign_up', methods=('GET', 'POST'))
def sign_up():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        error = None
        if current_app.config['USER_SIGNUP'] == "False":
            error = 'User registration disabled.'
        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif User.query.filter_by(username=username).first():
            error = 'Username is already taken.'

        if error is None:
            user = User(username=username, password=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            flash("Successfully signed up! Please log in.", 'success')
            return redirect(url_for('auth.log_in'))

        flash(error, category='error')

    return render_template('sign_up.html')

@auth.route('/log_in', methods=('GET', 'POST'))
def log_in():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        error = None

        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password, password):
            error = 'Username or password are incorrect'

        if error is None:
            session.clear()
            session['user_id'] = user.id
            return redirect(url_for('website.alerts'))

        flash(error, category='error')
 
    return render_template('log_in.html')

@auth.route('/log_out', methods=('GET', 'DELETE'))
def log_out():
    session.clear()
    flash('Successfully logged out.', 'success')
    return redirect(url_for('auth.log_in'))