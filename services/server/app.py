from flask import Flask
from werkzeug.security import generate_password_hash
from flask_celeryext import FlaskCeleryExt
from waitress import serve
import secrets
import string
import logging

from database.models import db, User
from celery_utils import make_celery

def create_app(config_filename=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_pyfile(config_filename)
    app.app_context().push()
    db.init_app(app)
    db.create_all()
    db.session.commit()
    register_blueprints(app)
    return app

def register_blueprints(app):
    from website.views import website
    from api.views import api
    from auth import auth

    app.register_blueprint(auth)
    app.register_blueprint(api)
    app.register_blueprint(website)

ext_celery = FlaskCeleryExt(create_celery_app=make_celery)
flask_app = create_app('flask.cfg')
ext_celery.init_app(flask_app)
celery = ext_celery.celery

if __name__ == '__main__':
    def _gen_admin() -> str:
        username = 'admin'        
        if User.query.filter_by(username=username).first() is not None:
            return False
        password = ''.join(secrets.choice(string.ascii_uppercase + string.ascii_lowercase) for i in range(17))
        user = User(username=username, password=generate_password_hash(password), role="Admin")
        db.session.add(user)
        db.session.commit()
        return password

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('waitress')
    logger.setLevel(logging.INFO)

    passw = _gen_admin()
    if passw:
        logger.info('admin user created with password: {passwd}'.format(passwd=passw))

    if flask_app.config['TESTING']:
        flask_app.run(host='0.0.0.0', port=8443, ssl_context=('cert.pem', 'key.pem'))
    else:
        serve(flask_app, host='0.0.0.0', port=5000, url_scheme='https')
    
