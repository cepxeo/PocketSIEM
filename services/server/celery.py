from app import create_app
from flask_celeryext import FlaskCeleryExt
from celery_utils import make_celery
import logging

logging.basicConfig(
        filename="pocketsiem.log",
        format='%(asctime)s:%(levelname)s:%(message)s', level=logging.INFO)

flask_app = create_app('flask_test.cfg')
ext_celery = FlaskCeleryExt(create_celery_app=make_celery)
ext_celery.init_app(flask_app)
celery = ext_celery.celery