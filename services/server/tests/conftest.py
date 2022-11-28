from werkzeug.security import generate_password_hash
import pytest

from database.models import User, db
from app import create_app

print("Conftest init")
@pytest.fixture(scope='module')
def new_user():    
    username = 'testuser'
    password = 'FlaskIsAwesome'
    user = User(username=username, password=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()
    return user

@pytest.fixture(scope='module')
def test_client():
    flask_app = create_app('flask.cfg')

    # Create a test client using the Flask application configured for testing
    with flask_app.test_client() as testing_client:
        print("test_client init")
        # Establish an application context
        with flask_app.app_context():
            yield testing_client  # this is where the testing happens!

@pytest.fixture(scope='module')
def init_database(test_client):
    print("init_database init")
    # Create the database and the database table
    # db.drop_all()
    # db.create_all()
    # db.session.commit()

    # Insert user data
    user1 = User(username='testuser1', password=generate_password_hash('FlaskIsAwesome1'), role='User')
    user2 = User(username='testadmin', password=generate_password_hash('FlaskIsAwesome2'), role='Admin')
    db.session.add(user1)
    db.session.add(user2)

    # Commit the changes for the users
    db.session.commit()

    yield  # this is where the testing happens!

    #db.drop_all()

@pytest.fixture(scope='function')
def login_default_user(test_client):
    test_client.post('/log_in',
        data=dict(username='testuser1', password='FlaskIsAwesome1'),
        follow_redirects=True)

    yield  # this is where the testing happens!

    test_client.get('/log_out', follow_redirects=True)

@pytest.fixture(scope='function')
def login_default_admin(test_client):
    test_client.post('/log_in',
        data=dict(username='testadmin', password='FlaskIsAwesome2'),
        follow_redirects=True)

    yield  # this is where the testing happens!

    test_client.get('/log_out', follow_redirects=True)