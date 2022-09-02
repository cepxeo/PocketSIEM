from datetime import datetime, timedelta

# Check all routes accessible by unauthenticated user
def test_urls_unauth(test_client):
    response = test_client.get('/')
    assert response.status_code == 302
    
    response = test_client.post('/')
    assert response.status_code == 405
    
    response = test_client.get('/log_in')
    assert response.status_code == 200

    response = test_client.get('/sign_up')
    assert response.status_code == 200

    response = test_client.get('/alerts')
    assert response.status_code == 302

    response = test_client.get('/events')
    assert response.status_code == 302

    response = test_client.get('/net')
    assert response.status_code == 302

    response = test_client.get('/processes')
    assert response.status_code == 302

    response = test_client.get('/logins')
    assert response.status_code == 302

    response = test_client.get('/notexisting')
    assert response.status_code == 404

# Initialize the DB, check the user is created
def test_new_user(test_client, init_database, new_user):

    assert new_user.role == 'User'
    assert new_user.username == 'testuser'

# Ensure incorrect password is declined
def test_login_incorrect(test_client):

    response = test_client.post('/log_in',
                     data=dict(username='testuser', password='incorrectpass'),
                     follow_redirects=True)

    assert response.status_code == 200
    assert b'incorrect' in response.data

# Correct credentials should work for login
def test_login_correct(test_client):

    response = test_client.post('/log_in',
                     data=dict(username='testuser', password='FlaskIsAwesome'),
                     follow_redirects=True)

    assert response.status_code == 200
    assert b'incorrect' not in response.data

# Check all routes accessible by authenticated user
def test_urls_auth_user(test_client, login_default_user):

    response = test_client.get('/alerts')
    assert response.status_code == 200

    response = test_client.get('/events')
    assert response.status_code == 200

    response = test_client.get('/net')
    assert response.status_code == 200

    response = test_client.get('/processes')
    assert response.status_code == 200

    response = test_client.get('/logins')
    assert response.status_code == 200

    response = test_client.get('/notexisting')
    assert response.status_code == 404


    response = test_client.get('/users')
    assert response.status_code == 200
    assert b'Access denied' in response.data
# User should not access next routes
    response = test_client.get('/token')
    assert response.status_code == 200
    assert b'Access denied' in response.data
   
# Admin should access next routes and see respective data
def test_urls_auth_admin(test_client, login_default_admin):

    response = test_client.get('/users')
    assert response.status_code == 200
    assert b'testadmin' in response.data

    response = test_client.get('/token')
    assert response.status_code == 200
    assert b'token' in response.data
    print(response.data)

# Check token
def test_token_healthcheck(test_client):

    response = test_client.get('/healthcheck')    
    assert response.status_code == 403
    assert b'Token is missing' in response.data

    response = test_client.get('/healthcheck', 
        headers={'x-access-tokens': 'invalidtoken'})
    assert response.status_code == 403
    assert b'Token is invalid' in response.data

    response = test_client.get('/healthcheck', 
    headers={'x-access-tokens': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwiZXhwIjoxNjY0MzA2MzkwfQ.3kOeOyD6HP3pj0wzWPV3wiO45j3j2Fq0MRWIAYVYDlo'})
    assert response.status_code == 200

# Send the process log, ensure it is accepted and visualized properly
# Check the alert is also raised
def test_send_logs(test_client, login_default_user):

    response = test_client.get('/processes')    
    assert response.status_code == 200
    assert b'VGAuthService' not in response.data

    response = test_client.get('/alerts')    
    assert response.status_code == 200
    assert b'VGAuthService' not in response.data
    
    response = test_client.post("/processes", data={
        "date": str(datetime.today() - timedelta(days=2)),
        "host": "TEST01",
        "image": "C:\Test\VGAuthService.exe",
        "company": "Microsoft Corporation",
        "command_line": "C:\Test\VGAuthService.exe ocdjjb.dll,bbb",    
        },headers={
        'x-access-tokens': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwiZXhwIjoxNjY0MzA2MzkwfQ.3kOeOyD6HP3pj0wzWPV3wiO45j3j2Fq0MRWIAYVYDlo'
        })
    assert response.status_code == 200

    response = test_client.get('/processes')    
    assert response.status_code == 200
    assert b'VGAuthService' in response.data

    response = test_client.get('/alerts')    
    assert response.status_code == 200
    assert b'VGAuthService' in response.data
    
# Date filter should reflect logs within set date range
# Default range is 7 days
def test_date_filter(test_client, login_default_user):

# 7 day filter doesn't show log created 9 days ago
    response = test_client.post("/processes", data={
        "date": str(datetime.today() - timedelta(days=8)),
        "host": "TEST01",
        "image": "C:\Test\TestCommand.exe",
        "company": "Microsoft Corporation",
        "command_line": "C:\Test\TestCommand.exe",    
        },headers={
        'x-access-tokens': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwiZXhwIjoxNjY0MzA2MzkwfQ.3kOeOyD6HP3pj0wzWPV3wiO45j3j2Fq0MRWIAYVYDlo'
        })
    assert response.status_code == 200

    response = test_client.get('/processes')    
    assert response.status_code == 200
    assert b'VGAuthService' in response.data
    assert b'TestCommand' not in response.data

# 1 day filter shows no records
    response = test_client.get("/processes", query_string={"range": "1"})
    assert response.status_code == 200

    assert b'VGAuthService' not in response.data
    assert b'TestCommand' not in response.data

# 30 days filter shows all records
    response = test_client.get("/processes", query_string={"range": "30"})
    assert response.status_code == 200

    assert b'VGAuthService' in response.data
    assert b'TestCommand' in response.data

# Host filter shows logs related to TEST01 logs, doesn't show to other
def test_host_filter(test_client, login_default_user):
    response = test_client.get('/processes/TEST01')    
    assert response.status_code == 200
    assert b'VGAuthService' in response.data
    assert b'TestCommand' not in response.data

    response = test_client.get('/processes/notexists')    
    assert response.status_code == 200
    assert b'VGAuthService' not in response.data
    assert b'TestCommand' not in response.data