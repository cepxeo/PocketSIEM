## Windows event log collector and visualizer

Very simple implementation for research / CTF usage as an alternative to a full blown ELK / winlogbeat etc setups. The main purpose of the tool is to evaluate the optimal logs volume and malicious patterns sufficient to detect common TTPs, which is often the problem of full size SIEM.

Current functionality includes:

* Powershell agent parses successful and invalid logon attempts and Sysmon events (check collector.ps1 for details).
* Sends the data to the API over HTTPS.
* API accepts logs via POST and visualizes via GET based on the event type with the host filtering and appropriate date range.
* Created process logs are checked against known evil patterns and an alert is generated on match.
* HTTP Basic and JWT authentication methods are used to access the endpoints

### GET requests supported:

```
/logins
/logins/hosts
/logins/<host>

/processes
/processes/hosts
/processes/<host>

/net
/net/host
/net/<host>

/events
/events/hosts
/events/<host>

/alerts
/alerts/hosts
/alerts/<host>
```

### Setup

#### Server:

* Install required dependencies `sudo pip3 install -r requirements.txt`
* Create the DB `python3 db.py --create`
* Obtain the server SSL key / certificate pair. I use certbot with registered domain for that.

```
sudo snap install certbot --classic
sudo certbot certonly --register-unsafely-without-email --agree-tos -d mydomain.com
```

For testing purposes, it is possible to use own generated certificate. In this case you need to update the `collector.ps1` to accept untrusted certificates [hint](https://stackoverflow.com/questions/11696944/powershell-v3-invoke-webrequest-https-error).

To generate the self-signed pair:

```
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```

* Start the server `sudo python3 PocketSIEM.py` Take a note of `admin` password.
* Create the new user: 

`curl -u admin:YOURPASSWORD -i -X POST -H "Content-Type: application/json" -d '{"username":"test","password":"randompassword"}' https://127.0.0.1/users -k`
* JWT is supported, but not required. To generate:

`curl -u test:randompassword -i -X GET  https://127.0.0.1/token -k`

#### Client:

* Download [Sysmon](https://download.sysinternals.com/files/Sysmon.zip)
* Install `Sysmon64.exe -i Client\sysmonconfig.xml`
* Amend the `$url` to your API server IP / Address in Client\collector.ps1
* Fill in the $user / $passw variables with your created user credentials.
* If JWT is used, it goes in the $user field, password doesn't matter.
* Create scheduled task to periodically run Client\collector.ps1. Tick "Run with highest privileges" within the created task.