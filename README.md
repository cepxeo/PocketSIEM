### Windows event log collector and visualizer

Very simple implementation for home / CTF usage as an alternative to a full-blown ELK / winlogbeat etc setups.

Current functionality includes:

* Powershell agent parses successful and invalid logon attempts and some types of the Sysmon events (check collector.ps1 for details)
* Sends the data to the API over HTTPS
* API accepts logs via POST and visualise via GET based on the event type with the host filtering and appropriate date range

#### GET requests supported:

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
```

#### Setup

Client:

* Download [Sysmon](https://download.sysinternals.com/files/Sysmon.zip)
* Install `Sysmon64.exe -i sysmonconfig.xml`
* Amend the `$url` to your API server IP / Address in collector.ps1
* Create scheduled task to run periodically with the next command: `powershell C:\Your\Path\collector.ps1`. Tick "Run with highest privelieges" within the created task.

Server:

* Install required dependency `sudo pip3 install flask_cors`
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

* Start the server `sudo python3 PocketSIEM.py`