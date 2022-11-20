## Windows security events monitoring and alerting

 The SIEM (security information and event management) implementation for research / CTF usage as an alternative to a full blown ELK / winlogbeat etc setups. The main purpose of the tool is to evaluate the optimal logs volume and malicious patterns sufficient to detect common TTPs, which is often the problem of full size SIEM.

Current functionality includes:

* Powershell agent parses logon attempts and Sysmon events (check Client/collector.ps1 for details).
* Sends logs to the API over HTTPS with JWT authentication.
* Nice web application to work with received logs, grouped by the event type with the host filtering and appropriate date range.
* User sign up and log in possible to view the logs.

![](img/network-logs.png)

* Incoming logs are checked against known evil patterns and an alert is generated on match.
* Over 1500 Sigma and custom rules currently implemented. Check Tweaking alerts section.

![](img/alerts.png)

* Log records could be added to or excluded from the false positives filter. Just click on the unwanted binary, user or destination IP.

![](img/false-positives.png)

### Server setup

#### Generate SSL keys

* Obtain the server SSL key / certificate pair. I use certbot with registered domain for that.

```
sudo snap install certbot --classic
sudo certbot certonly --register-unsafely-without-email --agree-tos -d mydomain.com
```

For testing purposes, it is possible to use own generated certificate. In this case you need to update the `collector.ps1` to accept untrusted certificates [hint](https://stackoverflow.com/questions/11696944/powershell-v3-invoke-webrequest-https-error).

To generate the self-signed pair:

```
cd PockerSIEM/services/nginx/certs
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```

#### Setup server with Docker

* Ensure SSL keys and certificates are in services/nginx/certs folder. If certs were generated with certbot, just run the following commands providing your domain name:

```
export MYDOMAIN=mydomain.com
sudo cp /etc/letsencrypt/live/$MYDOMAIN/privkey.pem services/nginx/certs/key.pem
sudo cp /etc/letsencrypt/live/$MYDOMAIN/fullchain.pem services/nginx/certs/cert.pem
```

* Run docker-compose:

```
sudo docker-compose up -d
```

* View the logs to get the admin password:

```
docker-compose logs | grep "password"
```

* Login with admin and obtain JWT by visiting `/token`

### Client setup:

* Download [Sysmon](https://download.sysinternals.com/files/Sysmon.zip)
* Install `Sysmon64.exe -i Client\sysmonconfig.xml`
* Amend the `$url` to your API server IP / Address in Client\collector.ps1
* Fill in the generated JWT value.
* Create scheduled task to periodically run Client\collector.ps1. Tick "Run with highest privileges" within the created task.

### Tweaking alerts:

Several rule files are maintained by the project. The simple rules list stored here `services/server/detect/rules/rules_simple.txt` aiming to detect malicious patterns in the process command line, created files, registry modifications and other log details fields. 

Feel free to add or remove patterns. Star `*` means both strings should be in the log details to raise an alert. `%` is an antipattern to exclude. Example:

```
- '.exe*.dll,%rundll32'
```

Here if any `.exe` file is executed with `.dll,` pattern in the parameters, the alert will be raised, unless the executable is `rundll32` In this example we are catching the technique when dlls are executed with renamed rundll32.