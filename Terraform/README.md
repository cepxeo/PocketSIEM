### Installing PocketSIEM on AWS with Terraform

* Ensure you have Terraform and awscli installed and configured
* Fill in terraform.tfvars variables with your registered domain name and the IP / subnet you will access the system from.
* Run the script

```
terraform init
terraform apply
```

Important!!! Follow the server creation process. Once the public IP is printed to the screen, update the DNS A Record in your domain DNS Management immediately. It will be used on the last build stage by the certbot during the SSL certificate registration.

SSH key `pocketsiem-key.pem` will be generated and saved in the current folder. Login to the new server and check the admin password:

```
ssh -i .\pocketsiem-key.pem ubuntu@YOUR_IP
docker logs $(docker ps -a -q --filter "ancestor=pocketsiem:1")
```