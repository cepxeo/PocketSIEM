openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
sudo rm -r /var/lib/docker/volumes/server_postgres_data_test
sudo mkdir -p /var/lib/docker/volumes/server_postgres_data_test/_data
docker-compose up