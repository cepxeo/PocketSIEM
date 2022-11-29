openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
cd services/server
docker-compose up
sudo rm -r /var/lib/docker/volumes/server_postgres_data_test
sudo mkdir -p /var/lib/docker/volumes/server_postgres_data_test/_data