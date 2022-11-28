sudo rm -r /var/lib/docker/volumes/server_postgres_data_test/_data
sudo mkdir /var/lib/docker/volumes/server_postgres_data_test/_data
cd services/server
docker-compose up
