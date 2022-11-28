cd services/server
docker-compose up -d
sleep 5
docker-compose logs web
# python3 -m pytest -v  --disable-warnings
docker-compose down
cd ../..
