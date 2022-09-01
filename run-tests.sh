cd services/server
docker-compose up -d
sleep 5
python3 -m pytest -v  --disable-warnings
docker-compose down
cd ../..
