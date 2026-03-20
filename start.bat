@echo off
cd /d %~dp0
echo Building images...
docker-compose build

echo Starting all services...
docker-compose up -d

echo Starting clients in separate windows...
start "Alice" cmd /k "docker-compose exec client_alice python client.py --resolver-ip 10.0.0.9 --resolver 9999 --name Alice"
start "Bob" cmd /k "docker-compose exec client_bob python client.py --resolver-ip 10.0.0.10 --resolver 9998 --name Bob"

pause
