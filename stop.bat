@echo off
cd /d %~dp0
echo Stopping and removing all containers...
docker-compose down
echo Done!
pause
