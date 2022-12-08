# download
echo Downloading updated web.py file
sudo wget https://raw.githubusercontent.com/drewmiranda-gl/gl-lookups/main/src/web.py -O /opt/graylog/lookup-service/web.py

echo Restarting gl_lookup.service
sudo systemctl restart gl_lookup.service

echo Waiting 60 seconds for service to restart
sleep 60

echo Restarting gl_lookup2.service
sudo systemctl restart gl_lookup2.service
