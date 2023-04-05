# download
echo Downloading updated web.py file
sudo wget https://raw.githubusercontent.com/drewmiranda-gl/gl-lookups/main/src/web.py -O /opt/graylog/lookup-service/web.py
sudo wget https://raw.githubusercontent.com/drewmiranda-gl/gl-lookups/main/src/dns_ip_search.py -O /opt/graylog/lookup-service/dns_ip_search.py

sudo chown -R gl_lookup_service:gl_lookup_service /opt/graylog/lookup-service/

echo Restarting gl_lookup.service
sudo systemctl stop gl_lookup.service
sleep 1
sudo rm -f /opt/graylog/lookup-service/web1.log
sleep 1
sudo systemctl start gl_lookup.service

echo Waiting 60 seconds for service to restart
sleep 60

echo Restarting gl_lookup2.service
sudo systemctl stop gl_lookup2.service
sleep 1
sudo rm -f /opt/graylog/lookup-service/web2.log
sleep 1
sudo systemctl start gl_lookup2.service
