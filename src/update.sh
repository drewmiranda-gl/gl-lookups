# download
echo Downloading updated web.py file
sudo wget https://raw.githubusercontent.com/drewmiranda-gl/gl-lookups/main/src/web.py -O /opt/graylog/lookup-service/web.py
sudo wget https://raw.githubusercontent.com/drewmiranda-gl/gl-lookups/main/src/dns_ip_search.py -O /opt/graylog/lookup-service/dns_ip_search.py

sudo chown -R gl_lookup_service:gl_lookup_service /opt/graylog/lookup-service/

echo Restarting gl_lookup.service
sudo systemctl restart gl_lookup.service

echo Waiting 60 seconds for service to restart
sleep 60

echo Restarting gl_lookup2.service
sudo systemctl restart gl_lookup2.service
