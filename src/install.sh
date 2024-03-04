# python

sudo apt-get -y install mariadb-client libmariadb3 libmariadb-dev
sudo python3 -m pip install -r requirements.txt

# haproxy
sudo apt install -y haproxy
cp -f haproxy/haproxy.cfg /etc/haproxy/

# create service user
# gl_lookup_service
sudo adduser --system --disabled-password --disabled-login --home /var/empty --no-create-home --quiet --force-badname --group gl_lookup_service

# service dir
sudo mkdir -p /opt/graylog/lookup-service

# copy files
sudo cp -f web.py /opt/graylog/lookup-service
sudo cp -f dns_ip_search.py /opt/graylog/lookup-service
sudo cp -f config.ini /opt/graylog/lookup-service
sudo mv -f /opt/graylog/lookup-service/config.ini /opt/graylog/lookup-service/auth.ini

sudo cp -f service-wrapper.sh /opt/graylog/lookup-service
sudo chmod +x /opt/graylog/lookup-service/service-wrapper.sh

sudo cp -f set-health-helper.sh /opt/graylog/lookup-service
sudo chmod +x /opt/graylog/lookup-service/set-health-helper.sh

sudo cp -f update.sh /opt/graylog/lookup-service
sudo chmod +x /opt/graylog/lookup-service/update.sh

# set owner
touch /opt/graylog/lookup-service/web1.log
touch /opt/graylog/lookup-service/web2.log
touch /opt/graylog/lookup-service/web3.log
touch /opt/graylog/lookup-service/web4.log

echo 0 | sudo tee /opt/graylog/lookup-service/health1.txt
echo 0 | sudo tee /opt/graylog/lookup-service/health2.txt
echo 0 | sudo tee /opt/graylog/lookup-service/health3.txt
echo 0 | sudo tee /opt/graylog/lookup-service/health4.txt

sudo chown -R gl_lookup_service:gl_lookup_service /opt/graylog/lookup-service/

# install service.....
sudo cp -f gl_lookup.service /etc/systemd/system/gl_lookup.service
sudo cp -f gl_lookup2.service /etc/systemd/system/gl_lookup2.service
sudo cp -f gl_lookup3.service /etc/systemd/system/gl_lookup3.service
sudo cp -f gl_lookup4.service /etc/systemd/system/gl_lookup4.service

sudo systemctl daemon-reload

sudo systemctl enable gl_lookup.service
sudo systemctl start gl_lookup.service

sudo systemctl enable gl_lookup2.service
sudo systemctl start gl_lookup2.service

sudo systemctl enable gl_lookup3.service
sudo systemctl start gl_lookup3.service

sudo systemctl enable gl_lookup4.service
sudo systemctl start gl_lookup4.service

sudo systemctl restart haproxy
