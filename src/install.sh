# create service user
# gl_lookup_service
sudo adduser --system --disabled-password --disabled-login --home /var/empty --no-create-home --quiet --force-badname --group gl_lookup_service

# service dir
sudo mkdir -p /opt/graylog/lookup-service

# copy file
cp web.py /opt/graylog/lookup-service

# set owner
sudo -u gl_lookup_service touch /opt/graylog/lookup-service/web1.log
sudo -u gl_lookup_service touch /opt/graylog/lookup-service/web2.log
sudo chown -R gl_lookup_service:gl_lookup_service /opt/graylog/lookup-service/


# install service.....
cp gl_lookup.service /etc/systemd/system/gl_lookup.service
cp gl_lookup2.service /etc/systemd/system/gl_lookup2.service

sudo systemctl daemon-reload

sudo systemctl enable gl_lookup.service
sudo systemctl start gl_lookup.service

sudo systemctl enable gl_lookup2.service
sudo systemctl start gl_lookup2.service
