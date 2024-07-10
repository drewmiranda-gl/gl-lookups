#!/bin/bash

cd /home/drew
rm web.py
/usr/bin/wget https://raw.githubusercontent.com/drewmiranda-gl/gl-lookups/main/src/web.py

/usr/bin/cp /home/drew/web.py /opt/graylog/lookup-service/web.py

/usr/bin/systemctl restart gl_lookup
/usr/bin/systemctl restart gl_lookup2