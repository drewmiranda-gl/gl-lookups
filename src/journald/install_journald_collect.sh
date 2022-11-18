sudo mkdir -p /graylog/filebeat_for_journald
sudo cp fb_journald.yaml /graylog/

# /usr/share/filebeat/bin/filebeat -c /graylog/fb_journald.yaml