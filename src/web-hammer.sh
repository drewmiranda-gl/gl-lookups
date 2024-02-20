#!/bin/bash
for (( ; ; ))
do
   echo "infinite loops [ hit CTRL+C to stop]"
   curl "http://localhost:8080/?lookup=rdns&key=192.168.0.1"
done
