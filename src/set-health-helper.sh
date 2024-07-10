#!/bin/bash


file=$1
value=$2

echo -n $2 > $1
# it is important this allows enough time for the HA proxy (or other load
#   balancer) to execute its health check and mark this as DOWN before
#   the service actually fully exits and stops accetping requests
#   currently doing 1 check every 1s so 10s should be plenty
sleep 10
