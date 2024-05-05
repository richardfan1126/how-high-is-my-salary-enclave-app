#!/bin/bash

set -e

# Assign local loopback address
ifconfig lo 127.0.0.1

# Start traffic forwarder
/usr/bin/socat -t 30 VSOCK-LISTEN:1000,fork,reuseaddr TCP:127.0.0.1:8000 &

# Start app
/app/how-high-is-my-salary &

# Exit if any process exit
wait -n
exit $?
