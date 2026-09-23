#!/bin/sh
set -eu

if [ -f /data/config.json ]; then
  export LIGHTHOUSE_HTTP_BIND=0.0.0.0:8080
  exec mesh-lighthouse /data/config.json
fi

exec mesh-lighthouse serve-http /data 0.0.0.0:8080
