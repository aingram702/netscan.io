#!/usr/bin/with-contenv bashio

bashio::log.info "Starting NetScanner Pro v3.1..."

export PORT=5000

cd /app
exec python3 server.py
