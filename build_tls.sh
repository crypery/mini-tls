#!/bin/sh
set -e
echo "Building TLS RSA Library and Examples..."
gcc -O2 -I./crypery ./crypery/*.c -o tls_client tls_client.c -DHTTP_NO_GZIP -lpthread
gcc -O2 -I./crypery ./crypery/*.c -o tls_server tls_server.c -DHTTP_NO_GZIP -lpthread
echo "Build complete."
