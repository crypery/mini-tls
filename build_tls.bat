@echo off
echo Building TLS RSA Library and Examples...
gcc -O2 -I./crypery ./crypery/*.c -o tls_client.exe tls_client.c -DHTTP_NO_GZIP -lws2_32
gcc -O2 -I./crypery ./crypery/*.c -o tls_server.exe tls_server.c -DHTTP_NO_GZIP -lws2_32
echo Build complete.
