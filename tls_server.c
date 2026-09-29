/*
 * Git: https://github.com/crypery
 * Author: https://crypery.com
 * License: GNU AGPL v3 (Affero GPL)
 */

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #define socklen_t int
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
#endif

#include "tls.h"

int send_pending(int client_sock, const uint8_t *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int res = send(client_sock, (const char *)(buf + sent), len - sent, 0);
        if (res <= 0) return res;
        sent += res;
    }
    return sent;
}

const char* get_tls_version_str(int tls) {
    if (tls==TLS_VERSION_12) return "1.2";
    if (tls==TLS_VERSION_13) return "1.3";
    return "1.2/1.3";
}

const char* get_cipher_suite_str(int cipher_suite) {
    if (cipher_suite == TLS13_CIPHER_SUITE) return "TLS_AES_128_GCM_SHA256";
    if (cipher_suite == TLS_RSA_CIPHER_SUITE) return "ECDHE-RSA-AES128-GCM-SHA256";
    return "UNKNOWN";
}

const char* get_key_exchange_str(int group) {
    if (group == TLS_RSA_CURVE_X25519) return "X25519";
    if (group == TLS_RSA_CURVE_SECP256R1) return "P-256";
    return "UNKNOWN";
}

#ifdef __cplusplus
}
#endif

int main(int argc, char *argv[]) {
    int socket_desc, client_sock, read_size;
    socklen_t c;
    struct sockaddr_in server, client;
    unsigned char client_message[0xFFFF];
    int tls = TLS_VERSION_AUTO;

    printf("Server TLS Version: %s\n", get_tls_version_str(tls));

#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#else
    signal(SIGPIPE, SIG_IGN);
#endif

    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc == -1) {
        return 0;
    }

    int port = 2000;
    if (argc > 1) {
        port = atoi(argv[1]);
        if (port <= 0)
            port = 2000;
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(port);

    int enable = 1;
    setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, (const char *)&enable, sizeof(int));

    if (bind(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0) {
        return 1;
    }

    listen(socket_desc, 3);

    RSAKey server_key;
    uint8_t server_cert[TLS_RSA_MAX_CERT_SIZE];
    int server_cert_len = 0;
    tls_rsa_generate_key(&server_key);
    tls_generate_self_signed_cert(&server_key, server_cert, &server_cert_len);

    while (1) {
        c = sizeof(struct sockaddr_in);
        client_sock = accept(socket_desc, (struct sockaddr *)&client, &c);
        if (client_sock < 0) {
            continue;
        }
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client.sin_addr, ip_str, sizeof(ip_str));
        printf("connect: %s\n", ip_str);

        TLSContext tls_ctx;
        tls_init_context(&tls_ctx, 1, tls);
        tls_set_rsa_key(&tls_ctx, &server_key);
        tls_set_certificate(&tls_ctx, server_cert, server_cert_len);

        uint8_t out_buf[0xFFFF];
        uint8_t in_buf[0xFFFF];
        int out_len;
        read_size = 0;
        int handshake_complete = 0;

        while (!handshake_complete) {
            int rc = tls_handshake_step(&tls_ctx, in_buf, read_size, out_buf, &out_len);

            if (out_len > 0) {
                send_pending(client_sock, out_buf, out_len);
            }

            if (rc == TLS_RSA_OK) {
                handshake_complete = 1;
                break;
            } else if (rc == TLS_RSA_ERROR) {
                break;
            } else {
                read_size = recv(client_sock, (char *)in_buf, sizeof(in_buf), 0);
                if (read_size <= 0) {
                    break;
                }
            }
        }

        if (!handshake_complete) {
#ifdef _WIN32
            closesocket(client_sock);
#else
            close(client_sock);
#endif
            continue;
        }

        int negotiated_tls13 = tls_negotiated_tls13(&tls_ctx);

        char info_msg[512];
        int info_len = snprintf(info_msg, sizeof(info_msg),
            "Server TLS: %s (%s)\n"
            "Cipher Suite: %s\n"
            "Key Exchange: %s",
            get_tls_version_str(tls),
            negotiated_tls13 ? "1.3" : "1.2",
            get_cipher_suite_str(tls_ctx.cipher_suite),
            get_key_exchange_str(tls_ctx.group));

        uint8_t enc_buf[0xFFFF];
        int enc_len;
        tls_send_application_data(&tls_ctx, (const uint8_t *)info_msg, info_len, enc_buf, &enc_len);
        send_pending(client_sock, enc_buf, enc_len);

        for (;;) {
            uint8_t dec_buf[0xFFFF];
            int dec_len = 0;
            int rc = tls_receive_application_data(&tls_ctx, NULL, 0, dec_buf, &dec_len);

            if (rc == TLS_RSA_NEED_MORE_DATA) {
                read_size = recv(client_sock, (char *)client_message, sizeof(client_message), 0);
                if (read_size <= 0) break;
                rc = tls_receive_application_data(&tls_ctx, client_message, read_size, dec_buf, &dec_len);
            }

            if (rc == TLS_RSA_ERROR || rc == TLS_RSA_CLOSED) break;
            if (rc != 0 || dec_len <= 0) continue;

            uint8_t enc_echo[0xFFFF];
            int enc_echo_len;
            tls_send_application_data(&tls_ctx, dec_buf, dec_len, enc_echo, &enc_echo_len);
            send_pending(client_sock, enc_echo, enc_echo_len);
        }

#ifdef _WIN32
        shutdown(client_sock, SD_BOTH);
        closesocket(client_sock);
#else
        shutdown(client_sock, SHUT_RDWR);
        close(client_sock);
#endif
        printf("disconnect: %s\n", ip_str);
    }

    return 0;
}