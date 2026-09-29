/*
 * Git: https://github.com/crypery
 * Author: https://crypery.com
 * License: GNU AGPL v3 (Affero GPL)
 */

// no interative: echo "test" | tls_client

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <io.h>
    #include <conio.h>
    #pragma comment (lib, "ws2_32.lib")
    #define socklen_t int
    static void my_usleep(unsigned int usec) {
        Sleep((DWORD)((usec + 999) / 1000));
    }
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <sys/ioctl.h>
    #include <netinet/in.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <termios.h>
    #include <time.h>

    static struct termios orig_termios;
    static int termios_saved = 0;

    static void my_usleep(unsigned int usec) {
        struct timespec ts;
        ts.tv_sec = (time_t)(usec / 1000000);
        ts.tv_nsec = (long)((usec % 1000000) * 1000);
        nanosleep(&ts, NULL);
    }

    static void termios_raw_mode(int enable) {
        struct termios raw;
        if (!termios_saved) {
            if (tcgetattr(STDIN_FILENO, &orig_termios) == 0)
                termios_saved = 1;
        }
        if (enable && termios_saved) {
            raw = orig_termios;
            raw.c_lflag &= (tcflag_t)~(ICANON | ECHO);
            raw.c_cc[VMIN] = 0;
            raw.c_cc[VTIME] = 0;
            tcsetattr(STDIN_FILENO, TCSANOW, &raw);
        } else if (!enable && termios_saved) {
            tcsetattr(STDIN_FILENO, TCSANOW, &orig_termios);
        }
    }

    static int kbhit(void) {
        int n = 0;
        if (ioctl(STDIN_FILENO, FIONREAD, &n) < 0)
            return 0;
        return n;
    }

    static int getch(void) {
        unsigned char c;
        while (read(STDIN_FILENO, &c, 1) <= 0) {
            my_usleep(1000);
        }
        return (int)c;
    }
#endif

#include "tls.h"

void error(const char *msg) {
    perror(msg);
    exit(0);
}

int send_pending(int client_sock, const uint8_t *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int res = send(client_sock, (const char *)(buf + sent), len - sent, 0);
        if (res <= 0) return res;
        sent += res;
    }
    return sent;
}

#ifdef __cplusplus
}
#endif

int main(int argc, char *argv[]) {
    int sockfd, portno;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    int tls = TLS_VERSION_AUTO;

    char *ref_argv[] = {"", "localhost", "2000"};
    if (argc < 3) {
        argv = ref_argv;
        argc = 3;
    }

#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#else
    signal(SIGPIPE, SIG_IGN);
#endif

    portno = atoi(argv[2]);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        error("ERROR opening socket");

    server = gethostbyname(argv[1]);
    if (server == NULL) {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }

    memset((char *)&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy((char *)&serv_addr.sin_addr.s_addr, (char *)server->h_addr, server->h_length);
    serv_addr.sin_port = htons(portno);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR connecting");

    char ip_str[64];
    strncpy(ip_str, argv[1], sizeof(ip_str) - 1);
    ip_str[sizeof(ip_str) - 1] = 0;
    printf("Connected to %s:%d\n", ip_str, portno);

    TLSContext tls_ctx;
    tls_init_context(&tls_ctx, 0, tls);

    uint8_t out_buf[0xFFFF];
    uint8_t in_buf[0xFFFF];
    int out_len;
    int read_size = 0;
    int handshake_complete = 0;

    while (!handshake_complete) {
        int rc = tls_handshake_step(&tls_ctx, in_buf, read_size, out_buf, &out_len);

        if (out_len > 0) {
            send_pending(sockfd, out_buf, out_len);
        }

        if (rc == TLS_RSA_OK) {
            handshake_complete = 1;
            break;
        } else if (rc == TLS_RSA_ERROR) {
            fprintf(stderr, "TLS handshake error\n");
            return 1;
        } else {
            read_size = recv(sockfd, (char *)in_buf, sizeof(in_buf), 0);
            if (read_size <= 0) {
                fprintf(stderr, "Connection closed during handshake\n");
                return 1;
            }
        }
    }

    int negotiated_tls13 = tls_negotiated_tls13(&tls_ctx);
    printf("Client TLS: %s\n", negotiated_tls13 ? "1.3" : "1.2");

    /* Read server handshake info */
    uint8_t dec_buf[0xFFFF];
    int dec_len = 0;
    int rc = tls_receive_application_data(&tls_ctx, NULL, 0, dec_buf, &dec_len);
    if (rc == TLS_RSA_NEED_MORE_DATA) {
        read_size = recv(sockfd, (char *)in_buf, sizeof(in_buf), 0);
        if (read_size > 0) {
            tls_receive_application_data(&tls_ctx, in_buf, read_size, dec_buf, &dec_len);
        }
    }
    if (dec_len > 0) {
        dec_buf[dec_len] = 0;
        printf("%s\n", dec_buf);
    }

    int interactive = 1;
#ifdef _WIN32
    if (!_isatty(_fileno(stdin))) {
        interactive = 0;
    }
#else
    if (!isatty(STDIN_FILENO)) {
        interactive = 0;
    }
#endif
    printf("Interactive:  %s\n", interactive ? "yes" : "no");
    if (interactive) {
        printf("Enter message ('exit' or esc to quit):\n");

#ifndef _WIN32
        termios_raw_mode(1);
#endif

        char line_buf[100];
        int line_pos = 0;

        while (1) {
            if (!kbhit()) { 
                my_usleep(1000);
                continue;
            } 
            char c = getch();
            if (c == 27) break;
            printf("%c", c); 
             fflush(stdout);
            if ((c == '\r' || c == '\n')&&(line_pos > 0)) {
                line_buf[line_pos] = 0;
                printf("Client: %s\r\n",line_buf);
                if (strcmp(line_buf, "exit") == 0) {
                    printf("Exiting...\n");
                    break;
                }

                if (line_pos > 0) {
                    uint8_t enc_buf[0xFFFF];
                    int enc_len;
                    tls_send_application_data(&tls_ctx, (const uint8_t *)line_buf, line_pos, enc_buf, &enc_len);
                    send_pending(sockfd, enc_buf, enc_len);

                    uint8_t resp_buf[0xFFFF];
                    int resp_len = 0;
                    int rrc = tls_receive_application_data(&tls_ctx, NULL, 0, resp_buf, &resp_len);
                    if (rrc == TLS_RSA_NEED_MORE_DATA) {
                        read_size = recv(sockfd, (char *)in_buf, sizeof(in_buf), 0);
                        if (read_size > 0) {
                            tls_receive_application_data(&tls_ctx, in_buf, read_size, resp_buf, &resp_len);
                        }
                    }
                    if (rrc == TLS_RSA_ERROR || rrc == TLS_RSA_CLOSED) break;
                    if (resp_len > 0) {
                        resp_buf[resp_len] = 0;
                        printf("Server: %s\r\n", resp_buf);
                    }
                }

                line_pos = 0;
            } else {
                if (line_pos < sizeof(line_buf) - 1) {
                    line_buf[line_pos++] = c;
                }
            }
        }

#ifndef _WIN32
        termios_raw_mode(0);
#endif
    } else {
        /* Non-interactive: read from stdin and send via TLS */
        for (;;) {
            char line_buf[1024];
            if (fgets(line_buf, sizeof(line_buf), stdin) == NULL) {
                break;
            }
            int len = (int)strlen(line_buf);
            if (len > 0 && line_buf[len - 1] == '\n') {
                line_buf[--len] = 0;
            }
            if (len == 0) continue;
            uint8_t enc_buf[0xFFFF];
            int enc_len;
            tls_send_application_data(&tls_ctx, (const uint8_t *)line_buf, len, enc_buf, &enc_len);
            send_pending(sockfd, enc_buf, enc_len);
            my_usleep(200);
            uint8_t resp_buf[0xFFFF];
            int resp_len = 0;
            int rrc = tls_receive_application_data(&tls_ctx, NULL, 0, resp_buf, &resp_len);
            if (rrc == TLS_RSA_NEED_MORE_DATA) {
                read_size = recv(sockfd, (char *)in_buf, sizeof(in_buf), 0);
                if (read_size > 0) {
                    tls_receive_application_data(&tls_ctx, in_buf, read_size, resp_buf, &resp_len);
                }
            }
            if (rrc == TLS_RSA_ERROR || rrc == TLS_RSA_CLOSED) break;
            if (resp_len > 0) {
                resp_buf[resp_len] = 0;
                printf("Server: %s\n", resp_buf);
            }
        }
    }

    uint8_t close_out[0xFFFF];
    int close_len;
    tls_close(&tls_ctx, close_out, &close_len);
    if (close_len > 0) {
        send_pending(sockfd, close_out, close_len);
    }

#ifdef _WIN32
    shutdown(sockfd, SD_BOTH);
    closesocket(sockfd);
#else
    shutdown(sockfd, SHUT_RDWR);
    close(sockfd);
#endif

    printf("Disconnected from %s:%d\n", ip_str, portno);
    return 0;
}