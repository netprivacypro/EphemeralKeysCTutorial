#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 4910

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

void ssl_info_callback(const SSL *ssl, int where, int ret) {
    const char *str;
    int w;

    w = where & ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT) str = "SSL_connect";
    else if (w & SSL_ST_ACCEPT) str = "SSL_accept";
    else str = "undefined";

    if (where & SSL_CB_LOOP) {
        printf("%s:%s\n", str, SSL_state_string_long(ssl));
    } else if (where & SSL_CB_ALERT) {
        str = (where & SSL_CB_READ) ? "read" : "write";
        printf("SSL3 alert %s:%s:%s\n", str, SSL_alert_type_string_long(ret), SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_EXIT) {
        if (ret == 0)
            printf("%s:failed in %s\n", str, SSL_state_string_long(ssl));
        else if (ret < 0)
            printf("%s:error in %s\n", str, SSL_state_string_long(ssl));
    }
}

SSL_CTX* create_context() {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load the CA certificate
    if (!SSL_CTX_load_verify_locations(ctx, "cert.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set SSL options
    SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    // Set a more comprehensive cipher list
    if (!SSL_CTX_set_cipher_list(ctx, "DEFAULT:!aNULL:!MD5:!RC4")) {
        perror("Unable to set cipher list");
        exit(EXIT_FAILURE);
    }

    // Set the info callback for verbose logging
    SSL_CTX_set_info_callback(ctx, ssl_info_callback);

    return ctx;
}

int main() {
    int sock;
    struct sockaddr_in addr;
    SSL_CTX* ctx;
    SSL* ssl;
    const char* hostname = "127.0.0.1";
    const char* message = "PING";
    char buf[256] = {0};

    init_openssl();
    ctx = create_context();

    ssl = SSL_new(ctx);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, hostname, &addr.sin_addr) <= 0) {
        perror("Invalid address");
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to connect");
        exit(EXIT_FAILURE);
    }

    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        SSL_write(ssl, message, strlen(message));
        SSL_read(ssl, buf, sizeof(buf));
        printf("Received: %s\n", buf);
    }

    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}