#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/ec.h>

#define PORT 4910

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_context() {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

DH* get_dh2048() {
    static unsigned char dhp_2048[] = {
		0xC1,0x51,0x58,0x69,0xFB,0xE8,0x6C,0x47,0x2B,0x86,0x61,0x4F,
		0x20,0x2E,0xD3,0xFC,0x19,0xEE,0xB8,0xF3,0x35,0x7D,0xBA,0x86,
		0x2A,0xC3,0xC8,0x6E,0xF4,0x99,0x75,0x65,0xD3,0x7A,0x9E,0xDF,
		0xD4,0x1F,0x88,0xE3,0x17,0xFC,0xA1,0xED,0xA2,0xB6,0x77,0x84,
		0xAA,0x08,0xF2,0x97,0x59,0x7A,0xA0,0x03,0x0D,0x3E,0x7E,0x6D,
		0x65,0x6A,0xA4,0xEA,0x54,0xA9,0x52,0x5F,0x63,0xB4,0xBC,0x98,
		0x4E,0xF6,0xE1,0xA4,0xEE,0x16,0x0A,0xB0,0x01,0xBD,0x9F,0xA1,
		0xE8,0x23,0x29,0x56,0x40,0x95,0x13,0xEB,0xCB,0xD5,0xFC,0x76,
		0x1A,0x41,0x26,0xCE,0x20,0xEB,0x30,0x10,0x17,0x07,0xE1,0x8C,
		0xAC,0x57,0x37,0x8B,0xE8,0x01,0xDE,0xA9,0xEF,0xA4,0xC2,0xA4,
		0x6E,0x48,0x25,0x11,0x33,0x11,0xD4,0x52,0x79,0x87,0x9F,0x75,
		0x61,0xF7,0x9C,0x7D,0x36,0x41,0xCB,0xEC,0x8F,0xEA,0x4A,0x47,
		0x6A,0x36,0x37,0x75,0xB9,0x8E,0xF5,0x5F,0x67,0xCF,0x1F,0xD8,
		0xCA,0x70,0x42,0xC7,0xA2,0xED,0x0F,0x7D,0xBE,0x43,0x08,0x28,
		0x66,0x3D,0xDD,0x87,0x0D,0x61,0x6E,0xD0,0xE7,0x49,0xD1,0x70,
		0xA9,0x4D,0xD5,0xFD,0xED,0xF2,0x6D,0x32,0x17,0x97,0x5B,0x06,
		0x60,0x9C,0x5F,0xA3,0x5D,0x34,0x14,0x7E,0x63,0x54,0xE4,0x7E,
		0x09,0x8F,0xBB,0x8E,0xA0,0xD0,0x96,0xAC,0x30,0x20,0x39,0x3B,
		0x8C,0x92,0x65,0x37,0x0A,0x8F,0xEC,0x72,0x8B,0x61,0x7D,0x62,
		0x24,0x54,0xE9,0x1D,0x01,0x68,0x89,0xC4,0x7B,0x3C,0x48,0x62,
		0x9B,0x83,0x11,0x3A,0x0B,0x0D,0xEF,0x5A,0xE4,0x7A,0xA0,0x69,
		0xF4,0x54,0xB5,0x5B,
	};
	static unsigned char dhg_2048[] = {
		0x02,
	};
    DH* dh = DH_new();
    if (dh == NULL) return NULL;
    BIGNUM* p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), NULL);
    BIGNUM* g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), NULL);
    if (p == NULL || g == NULL || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        return NULL;
    }
    return dh;
}

EC_KEY* get_ecdh_key() {
    EC_KEY* ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ecdh == NULL || !EC_KEY_generate_key(ecdh)) {
        EC_KEY_free(ecdh);
        return NULL;
    }
    return ecdh;
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

void configure_context(SSL_CTX* ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    DH* dh = get_dh2048();
    if (dh == NULL) {
        perror("Unable to create DH parameters");
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_tmp_dh(ctx, dh);
    DH_free(dh);

    EC_KEY* ecdh = get_ecdh_key();
    if (ecdh == NULL) {
        perror("Unable to create ECDH key");
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_tmp_ecdh(ctx, ecdh);
    EC_KEY_free(ecdh);

    // Load the server certificate and key
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
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
}

int main() {
    int server_sock;
    struct sockaddr_in addr;
    SSL_CTX* ctx;

    init_openssl();
    ctx = create_context();
    configure_context(ctx);

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(server_sock, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    while (1) {
        struct sockaddr_in client_addr;
        uint32_t len = sizeof(client_addr);
        SSL* ssl;
        const char reply[] = "PONG";

        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &len);
        if (client_sock < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sock);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            char buf[256] = {0};
            SSL_read(ssl, buf, sizeof(buf));
            printf("Received: %s\n", buf);

            SSL_write(ssl, reply, strlen(reply));
        }

        SSL_free(ssl);
        close(client_sock);
    }

    close(server_sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}