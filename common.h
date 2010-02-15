#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

#include <openssl/ssl.h>

// crypto magic
#define KEYFILE "client.pem"
#define CA_LIST "root.pem"
#define PASSWORD "passw" 

extern BIO *bio_err;
int berr_exit (char *string);
int err_exit(char *string);

SSL_CTX *ssl_initi_ctx(char *keyfile, char *password);
void ssl_destroy_ctx(SSL_CTX *ctx);
void ssl_check_cert(SSL *ssl, char *host);

