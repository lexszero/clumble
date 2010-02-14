#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/ssl.h>

int TCPSock;

void die(char *msg) {
	puts(msg);
	exit(1);
}

void ssl_init() {
	SSL_load_error_strings();
	SSL_library_init();
	
	SSL_CTX *sslctx = SSL_CTX_new(TLSv1_client_method());
	SSL *ssl SSL_new(sslctx);
	SSL_set_fd(ssl, TCPSock);
	if (SSL_connect(ssl) <= 0) {
		die("SSL_connect failed");
	}

}

int _connect(char* addr, int port) {
	struct hostent *host;
	struct sockaddr_in s_addr;
	int sock;
	if (! (host = gethostbyname(addr))) {
		// can't resolve
		return 0;
	}
	if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		// can't create socket
		return 0;
	}
	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sin_family = AF_INET;
	s_addr.sin_addr.s_addr = *((unsigned long *) host->h_addr_list[0]);
	s_addr.sin_port = htons(port);
	if (connect(sock, (struct sockaddr *) &s_addr, sizeof(s_addr)) < 0) {
		// can't connect
		return 0;
	}
	return sock;
}

int main(int argc, char* argv[]) {
	TCPSock = _connect(,);
	ssl_init();
	return 0;
}
