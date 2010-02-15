#include "common.h"
#include <openssl/err.h>

BIO *bio_err=0;
static char *pass;
static int password_cb(char *buf,int num, int rwflag,void *userdata);

/* A simple error and exit routine*/
int err_exit(char *string) {
	fprintf(stderr,"%s\n",string);
	exit(0);
}

/* Print SSL errors and exit*/
int berr_exit(char *string) {
	BIO_printf(bio_err,"%s\n",string);
	ERR_print_errors(bio_err);
	exit(0);
}

/*The password code is not thread safe*/
static int password_cb(char *buf, int num, int rwflag,void *userdata) {
	if(num<strlen(pass)+1)
		return(0);
	strcpy(buf,pass);
	return(strlen(pass));
}

SSL_CTX *ssl_init_ctx(char *keyfile, char *password) {
	SSL_METHOD *meth;
	SSL_CTX *ctx;
 
	if(!bio_err){
		/* Global system initialization*/
		SSL_library_init();
		SSL_load_error_strings();
	  
		/* An error write context */
		bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	}

	/* Create our context*/
	meth = SSLv23_method();
	ctx = SSL_CTX_new(meth);

	/* Load our keys and certificates*/
	if(!(SSL_CTX_use_certificate_chain_file(ctx, keyfile)))
		berr_exit("Can't read certificate file");

	pass = password;
	SSL_CTX_set_default_passwd_cb(ctx, password_cb);
	if(!(SSL_CTX_use_PrivateKey_file(ctx, keyfile,SSL_FILETYPE_PEM)))
		berr_exit("Can't read key file");

	/* Load the CAs we trust*/
	if(!(SSL_CTX_load_verify_locations(ctx, CA_LIST,0)))
		berr_exit("Can't read CA list");
	return ctx;
}
	 
void ssl_destroy_ctx(SSL_CTX *ctx) {
	SSL_CTX_free(ctx);
}


int tcp_connect(char *host, int port) {
	struct hostent *hp;
	struct sockaddr_in addr;
	int sock;
	
	if(!(hp = gethostbyname(host)))
		berr_exit("Couldn't resolve host");
	memset(&addr, 0, sizeof(addr));
	addr.sin_addr = *(struct in_addr*) hp->h_addr_list[0];
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if((sock=socket(AF_INET,SOCK_STREAM, IPPROTO_TCP)) < 0)
		err_exit("Couldn't create socket");
	if(connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		err_exit("Couldn't connect socket");
	
	return sock;
}

/* Check that the common name matches the host name*/
void check_cert(SSL *ssl, char *host) {
	X509 *peer;
	char peer_CN[256];
	
	if(SSL_get_verify_result(ssl)!=X509_V_OK)
		berr_exit("Certificate doesn't verify");

	/*Check the cert chain. The chain length
	  is automatically checked by OpenSSL when
	  we set the verify depth in the ctx */

	/*Check the common name*/
	peer = SSL_get_peer_certificate(ssl);
	X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, peer_CN, 256);
	if (strcasecmp(peer_CN, host))
		err_exit("Common name doesn't match host name");
}
