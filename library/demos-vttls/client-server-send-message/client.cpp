/* cli.cpp  -  Minimal ssleay client for Unix
 30.9.1996, Sampo Kellomaki <sampo@iki.fi> */

/* mangled to work with OpenSSL 0.9.2b
 Simplified to be even more minimal
 12/98 - 4/99 Wade Scholine <wades@mail.cybg.com> */

#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <iostream>

#include <vttls/crypto.h>
#include <vttls/x509.h>
#include <vttls/pem.h>
#include <vttls/ssl.h>
#include <vttls/err.h>

/* define HOME to be dir for key and cert files... */
#define HOME "./"

#define DIVERSITY_FACTOR 2

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

#define BUF_SZ 4 * 1024

int main(int argc, char* argv[]) {
	int err;
	int sd;
	struct sockaddr_in sa;
	SSL_CTX* ctx;
	SSL* ssl;
	X509* server_cert;
	X509* server_sec_cert;
	char* str;
	char buf[BUF_SZ];
	SSL_METHOD const *meth;
	timeval start, end;

	const char *ip;
	unsigned int port;
	const char *toSend;

	if (argc != 4) {
		printf("Usage: ./client <server-ip> <port> <message-to-send>\n");
		exit(0);
	}
	ip = argv[1];
	port = atoi(argv[2]);
	toSend = argv[3];

	/* SSL_library_init() */
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
	meth = TLSv1_2_client_method();

	ctx = SSL_CTX_new(meth);
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		exit(2);
	}

	/* ----------------------------------------------- */
	/* Create a socket and connect to server using normal socket calls. */

	sd = socket(AF_INET, SOCK_STREAM, 0);
	CHK_ERR(sd, "socket");

	memset(&sa, 0, sizeof(sa));

	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr(ip); /* Server IP */
	sa.sin_port = htons(port); /* Server Port number */

	err = connect(sd, (struct sockaddr*) &sa, sizeof(sa));
	CHK_ERR(err, "connect");

	/* -------------------------------------------------- */
	/* Now we have TCP connection. Start SSL negotiation. */

	ssl = SSL_new(ctx);
	CHK_NULL(ssl);

	SSL_set_fd(ssl, sd);
	/* Sets the file descriptor fd as the input/output
	 * facility for the TLS encypted side
	 * of argument "ssl"; fd is usually the socket descriptor */

	unsigned long long diff;
	int i = 0;

	gettimeofday(&start, NULL);

	err = SSL_connect(ssl);
	CHK_SSL(err);

	gettimeofday(&end, NULL);
	diff = 1000 * (end.tv_sec - start.tv_sec)
			+ (end.tv_usec - start.tv_usec) / 1000;
	printf("The vtTLS Handshake took %llu ms\n", diff);
	diff = 0;

	/* ssl->method->ssl_connect(s)*/

	/* Following two steps are optional and not required for
	 data exchange to be successful. */

	/* Get the cipher - opt */

	printf("SSL connection using %s\n", SSL_get_cipher(ssl));
	printf("SSL connection using %s\n",
			SSL_get_n_cipher(DIVERSITY_FACTOR, ssl));

	/* Get server's certificate (note: beware of dynamic allocation) - opt */

	server_cert = SSL_get_peer_certificate(ssl);
	CHK_NULL(server_cert);

	server_sec_cert = SSL_get_n_peer_certificate(DIVERSITY_FACTOR, ssl);
	CHK_NULL(server_sec_cert);

	printf("Server certificate:\n");

	str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
	CHK_NULL(str);
	printf("\t subject: %s\n", str);
	OPENSSL_free(str);

	str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
	CHK_NULL(str);
	printf("\t issuer: %s\n", str);
	OPENSSL_free(str);

	printf("Server second certificate:\n");

	str = X509_NAME_oneline(X509_get_subject_name(server_sec_cert), 0, 0);
	CHK_NULL(str);
	printf("\t subject: %s\n", str);
	OPENSSL_free(str);

	str = X509_NAME_oneline(X509_get_issuer_name(server_sec_cert), 0, 0);
	CHK_NULL(str);
	printf("\t issuer: %s\n", str);
	OPENSSL_free(str);

	/* We could do all sorts of certificate verification stuff here before
	 deallocating the certificate. */

	X509_free(server_cert);
	X509_free(server_sec_cert);

	/* --------------------------------------------------- */
	/* DATA EXCHANGE - Send a message and receive a reply. */

	err = SSL_write(ssl, toSend, strlen(toSend));
	CHK_SSL(err);

	printf("-- total_size: %d\n", err);

	/* send SSL/TLS close_notify */
	SSL_shutdown(ssl);

	/* Clean up. */
	close(sd);
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;

}
/* EOF - client.cpp */
