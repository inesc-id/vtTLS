/* serv.cpp  -  Minimal ssleay server for Unix
 30.9.1996, Sampo Kellomaki <sampo@iki.fi> */

/* mangled to work with OpenSSL 0.9.2b
 Simplified to be even more minimal
 12/98 - 4/99 Wade Scholine <wades@mail.cybg.com> */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>

#include <vttls/rsa.h>
#include <vttls/crypto.h>
#include <vttls/x509.h>
#include <vttls/pem.h>
#include <vttls/ssl.h>
#include <vttls/err.h>

#include <string>

/* define HOME to be dir for key and cert files... */
#define HOME "./"
/* Make these what you want for cert & key files */

/*ECDHE-ECDSA*/
#define ECDH_CERTF  "server-ecdhe-cert.crt"
#define ECDH_KEYF   "server-ecdhe-key.pem"

#define RSA_CERTF   "server_rsa.crt"
#define RSA_KEYF    "server_rsa.key"

#define ECDH2_CERTF    "server-dh-cert.crt"
#define ECDH2_KEYF     "server-dh-key.pem"

#define DIVERSITY_FACTOR 2

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

#define BUF_SZ 4 * 1024

int main(int argc, char* argv[]) {
	int err;
	int listen_sd;
	int sd;
	struct sockaddr_in sa_serv;
	struct sockaddr_in sa_cli;
	socklen_t client_len;
	SSL_CTX* ctx;
	SSL* ssl;
	X509* client_cert;
	char* str;
	char buf[BUF_SZ];
	SSL_METHOD const *meth;

	unsigned int port;

	if (argc != 2) {
		printf("Usage: ./server <port>\n");
		exit(0);
	}
	port = atoi(argv[1]);

	/* SSL preliminaries. We keep the certificate and key with the context. */

	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
	meth = TLSv1_2_method();

	ctx = SSL_CTX_new(meth);

	if (!ctx) {
		ERR_print_errors_fp(stderr);
		exit(2);
	}

	if (SSL_CTX_use_certificate_file(ctx, ECDH_CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(3);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, ECDH_KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr,
				"Private key does not match the certificate public key\n");
		exit(5);
	}

	if (SSL_CTX_use_n_certificate_file(DIVERSITY_FACTOR, ctx, RSA_CERTF,
	SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(3);
	}
	if (SSL_CTX_use_n_PrivateKey_file(DIVERSITY_FACTOR, ctx, RSA_KEYF,
	SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}

	if (!SSL_CTX_check_n_private_key(DIVERSITY_FACTOR, ctx)) {
		fprintf(stderr,
				"Second private key does not match the certificate public key\n");
		exit(5);
	}

	/* -------------------------------------------- */
	/* Prepare TCP socket for receiving connections */

	listen_sd = socket(AF_INET, SOCK_STREAM, 0);
	CHK_ERR(listen_sd, "socket");

	memset(&sa_serv, 0, sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(port); /* Server Port number */

	err = bind(listen_sd, (struct sockaddr*) &sa_serv, sizeof(sa_serv));
	CHK_ERR(err, "bind");

	/* Receive a TCP connection. */

	err = listen(listen_sd, 5);
	CHK_ERR(err, "listen");

	client_len = sizeof(sa_cli);
	sd = accept(listen_sd, (struct sockaddr*) &sa_cli, &client_len);
	CHK_ERR(sd, "accept");
	close(listen_sd);

	// convert IP address to string
	char addr_buf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(sa_cli.sin_addr.s_addr), addr_buf, INET_ADDRSTRLEN);
	// print IP and port
	printf("Connection from %s, port %d\n", addr_buf, ntohs(sa_cli.sin_port));

	/* -------------------------------------------- */
	/* TCP connection is ready. Do server side SSL. */

	ssl = SSL_new(ctx);
	CHK_NULL(ssl); /* CHECKED */
	SSL_set_fd(ssl, sd);
	err = SSL_accept(ssl);
	CHK_SSL(err); /* CHECKED */

	/* Get the cipher - opt */

	printf("SSL connection using %s\n", SSL_get_cipher(ssl));
	printf("SSL connection using %s\n",
			SSL_get_n_cipher(DIVERSITY_FACTOR, ssl));

	/* DATA EXCHANGE - Receive message and send reply. */

	err = SSL_read(ssl, buf, sizeof(buf) - 1);
	CHK_SSL(err);
	buf[err] = '\0';
	printf("Got %d chars:'%s'\n", err, buf);

	printf("total_size: %d\n", err);

	/* Clean up. */
	close(sd);
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;

}
/* EOF - server.cpp */
