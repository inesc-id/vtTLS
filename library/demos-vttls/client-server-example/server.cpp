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

#include "read_line.h"

#include "debug.h"
#include "demo.h"

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

#define MAX_MSG_SIZE 16250

// Error checking
#define CHK_NULL(x,s) if ((x)==NULL) { fprintf(stderr, "%s null\n", s); exit (1); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

// Buffer settings
#define BUF_SZ 8 * 1024

#define MAX_FILE_NAME 255
#define MAX_FILE_PATH 4096

// 2^32=2147483647 plus negative plus thousands separators plus null character
#define MAX_INT_STRING 10+1+3+1

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

	/* buffer for IP address strings */
	char addr_buf[INET_ADDRSTRLEN];
	/* buffer for file name */
	char file_name[MAX_FILE_NAME];
	/* buffer for file size as string */
	char file_len_str[MAX_INT_STRING];

	/* for performance measurements */
	unsigned long long diff;

	/* arguments */
	unsigned int port;

	/* Arguments validation */
	if (argc != 2) {
		printf("Usage: ./server <port>\n");
		exit(1);
	}
	port = atoi(argv[1]);
	debug_printf("Arguments: Port %d\n", port);

	debug_printf("Work buffer size %d bytes\n", BUF_SZ);

	demo_banner();
	demo_printf("Server listening on port %d\n", port);
	demo_println("");

	/* ----------------------------------------------- */
	/* Prepare TCP socket for receiving connections */

	listen_sd = socket(AF_INET, SOCK_STREAM, 0);
	CHK_ERR(listen_sd, "socket");

	const int enable = 1;
	err = setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
	CHK_ERR(err, "setsockopt(SO_REUSEADDR) failed");

	memset(&sa_serv, 0, sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(port); /* Server Port number */

	err = bind(listen_sd, (struct sockaddr*) &sa_serv, sizeof(sa_serv));
	CHK_ERR(err, "bind");
	trace_printf("Server bound to port %d\n", ntohs(sa_serv.sin_port));

	/* Receive a TCP connections. */

	while (1) {
		err = listen(listen_sd, 5);
		CHK_ERR(err, "listen");
		debug_printf("Server listening for connection requests on port %d\n",
				ntohs(sa_serv.sin_port));

		client_len = sizeof(sa_cli);
		sd = accept(listen_sd, (struct sockaddr*) &sa_cli, &client_len);
		CHK_ERR(sd, "accept");
		trace_println("Server accepted connection");

		// convert IP address to string
		inet_ntop(AF_INET, &(sa_cli.sin_addr.s_addr), addr_buf,
		INET_ADDRSTRLEN);
		// print IP and port
		debug_printf("Connection from %s, port %d\n", addr_buf,
				ntohs(sa_cli.sin_port));

		demo_println("Client connection");
		demo_println("Start negotiation of security parameters");

		/* ----------------------------------------------- */
		/* TCP connection is ready. */

		/* SSL preliminaries. We keep the certificate and key with the context. */
		/* This needs to be redone for every connection due to vtTLS stability issues. */

		SSL_load_error_strings();
		OpenSSL_add_ssl_algorithms();
		meth = TLSv1_2_method();

		ctx = SSL_CTX_new(meth);

		if (!ctx) {
			ERR_print_errors_fp(stderr);
			exit(2);
		}

		if (SSL_CTX_use_certificate_file(ctx, RSA_CERTF, SSL_FILETYPE_PEM)
				<= 0) {
			ERR_print_errors_fp(stderr);
			exit(3);
		}
		if (SSL_CTX_use_PrivateKey_file(ctx, RSA_KEYF, SSL_FILETYPE_PEM) <= 0) {
			ERR_print_errors_fp(stderr);
			exit(4);
		}

		if (!SSL_CTX_check_private_key(ctx)) {
			fprintf(stderr,
					"Private key does not match the certificate public key\n");
			exit(5);
		}

		if (SSL_CTX_use_n_certificate_file(DIVERSITY_FACTOR, ctx, ECDH_CERTF,
		SSL_FILETYPE_PEM) <= 0) {
			ERR_print_errors_fp(stderr);
			exit(3);
		}
		if (SSL_CTX_use_n_PrivateKey_file(DIVERSITY_FACTOR, ctx, ECDH_KEYF,
		SSL_FILETYPE_PEM) <= 0) {
			ERR_print_errors_fp(stderr);
			exit(4);
		}

		if (!SSL_CTX_check_n_private_key(DIVERSITY_FACTOR, ctx)) {
			fprintf(stderr,
					"Second private key does not match the certificate public key\n");
			exit(5);
		}

		/* Do server side SSL. */

		demo_println("Received list of ciphers supported by the client");
		demo_printf("Choosing %d ciphers\n", DIVERSITY_FACTOR);
		demo_printf("Sending %d different certificates", DIVERSITY_FACTOR);
		demo_println(", signed by different CAs");

		trace_println("creating SSL context");
		ssl = SSL_new(ctx);
		CHK_NULL(ssl, "ssl-ctx");
		SSL_set_fd(ssl, sd);

		trace_println("SSL accept");
		err = SSL_accept(ssl);
		CHK_SSL(err);

		demo_println("Negotiation concluded with success");
		demo_println("");

		/* Get the cipher - opt */

		const char* cipher1 = SSL_get_cipher(ssl);
		debug_printf("SSL connection using %s\n", cipher1);

		const char* cipher2 = SSL_get_n_cipher(DIVERSITY_FACTOR, ssl);
		debug_printf("SSL connection using %s\n", cipher2);

		/* Get client's certificate (note: beware of dynamic allocation) - opt */

		client_cert = SSL_get_peer_certificate(ssl);
		if (client_cert != NULL) {
			debug_println("Client certificate:");

			str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
			CHK_NULL(str, "x509-client-cert-subject");
			debug_printf("\t subject: %s\n", str);
			OPENSSL_free(str);

			str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
			CHK_NULL(str, "x509-client-cert-issuer");
			debug_printf("\t issuer: %s\n", str);
			OPENSSL_free(str);
			X509_free(client_cert);

		} else {
			debug_println("Client does not have certificate.");
		}

		/* ----------------------------------------------- */
		/* DATA EXCHANGE - Receive message and send reply. */

		demo_printf("Activate encryption layer 1 with %s\n", cipher1);
		demo_printf("Activate encryption layer 2 with %s\n", cipher2);

		/* REQUEST */

		// read file name line (result includes line break)
		err = readSSLLine(ssl, buf, BUF_SZ);
		CHK_SSL(err);
		// copy file name from work buffer, removing line break
		strncpy(file_name, buf, err - 1);
		file_name[err - 1] = '\0';
		debug_printf("Requested file name '%s'\n", file_name);
		demo_printf("Client requested %s\n", file_name);

		// read empty line separator
		err = readSSLLine(ssl, buf, BUF_SZ);
		CHK_SSL(err);

		// open file to read
		FILE *file;
		long file_len;

		// Open the file in binary mode
		file = fopen(file_name, "rb");
		//file = fopen("files/Tux.png", "rb");
		if (file == NULL) {
			demo_println("Client requested file that does not exist");
			debug_printf("fopen() error: %s\n", strerror(errno));
			// -1 means that the file does not exist
			file_len = -1;
		} else {
			debug_println("File open");
			fseek(file, 0, SEEK_END);	// Jump to the end of the file
			file_len = ftell(file);	// Get the current byte offset in the file
			rewind(file);			// Jump back to the beginning of the file
			debug_printf("File size is %ld\n", file_len);
		}

		/* RESPONSE */

		// write file size (as a string)
		sprintf(file_len_str, "%ld", file_len);
		err = SSL_write(ssl, file_len_str, strlen(file_len_str));
		// add end-of-line
		err = SSL_write(ssl, "\n", sizeof(char));
		trace_println("Wrote file size");

		// write empty line separator
		err = SSL_write(ssl, "\n", sizeof(char));
		trace_println("Wrote separator line");

		if (file_len > 0) {
			demo_print("Returning secure data to client");

			// write file to secure socket
			int bytesRead = 0;
			while (bytesRead < file_len) {
				int readResult = fread(buf, sizeof(char), BUF_SZ, file);
				CHK_ERR(readResult, "file");
				trace_printf("Read %d bytes from file\n", readResult);
				bytesRead += readResult;

				int writeResult = SSL_write(ssl, buf, readResult);
				CHK_SSL(writeResult);
				trace_printf("Wrote %d bytes to secure socket\n", writeResult);

				demo_print(".");
			}
			debug_println("Wrote all file bytes");
			// Close the file
			fclose(file);
			trace_println("File closed");
			demo_println("");
		}

		/* Clean up. */
		close(sd);
		debug_println("Client socket closed");

		demo_println("Transmission complete");
		demo_println("");
		demo_println("");

		SSL_free(ssl);
		SSL_CTX_free(ctx);
	}

	// this clean-up code is actually never reached
	// because the server is in an infinite loop
	close(listen_sd);
	debug_print("Server socket closed\n");

	return 0;
}
/* EOF - server.cpp */
