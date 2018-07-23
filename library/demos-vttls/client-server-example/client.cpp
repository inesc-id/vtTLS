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

#include "read_line.h"

#include "debug.h"
#include "demo.h"

/* define HOME to be dir for key and cert files... */
#define HOME "./"

#define DIVERSITY_FACTOR 2

// Error checking
#define CHK_NULL(x,s) if ((x)==NULL) { fprintf(stderr, "%s null\n", s); exit (1); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

// Buffer settings
#define BUF_SZ 8 * 1024

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

	/* for performance measurements */
	unsigned long long diff;

	/* arguments */
	const char *ip;
	unsigned int port;
	const char *file_to_download;
	const char *file_to_save;

	/* Arguments validation */
	if (argc != 5) {
		printf("Usage: ./client <server-ip> <server-port> <file-to-download> <file-to-save>\n");
		exit(0);
	}
	ip = argv[1];
	port = atoi(argv[2]);

	file_to_download = argv[3];
	file_to_save = argv[4];
	debug_printf("Arguments: IP %s Port %u File to download '%s' File to save '%s'\n",
		     ip, port, file_to_download, file_to_save);

	debug_printf("Work buffer size %d bytes\n", BUF_SZ);

	/* SSL initialization */

	SSL_load_error_strings();
	/* SSL_library_init() */
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

	demo_printf("Connect to server at %s\n", ip);

	err = connect(sd, (struct sockaddr*) &sa, sizeof(sa));
	CHK_ERR(err, "connect");
	debug_println("Connected to server");


	/* -------------------------------------------------- */
	/* Now we have TCP connection. Start SSL negotiation. */

	demo_println("Start negotiation of security parameters");
	demo_println("Send list of supported ciphers");

	trace_println("create SSL context");
	ssl = SSL_new(ctx);
	CHK_NULL(ssl, "ssl-ctx");

	SSL_set_fd(ssl, sd);
	/* Sets the file descriptor fd as the input/output
	 * facility for the TLS encrypted side
	 * of argument "ssl"; fd is usually the socket descriptor */

	trace_println("SSL connect");
	gettimeofday(&start, NULL);
	err = SSL_connect(ssl);
	CHK_SSL(err);

	gettimeofday(&end, NULL);
	diff = 1000 * (end.tv_sec - start.tv_sec)
			+ (end.tv_usec - start.tv_usec) / 1000;
	debug_printf("The vtTLS Handshake took %llu ms\n", diff);

	/* ssl->method->ssl_connect(s)*/

	/* Following two steps are optional and not required for
	 data exchange to be successful. */

	/* Get the cipher - opt */

	const char* cipher1 = SSL_get_cipher(ssl);
	debug_printf("SSL connection using %s\n", cipher1);

	const char* cipher2 = SSL_get_n_cipher(DIVERSITY_FACTOR, ssl);
	debug_printf("SSL connection using %s\n", cipher2);


	/* Get server's certificate (note: beware of dynamic allocation) - opt */

	server_cert = SSL_get_peer_certificate(ssl);
	CHK_NULL(server_cert, "server-cert");

	server_sec_cert = SSL_get_n_peer_certificate(DIVERSITY_FACTOR, ssl);
	CHK_NULL(server_sec_cert, "server-cert-2");

	debug_println("Server certificate:");

	str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
	CHK_NULL(str, "x509-subject-name");
	debug_printf("\t subject: %s\n", str);
	OPENSSL_free(str);

	str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
	CHK_NULL(str, "x509-issuer-name");
	debug_printf("\t issuer: %s\n", str);
	OPENSSL_free(str);

	debug_println("Server second certificate:");

	str = X509_NAME_oneline(X509_get_subject_name(server_sec_cert), 0, 0);
	CHK_NULL(str, "x509-subject-name-2");
	debug_printf("\t subject: %s\n", str);
	OPENSSL_free(str);

	str = X509_NAME_oneline(X509_get_issuer_name(server_sec_cert), 0, 0);
	CHK_NULL(str, "x509-issuer-name-2");
	debug_printf("\t issuer: %s\n", str);
	OPENSSL_free(str);

	/* We could do all sorts of certificate verification stuff here before
	 deallocating the certificate. */

	X509_free(server_cert);
	X509_free(server_sec_cert);

	demo_printf("Server presented %d certificates", DIVERSITY_FACTOR);
	demo_println(", signed by different CAs");

	demo_printf("Server chose %d crypto protections\n", DIVERSITY_FACTOR);
	demo_println("Negotiation complete");
	demo_println("");

	demo_printf("Activate encryption layer 1 with %s\n", cipher1);
	demo_printf("Activate encryption layer 2 with %s\n", cipher2);

	demo_println("Send secure request to server");


	/* --------------------------------------------------- */
	/* DATA EXCHANGE - Send a message and receive a reply. */

	/* REQUEST */

	// send file name to server to request it
	err = SSL_write(ssl, file_to_download, strlen(file_to_download));
	CHK_SSL(err);
	// add end-of-line
	err = SSL_write(ssl, "\n", sizeof(char));
	CHK_SSL(err);

	// send empty line separator
	err = SSL_write(ssl, "\n", sizeof(char));
	CHK_SSL(err);

	/* RESPONSE */

	// read file size (as a string)
	err = readSSLLine(ssl, buf, BUF_SZ);
	CHK_SSL(err);
	const int bytesToDownload = atoi(buf);
	if (bytesToDownload < 0) {
		printf("File not found on server!\n");
	} else {
		debug_printf("%d bytes to download\n", bytesToDownload);
		demo_print("Receiving secure response data from server");
	}

	// read empty line separator
	err = readSSLLine(ssl, buf, BUF_SZ);
	CHK_SSL(err);

	if (bytesToDownload >= 0) {
		// open file to save
		FILE *file_rcv = fopen(file_to_save, "wb+");

		if (bytesToDownload > 0) {
			// read until all expected bytes are received
			int bytesDownloaded = 0;
			gettimeofday(&start, NULL);
			while (bytesDownloaded < bytesToDownload) {
				int readResult = SSL_read(ssl, buf, BUF_SZ);
				CHK_SSL(readResult);
				trace_printf("Read %d bytes from secure socket\n", readResult);
				bytesDownloaded += readResult;
				// write bytes to open file
				size_t writeResult = fwrite(buf, sizeof(char), readResult,
						file_rcv);
				CHK_ERR(writeResult, "file");
				trace_printf("Wrote %lu bytes to file\n", writeResult);

				demo_print(".");
			}
			gettimeofday(&end, NULL);
			diff = 1000 * (end.tv_sec - start.tv_sec)
					+ (end.tv_usec - start.tv_usec) / 1000;
			debug_printf("vtTLS took %llu ms to transfer and save %d bytes.\n",
					diff, bytesDownloaded);
			debug_println("Read all expected bytes");
		}
		// close file
		fclose(file_rcv);
		trace_println("File closed");
		demo_println("");
	}

	/* send SSL/TLS close_notify */
	SSL_shutdown(ssl);

	/* Clean up. */
	close(sd);
	debug_println("Socket closed");

	demo_println("Transmission complete");
	demo_println("");
	if (bytesToDownload > 0)
		demo_open_file(file_to_save);

	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;
}
/* EOF - client.cpp */
