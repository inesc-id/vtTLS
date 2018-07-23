/* This example code is placed in the public domain. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include <sys/time.h>
#include <unistd.h>


/* A very basic Datagram TLS client, over UDP with X.509 authentication.
 */

#define CHECK(x) assert((x)>=0)

#define CHK_RECV(x) assert((x)>0)

#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }

#define MAX_BUF 1024
#define CAFILE "certs/x509-ca.pem"

extern int udp_connect(void);
extern void udp_close(int sd);
extern int verify_certificate_callback(gnutls_session_t session);

int main(int argc, char* argv[])
{
        int ret, sd, ii, bytesDownloaded;
        gnutls_session_t session;
        gnutls_certificate_credentials_t xcred;
	const char *file_to_download;
	const char *file_to_save;
        char buffer[MAX_BUF];
	int mtu = 1500;

	file_to_download = argv[1];
	file_to_save = argv[2];

	/* for performance measurements */
	struct timeval start, end;
	unsigned long long diff;

        if (gnutls_check_version("3.1.4") == NULL) {
                fprintf(stderr, "GnuTLS 3.1.4 or later is required for this example\n");
                exit(1);
        }

        /* for backwards compatibility with gnutls < 3.3.0 */
        CHECK(gnutls_global_init());

        /* X509 stuff */
        CHECK(gnutls_certificate_allocate_credentials(&xcred));

        /* sets the trusted cas file */
        CHECK(gnutls_certificate_set_x509_trust_file(xcred, CAFILE,
                                                     GNUTLS_X509_FMT_PEM));

        /* Initialize TLS session */
        CHECK(gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_DATAGRAM));

        /* Use default priorities */
        CHECK(gnutls_set_default_priority(session));

        /* put the x509 credentials to the current session */
        CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred));
        CHECK(gnutls_server_name_set(session, GNUTLS_NAME_DNS, "test.gnutls.org",
                                     strlen("test.gnutls.org")));

        gnutls_session_set_verify_cert(session, "test.gnutls.org", 0);

        /* connect to the peer */
        sd = udp_connect();

        gnutls_transport_set_int(session, sd);

        /* set the connection MTU */
        gnutls_dtls_set_mtu(session, mtu);
        //gnutls_dtls_set_timeouts(session, 1000, 60000);

        /* Perform the TLS handshake */
        do {
                ret = gnutls_handshake(session);
        }
        while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);
        /* Note that DTLS may also receive GNUTLS_E_LARGE_PACKET */

        if (ret < 0) {
                fprintf(stderr, "*** Handshake failed\n");
                gnutls_perror(ret);
                goto end;
        } else {
                char *desc;

                desc = gnutls_session_get_desc(session);
                printf("- Session info: %s\n", desc);
                gnutls_free(desc);
        }

	/* ----------------------------------------------- */
	/* ---------------- DATA EXCHANGE ---------------- */
	/* ----------------------------------------------- */


	/* REQUEST */

	// send file name to server to request it
	ret = gnutls_record_send(session, file_to_download, strlen(file_to_download));
	CHECK(ret);

	// add end-of-line
	ret = gnutls_record_send(session, "\n", sizeof(char));
	CHECK(ret);

	// send empty line separator
	ret = gnutls_record_send(session, "\n", sizeof(char));
	CHECK(ret);

	/* RESPONSE */

	// read file size (as a string)
	ret = gnutls_record_recv(session, buffer, MAX_BUF);
	CHECK(ret);
	const int bytesToDownload = atoi(buffer);
	if (bytesToDownload < 0) {
		printf("File not found on server!\n");
	} else {
		printf("%d bytes to download\n", bytesToDownload);
		printf("Receiving secure response data from server\n");
	}

	// read empty line separator
	ret = gnutls_record_recv(session, buffer, MAX_BUF);
	CHECK(ret);

	if (bytesToDownload >= 0) {
		// open file to save
		FILE *file_rcv = fopen(file_to_save, "wb+");

		if (bytesToDownload > 0) {
			// read until all expected bytes are received
			bytesDownloaded = 0;

			gettimeofday(&start, NULL);
			while (bytesDownloaded < bytesToDownload) {
				int readResult = gnutls_record_recv(session, buffer, MAX_BUF);
				if (readResult == 0) {
					printf("- Peer has closed the TLS connection\n");
					goto end;
				} else if (readResult < 0 && gnutls_error_is_fatal(readResult) == 0) {
					fprintf(stderr, "*** Warning: %s\n", gnutls_strerror(ret));
				} else if (readResult < 0) {
					fprintf(stderr, "*** Error: %s\n", gnutls_strerror(ret));
					goto end;
        			}
				
				bytesDownloaded += readResult;

				// write bytes to open file
				size_t writeResult = fwrite(buffer, sizeof(char), readResult, file_rcv);
				CHK_ERR(writeResult, "file");
			}
			gettimeofday(&end, NULL);
			diff = 1000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000;
			printf("multiTLS with DTLS took %llu ms to transfer and save %d bytes.\n", diff, bytesDownloaded);
			printf("Read all expected bytes");
		}
		// close file
		fclose(file_rcv);
	}

        /* It is suggested not to use GNUTLS_SHUT_RDWR in DTLS
         * connections because the peer's closure message might
         * be lost */
        CHECK(gnutls_bye(session, GNUTLS_SHUT_WR));
	
      end:
	gettimeofday(&end, NULL);
	diff = 1000 * (end.tv_sec - start.tv_sec) + 
			(end.tv_usec - start.tv_usec) / 1000;
	printf("multiTLS with DTLS took %llu ms to transfer and save %d bytes.\n", 
								diff, bytesDownloaded);
        udp_close(sd);

        gnutls_deinit(session);

        gnutls_certificate_free_credentials(xcred);

        gnutls_global_deinit();

        return 0;
}
