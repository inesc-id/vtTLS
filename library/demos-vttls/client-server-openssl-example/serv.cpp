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

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <string>

/* define HOME to be dir for key and cert files... */
#define HOME "./"
/* Make these what you want for cert & key files */

/*ECDHE-ECDSA*/
#define ECDH_CERTF  "server-ecdhe-cert.crt"
#define ECDH_KEYF   "server-ecdhe-key.pem"

#define MAX_MSG_SIZE 16250

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

int main (int argc, char* argv[])
{
  int       err;
  int       listen_sd;
  int       sd;
  struct sockaddr_in sa_serv;
  struct sockaddr_in sa_cli;
  socklen_t    client_len;
  SSL_CTX*  ctx;
  SSL*      ssl;
  X509*     client_cert;
  char*     str;
  char      buf [4096];
  SSL_METHOD const *meth;
  unsigned long long diff;
  timeval start, end;
  
  /* SSL preliminaries. We keep the certificate and key with the context. */

  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
  meth = TLSv1_2_method();
  
  ctx = SSL_CTX_new (meth);
  
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
    fprintf(stderr,"Private key does not match the certificate public key\n");
    exit(5);
  }

  /* ----------------------------------------------- */
  /* Prepare TCP socket for receiving connections */

  listen_sd = socket (AF_INET, SOCK_STREAM, 0);   CHK_ERR(listen_sd, "socket");
  
  memset(&sa_serv, 0, sizeof(sa_serv));
  sa_serv.sin_family      = AF_INET;
  sa_serv.sin_addr.s_addr = INADDR_ANY;
  sa_serv.sin_port        = htons (1111);          /* Server Port number */
  
  err = bind(listen_sd, (struct sockaddr*) &sa_serv,
	     sizeof (sa_serv));                   CHK_ERR(err, "bind");
	     
  /* Receive a TCP connection. */
	     
  err = listen (listen_sd, 5);                    CHK_ERR(err, "listen");
  
  client_len = sizeof(sa_cli);
  sd = accept (listen_sd, (struct sockaddr*) &sa_cli, &client_len);
  CHK_ERR(sd, "accept");
  close (listen_sd);

  /*printf ("Connection from %lx, port %x\n",
	  sa_cli.sin_addr.s_addr, sa_cli.sin_port);*/
  
  /* ----------------------------------------------- */
  /* TCP connection is ready. Do server side SSL. */

  ssl = SSL_new (ctx);                           CHK_NULL(ssl);     /* CHECKED */
  SSL_set_fd (ssl, sd);
  
  err = SSL_accept (ssl);                        CHK_SSL(err);      /* CHECKED */
  
  /* Get the cipher - opt */
  
  // printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
  
  /* DATA EXCHANGE - Receive message and send reply. */
    
  err = SSL_read (ssl, buf, sizeof(buf) - 1);                   CHK_SSL(err);
  buf[err] = '\0';
  // printf ("Got %d chars:'%s'\n", err, buf);
  
  FILE *file;
  char *buffer;
  long file_len;

  file = fopen(buf, "rb");	// Open the file in binary mode
  fseek(file, 0, SEEK_END);	// Jump to the end of the file
  file_len = ftell(file);	// Get the current byte offset in the file
  rewind(file);			// Jump back to the beginning of the file

  buffer = (char *)malloc((file_len+1)*sizeof(char));	// Enough memory for file + \0
  fread(buffer, file_len, 1, file);                	// Read in the entire file
  buffer[file_len] = '\0';
  fclose(file);                                   	// Close the file
      
  char filelen[512];
  sprintf(filelen, "%d", file_len);
    
  err = SSL_write (ssl, filelen, strlen(filelen));
  
  int counter = 0;
  
  //for (counter = 0; counter < 100; counter++){
    /*********************/
    err = 0;
    int i = file_len;
    
    gettimeofday(&start, NULL);

    for(i = file_len; i - MAX_MSG_SIZE > 0; i -= MAX_MSG_SIZE){
      err += SSL_write (ssl, buffer+err, MAX_MSG_SIZE);
    }
    
    err += SSL_write (ssl, buffer+err, i);

    gettimeofday(&end, NULL);
    diff = 1000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000;
    printf("%llu\n", diff);
    // printf ("The OpenSSL Handshake took %llu ms\n", diff);
    diff = 0;
    /*********************/
  //}

  
  // printf("total_size: %d\n", err);
    
  /* Clean up. */

  free(buffer);
  
  close (sd);
  SSL_free (ssl);
  SSL_CTX_free (ctx);
  
  return 0;
  
}
/* EOF - serv.cpp */