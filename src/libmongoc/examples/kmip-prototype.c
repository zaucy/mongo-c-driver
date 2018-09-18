/* gcc kmip-prototype.c -o kmip-prototype $(pkg-config --cflags --libs
 * libmongoc-1.0 kmip_message) */

/* ./example-client [CONNECTION_STRING [COLLECTION_NAME]] */

#include <kmip_message/kmip_message.h>
#include <mongoc/mongoc.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define ERRNO_IS_AGAIN(errno)                                          \
   ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK) || \
    (errno == EINPROGRESS))

static mongoc_stream_t *
get_localhost_stream (uint16_t port)
{
   int errcode;
   int r;
   struct sockaddr_in server_addr = {0};
   mongoc_socket_t *conn_sock;

   conn_sock = mongoc_socket_new (AF_INET, SOCK_STREAM, 0);
   assert (conn_sock);

   server_addr.sin_family = AF_INET;
   server_addr.sin_port = htons (port);
   server_addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
   r = mongoc_socket_connect (
      conn_sock, (struct sockaddr *) &server_addr, sizeof (server_addr), -1);

   errcode = mongoc_socket_errno (conn_sock);
   if (!(r == 0 || ERRNO_IS_AGAIN (errcode))) {
      fprintf (stderr,
               "mongoc_socket_connect unexpected return: "
               "%d (errno: %d)\n",
               r,
               errcode);
      perror ("");
      abort ();
   }

   return mongoc_stream_socket_new (conn_sock);
}


int
main (int argc, char *argv[])
{
   const mongoc_ssl_opt_t *ssl_default = mongoc_ssl_opt_get_default ();
   mongoc_ssl_opt_t ssl_opts = {0};
   mongoc_stream_t *stream, *tls_stream;
   bson_error_t error;
   kmip_get_request_t *get_request;
   kmip_request_t *msg;
   const uint8_t *msg_data;
   uint32_t msg_len;
   ssize_t n;
   uint8_t read_buf[512];
   kmip_parser_t *parser;
   char *dump;

   /* optionally set custom trust dir or file; otherwise default is used. */
   memcpy (&ssl_opts, ssl_default, sizeof ssl_opts);
   ssl_opts.allow_invalid_hostname = true;
   ssl_opts.weak_cert_validation = true;
   ssl_opts.pem_file = "/etc/pykmip/certs/client.pem";
   ssl_opts.ca_file = "/etc/pykmip/certs/cert.pem";

   stream = get_localhost_stream (5696 /* default PyKMIP port */);
   tls_stream = mongoc_stream_tls_new_with_hostname (
      stream, "localhost", &ssl_opts, 1 /* client */);

   if (!mongoc_stream_tls_handshake_block (
          tls_stream, "localhost", 1000, &error)) {
      fprintf (stderr, "Error in handshake: %s\n", error.message);
      abort ();
   }

   get_request = kmip_get_request_new ();
   kmip_get_request_set_username (get_request, (uint8_t *) "", 0);
   kmip_get_request_set_password (get_request, (uint8_t *) "", 0);
   kmip_get_request_set_uid (get_request, (uint8_t *) "2", 1);
   msg = kmip_request_new ();
   if (!kmip_get_request_write (get_request, msg)) {
      fprintf (stderr,
               "KMIP message generator failed: %s\n",
               kmip_request_get_error (msg));
      abort ();
   }

   msg_data = kmip_request_get_data (msg, &msg_len);
   n = mongoc_stream_write (
      tls_stream, (void *) msg_data, (size_t) msg_len, 1000 /* timeout ms */);

   if (n != (ssize_t) msg_len) {
      fprintf (stderr,
               "Only wrote %zd of %" PRIu32 " bytes (errno: %d)\n",
               n,
               msg_len,
               errno);
      perror ("");
      abort ();
   }

   parser = kmip_parser_new ();

   while (kmip_parser_want_bytes (parser)) {
      n = mongoc_stream_read (tls_stream, read_buf, sizeof (read_buf), 1, 1000);
      if (n < 0) {
         fprintf (stderr,
                  "Only read %zd of %" PRIu32 " bytes (errno: %d)\n",
                  n,
                  msg_len,
                  errno);
         perror ("");
         abort ();
      }

      if (!kmip_parser_feed (parser, read_buf, (size_t) n)) {
         fprintf (
            stderr, "KMIP parser failed: %s\n", kmip_parser_get_error (parser));
         abort ();
      }
   }

   dump = kmip_parser_dump (parser);
   if (!dump) {
      fprintf (stderr,
               "kmip_parser_dump failed: %s\n",
               kmip_parser_get_error (parser));
      abort ();
   }

   printf ("%s\n", dump);
   free (dump);
   kmip_parser_destroy (parser);
   kmip_get_request_destroy (get_request);
   kmip_request_destroy (msg);

   return EXIT_SUCCESS;
}
