/* gcc kms-prototype.c -o kms-prototype $(pkg-config --cflags --libs
 * libmongoc-1.0 kms_message) */

/* ./example-client [CONNECTION_STRING [COLLECTION_NAME]] */

#include <kms_message/kms_message.h>
#include <mongoc/mongoc.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define ERRNO_IS_AGAIN(errno)                                          \
   ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK) || \
    (errno == EINPROGRESS))

static mongoc_stream_t *
get_stream (uint16_t port)
{
   int errcode;
   int r;
   struct sockaddr_in server_addr = {0};
   mongoc_socket_t *conn_sock;

   conn_sock = mongoc_socket_new (AF_INET, SOCK_STREAM, 0);
   assert (conn_sock);

   server_addr.sin_family = AF_INET;
   server_addr.sin_port = htons (port);
   /* 54.239.18.135, kms.us-east-1.amazonaws.com */
   server_addr.sin_addr.s_addr = htonl (0x36EF1287);
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
   mongoc_ssl_opt_t ssl_opts = {0};
   mongoc_stream_t *stream, *tls_stream;
   bson_error_t error;
   kms_request_t *request;
   const char *body;
   char *sreq;
   size_t sreq_len;
   ssize_t n;
   uint8_t read_buf[512];

   if (argc != 3) {
      fprintf (stderr, "Usage: %s ACCESS-KEY-ID SECRET-ACCESS-KEY\n", argv[0]);
      return EXIT_FAILURE;
   }

   memcpy (&ssl_opts, mongoc_ssl_opt_get_default (), sizeof ssl_opts);
   stream = get_stream (443 /* https */);
   tls_stream = mongoc_stream_tls_new_with_hostname (
      stream, "kms.us-east-1.amazonaws.com", &ssl_opts, 1 /* client */);

   if (!mongoc_stream_tls_handshake_block (
          tls_stream, "kms.us-east-1.amazonaws.com", 1000, &error)) {
      fprintf (stderr, "Error in handshake: %s\n", error.message);
      abort ();
   }

   request = kms_request_new ("POST", "/");
   kms_request_set_region (request, "us-east-1");
   kms_request_set_service (request, "kms");
   kms_request_set_access_key_id (request, argv[1]);
   kms_request_set_secret_key (request, argv[2]);

   /* TODO: set these automatically */
   kms_request_add_header_field (request, "Content-Type", "application/x-amz-json-1.1");
   kms_request_add_header_field (request, "Content-Length", "41");
   kms_request_add_header_field (request, "X-Amz-Target", "TrentService.Encrypt");

   /* TODO: connection: close fails signature test */
   //kms_request_add_header_field (request, "Connection", "keep-alive");
   //kms_request_add_header_field (request, "Connection", "close");

   /* TODO: auto base64 encode and decode */
   body = "{\"Plaintext\": \"Zm9v\", \"KeyId\": \"alias/1\"}";
   assert (strlen (body) == 41);
   kms_request_append_payload (request, body, strlen (body));

   /* TODO: CRLF endings? */
   sreq = kms_request_get_signed (request);
   sreq_len = strlen (sreq);
   printf ("%s\n", sreq);

   n = mongoc_stream_write (
      tls_stream, sreq, sreq_len, 1000 /* timeout ms */);

   if (n != (ssize_t) sreq_len) {
      fprintf (stderr,
               "Only wrote %zd of %zu bytes (errno: %d)\n",
               n,
               sreq_len,
               errno);
      perror ("");
      abort ();
   }

   /* TODO: write a KMS reply parser */
   while (true) {
      n = mongoc_stream_read (tls_stream, read_buf, sizeof (read_buf), 1, 1000);
      if (n < 0) {
         fprintf (stderr,
                  "Only read %zd bytes (errno: %d)\n",
                  n,
                  errno);
         perror ("");
         break;
         abort ();
      }

      if (n == 0) {
         break;
      }

      fwrite (read_buf, 1, (size_t) n, stdout);
   }

   kms_request_destroy (request);
   return EXIT_SUCCESS;
}
