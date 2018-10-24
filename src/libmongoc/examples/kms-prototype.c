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

static void
print_without_carriage_return (uint8_t *buf, ssize_t n)
{
   ssize_t i;

   for (i = 0; i < n; i++) {
      if (buf[i] != '\r') {
         putchar (buf[i]);
      }
   }
}

static void
api_call (kms_request_t *request, mongoc_stream_t *tls_stream)
{
   char *sreq;
   size_t sreq_len;
   ssize_t n;
   uint8_t read_buf[64];
   kms_response_parser_t *parser = kms_response_parser_new ();
   int64_t start;
   const int32_t timeout_msec = 1000;

   /* TODO: CRLF endings? */
   sreq = kms_request_get_signed (request);
   sreq_len = strlen (sreq);
   printf ("%s\n", sreq);

   n = mongoc_stream_write (tls_stream, sreq, sreq_len, timeout_msec);

   if (n != (ssize_t) sreq_len) {
      fprintf (stderr,
               "Only wrote %zd of %zu bytes (errno: %d)\n",
               n,
               sreq_len,
               errno);
      perror ("");
      abort ();
   }

   start = bson_get_monotonic_time ();
   while (kms_response_parser_wants_bytes (parser, sizeof (read_buf))) {
      if (bson_get_monotonic_time () - start > timeout_msec * 1000) {
         fprintf (stderr, "Timed out reading response\n");
         abort ();
      }

      n = mongoc_stream_read (
         tls_stream, read_buf, sizeof (read_buf), 1, timeout_msec);
      if (n < 0) {
         fprintf (stderr, "Read returned %zd (errno: %d)\n", n, errno);
         perror ("");
         abort ();
      }

      if (n == 0) {
         break;
      }

      print_without_carriage_return (read_buf, n);
      kms_response_parser_feed (parser, read_buf, (uint32_t) n);
   }

   kms_response_parser_destroy (parser);
}

const char ciphertext_blob[] =
   "\x01\x02\x02\x00\x78\xf3\x8e\xd8\xd4\xc6\xba\xfb\xa1\xcf\xc1\x1e\x68\xf2"
   "\xa1\x91\x9e\x36\x4d\x74\xa2\xc4\x9e\x30\x67\x08\x53\x33\x0d\xcd\xe0\xc9"
   "\x1b\x01\x60\x30\xd4\x73\x9e\x90\x1f\xa7\x43\x55\x84\x26\xf9\xd5\xf0\xb1"
   "\x00\x00\x00\x64\x30\x62\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x06\xa0"
   "\x55\x30\x53\x02\x01\x00\x30\x4e\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07"
   "\x01\x30\x1e\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x2e\x30\x11\x04\x0c"
   "\xa2\xc7\x12\x1c\x25\x38\x0e\xec\x08\x1f\x23\x09\x02\x01\x10\x80\x21\x61"
   "\x03\xcd\xcb\xe2\xac\x36\x4f\x73\xdb\x1b\x73\x2e\x33\xda\x45\x51\xf4\xcd"
   "\xc0\xff\xd2\xe1\xb9\xc4\xc2\x0e\xbf\x53\x90\x46\x18\x42";

int
main (int argc, char *argv[])
{
   mongoc_ssl_opt_t ssl_opts = {0};
   kms_request_opt_t *request_opt;
   mongoc_stream_t *stream, *tls_stream;
   bson_error_t error;
   kms_request_t *request;

   if (argc != 3) {
      fprintf (stderr, "Usage: %s ACCESS-KEY-ID SECRET-ACCESS-KEY\n", argv[0]);
      return EXIT_FAILURE;
   }

   mongoc_init ();
   kms_message_init ();

   memcpy (&ssl_opts, mongoc_ssl_opt_get_default (), sizeof ssl_opts);
   stream = get_stream (443 /* https */);
   tls_stream = mongoc_stream_tls_new_with_hostname (
      stream, "kms.us-east-1.amazonaws.com", &ssl_opts, 1 /* client */);

   if (!mongoc_stream_tls_handshake_block (
          tls_stream, "kms.us-east-1.amazonaws.com", 1000, &error)) {
      fprintf (stderr, "Error in handshake: %s\n", error.message);
      abort ();
   }

   request_opt = kms_request_opt_new ();
   kms_request_opt_set_connection_close (request_opt, true);
   request = kms_encrypt_request_new ("foobar", "alias/1", request_opt);
   kms_request_set_region (request, "us-east-1");
   kms_request_set_service (request, "kms");
   kms_request_set_access_key_id (request, argv[1]);
   kms_request_set_secret_key (request, argv[2]);

   api_call (request, tls_stream);

   kms_request_destroy (request);


   stream = get_stream (443 /* https */);
   tls_stream = mongoc_stream_tls_new_with_hostname (
      stream, "kms.us-east-1.amazonaws.com", &ssl_opts, 1 /* client */);

   if (!mongoc_stream_tls_handshake_block (
          tls_stream, "kms.us-east-1.amazonaws.com", 1000, &error)) {
      fprintf (stderr, "Error in handshake: %s\n", error.message);
      abort ();
   }

   /* the ciphertext blob from a response to an "Encrypt" API call */
   /* the output is Base64-encoded, "Zm9vYmFy", which is "foobar" */
   request = kms_decrypt_request_new (
      (uint8_t *) ciphertext_blob, sizeof (ciphertext_blob) - 1, request_opt);
   kms_request_set_region (request, "us-east-1");
   kms_request_set_service (request, "kms");
   kms_request_set_access_key_id (request, argv[1]);
   kms_request_set_secret_key (request, argv[2]);

   api_call (request, tls_stream);

   kms_request_destroy (request);

   mongoc_cleanup ();
   kms_message_cleanup ();

   return EXIT_SUCCESS;
}
