
#include "mongoc-prelude.h"

#ifndef MONGO_C_DRIVER_MONGOC_CONNECTION_POOL_PRIVATE_H
#define MONGO_C_DRIVER_MONGOC_CONNECTION_POOL_PRIVATE_H

#include "mongoc-config.h"
#include "mongoc-topology-private.h"
#include "mongoc-queue-private.h"
#include "mongoc-topology-scanner-private.h"
#include "mongoc-server-description-private.h"
#include "mongoc-topology-description-private.h"
#include "mongoc-thread-private.h"
#include "mongoc-uri.h"
#include "mongoc-client-session-private.h"
#include "mongoc-crypt-private.h"
#include "mongoc-client-private.h"
#include "utlist.h"

typedef struct _mongoc_connection_pool_t {
   int total_connections;
   int available_connections;
   int generation;
   int server_id;
   int max_id;
   mongoc_queue_t *cond_queue;
   mongoc_queue_t *queue;
   bson_mutex_t mutex;
   mongoc_topology_t *topology;
} mongoc_connection_pool_t ;

mongoc_server_stream_t *
mongoc_checkout_connection (mongoc_connection_pool_t *connection_pool,
                            bson_error_t *error);

void
mongoc_checkin_connection (mongoc_connection_pool_t *connection_pool,
                            mongoc_server_stream_t *server_stream);

mongoc_connection_pool_t *
mongoc_connection_pool_new (mongoc_topology_t *topology,
                            mongoc_server_description_t *sd);


void
mongoc_connection_pool_close (mongoc_connection_pool_t *);

void
mongoc_connection_pool_destroy (mongoc_connection_pool_t *pool);

#endif // MONGO_C_DRIVER_MONGOC_CONNECTION_POOL_PRIVATE_H
