#include "mongoc-config.h"

#include "mongoc-connection-pool-private.h"

mongoc_server_stream_t *
mongoc_checkout_connection (mongoc_connection_pool_t *connection_pool,
                            bson_error_t *error)
{
   mongoc_stream_t *stream;
   mongoc_topology_t *topology;
   uint32_t server_id;
   mongoc_host_list_t *host = NULL;
   mongoc_server_stream_t *server_stream;
   mongoc_server_description_t *sd;

   bson_mutex_lock (&connection_pool->mutex);
   server_id = connection_pool->server_id;
   topology = connection_pool->topology;

   sd = mongoc_topology_description_server_by_id (
         &topology->description, server_id, error);
again:
   if (_mongoc_queue_get_length (connection_pool->queue)) {
      server_stream = _mongoc_queue_pop_head (connection_pool->queue);
   }
   else if (connection_pool->size < topology->max_connection_pool_size) {
      connection_pool->size++;
      bson_mutex_unlock (&connection_pool->mutex);
      host =
         _mongoc_topology_host_by_id (topology, server_id, error);
      stream = mongoc_client_connect_tcp (topology->connect_timeout_msec, host, error);
      if (!stream) {
         return NULL;
      }
      server_stream = mongoc_server_stream_new (&topology->description, sd, stream);
      server_stream->server_id = server_id;
      bson_mutex_lock (&connection_pool->mutex);
      server_stream->connection_id = ++connection_pool->max_id;
   }
   else {
      mongoc_cond_wait (&connection_pool->cond, &connection_pool->mutex);
      goto again;
   }
   bson_mutex_unlock (&connection_pool->mutex);
   return server_stream;
}

void
mongoc_checkin_connection (mongoc_connection_pool_t *connection_pool,
                           mongoc_server_stream_t *server_stream)
{
   bson_mutex_lock (&connection_pool->mutex);
   _mongoc_queue_push_head (connection_pool->queue, server_stream);
   mongoc_cond_signal (&connection_pool->cond);
   bson_mutex_unlock (&connection_pool->mutex);
}

mongoc_connection_pool_t *
mongoc_connection_pool_new (mongoc_topology_t *topology,
                            mongoc_server_description_t *sd)
{
   mongoc_connection_pool_t *new_pool =
      bson_malloc0 (sizeof (mongoc_connection_pool_t));
   new_pool->server_id = sd->id;
   new_pool->max_id = 0;
   new_pool->topology = topology;
   bson_mutex_init (&new_pool->mutex);
   mongoc_cond_init (&new_pool->cond);
   new_pool->queue = bson_malloc (sizeof (mongoc_queue_t));
   _mongoc_queue_init (new_pool->queue);
   return new_pool;
}

bool
mongoc_connection_pool_close (mongoc_connection_pool_t *pool)
{
   mongoc_queue_t *queue = pool->queue;
   mongoc_server_stream_t *curr;
   bson_mutex_lock (&pool->mutex);
   while ((curr = _mongoc_queue_pop_head (queue))) {
      mongoc_stream_close (curr->stream);
      mongoc_server_stream_cleanup (curr);
   }
   bson_mutex_unlock (&pool->mutex);
}

