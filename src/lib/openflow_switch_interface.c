/*
 * Author: Yasunobu Chiba
 *
 * Copyright (C) 2008-2013 NEC Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#include <assert.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <syslog.h>
#include "hash_table.h"
#include "log.h"
#include "messenger.h"
#include "openflow_message.h"
#include "openflow_service_interface.h"
#include "openflow_switch_interface.h"
#include "safe_timer.h"
#include "secure_channel.h"
#include "wrapper.h"


#ifdef UNIT_TESTING

#define static

#ifdef send_message_to_secure_channel
#undef send_message_to_secure_channel
#endif
#define send_message_to_secure_channel mock_send_message_to_secure_channel
bool mock_send_message_to_secure_channel( buffer *message );

#ifdef send_message
#undef send_message
#endif
#define send_message mock_send_message
bool mock_send_message( const char *service_name, const uint16_t tag, const void *data, size_t len );

#ifdef init_secure_channel
#undef init_secure_channel
#endif
#define init_secure_channel mock_init_secure_channel
bool mock_init_secure_channel( uint32_t ip, uint16_t port,
                               connected_handler connected_callback, disconnected_handler disconnected_callback );

#ifdef add_periodic_event_callback
#undef add_periodic_event_callback
#endif
#define add_periodic_event_callback mock_add_periodic_event_callback
bool mock_add_periodic_event_callback( const time_t seconds, timer_callback callback, void *user_data );

#ifdef finalize_secure_channel
#undef finalize_secure_channel
#endif
#define finalize_secure_channel mock_finalize_secure_channel
bool mock_finalize_secure_channel();

#ifdef delete_timer_event
#undef delete_timer_event
#endif
#define delete_timer_event mock_delete_timer_event
bool mock_delete_timer_event( timer_callback callback, void *user_data );

#ifdef add_message_received_callback
#undef add_message_received_callback
#endif
#define add_message_received_callback mock_add_message_received_callback
bool mock_add_message_received_callback( const char *service_name,
                                         void ( *callback )( uint16_t tag, void *data, size_t len ) );

#ifdef getpid
#undef getpid
#endif
#define getpid mock_getpid
pid_t mock_getpid( void );

#ifdef debug
#undef debug
#endif
#define debug mock_debug
extern void mock_debug( const char *format, ... );

#ifdef error
#undef error
#endif
#define error mock_error
extern void mock_error( const char *format, ... );

#endif // UNIT_TESTING


typedef struct {
  uint64_t datapath_id;
  struct {
    uint32_t ip;
    uint16_t port;
  } controller;
} openflow_switch_config;

typedef bool ( *message_send_handler )( buffer *message, void *user_data );

typedef struct {
  uint32_t transaction_id;
  buffer *message;
  message_send_handler send_callback;
  void *user_data;
  time_t created_at;
} openflow_context;


static bool openflow_switch_interface_initialized = false;
static openflow_switch_event_handlers event_handlers;
static openflow_switch_config config;
static const int CONTEXT_LIFETIME = 5;
static hash_table *contexts = NULL;


static bool
compare_context( const void *x, const void *y ) {
  const openflow_context *cx = x;
  const openflow_context *cy = y;

  return ( cx->transaction_id == cy->transaction_id ) ? true : false;
}


static unsigned int
hash_context( const void *key ) {
  return ( unsigned int ) *( ( const uint32_t * ) key );
}


static openflow_context *
lookup_context( uint32_t transaction_id ) {
  assert( contexts != NULL );

  return lookup_hash_entry( contexts, &transaction_id );
}


static bool
save_context( uint32_t transaction_id, buffer *message, message_send_handler callback, void *user_data ) {
  assert( contexts != NULL );

  openflow_context *context = lookup_context( transaction_id );
  if ( context != NULL ) {
    return false;
  }

  context = xmalloc( sizeof( openflow_context ) );
  memset( context, 0, sizeof( openflow_context ) );
  context->transaction_id = transaction_id;
  context->message = duplicate_buffer( message );
  context->send_callback = callback;
  context->user_data = user_data;
  context->created_at = time( NULL );

  insert_hash_entry( contexts, &context->transaction_id, context );

  return true;
}


static void
delete_context( uint32_t transaction_id ) {
  assert( contexts != NULL );

  openflow_context *context = delete_hash_entry( contexts, &transaction_id );
  if ( context == NULL ) {
    return;
  }

  if ( context->message != NULL ) {
    free_buffer( context->message );
  }
  if ( context->user_data != NULL ) {
    xfree( context->user_data );
  }

  xfree( context );
}


static void
age_contexts( void *user_data ) {
  UNUSED( user_data );

  time_t now = time( NULL );

  hash_iterator iter;
  init_hash_iterator( contexts, &iter );
  hash_entry *e = NULL;
  while ( ( e = iterate_hash_next( &iter ) ) != NULL ) {
    openflow_context *context = e->value;
    if ( ( context != NULL ) && ( ( context->created_at + CONTEXT_LIFETIME ) <= now ) ) {
      delete_context( context->transaction_id );
    }
  }
}


static void
init_context() {
  assert( contexts == NULL );

  contexts = create_hash_with_size( compare_context, hash_context, 128 );
}


static void
finalize_context() {
  assert( contexts != NULL );

  hash_iterator iter;
  init_hash_iterator( contexts, &iter );
  hash_entry *e = NULL;
  while ( ( e = iterate_hash_next( &iter ) ) != NULL ) {
    openflow_context *context = e->value;
    if ( context != NULL ) {
      delete_context( context->transaction_id );
    }
  }
  delete_hash( contexts );
  contexts = NULL;
}


bool
openflow_switch_interface_is_initialized() {
  return openflow_switch_interface_initialized;
}


bool
set_openflow_switch_event_handlers( const openflow_switch_event_handlers handlers ) {
  assert( openflow_switch_interface_initialized );

  memcpy( &event_handlers, &handlers, sizeof( event_handlers ) );

  return true;
}


bool
set_controller_connected_handler( controller_connected_handler callback, void *user_data ) {
  assert( callback != NULL );
  assert( openflow_switch_interface_initialized );

  debug( "Setting a controller connected handler ( callback = %p, user_data = %p ).", callback, user_data );

  event_handlers.controller_connected_callback = callback;
  event_handlers.controller_connected_user_data = user_data;

  return true;
}


bool
set_controller_disconnected_handler( controller_disconnected_handler callback, void *user_data ) {
  assert( callback != NULL );
  assert( openflow_switch_interface_initialized );

  debug( "Setting a controller disconnected handler ( callback = %p, user_data = %p ).", callback, user_data );

  event_handlers.controller_disconnected_callback = callback;
  event_handlers.controller_disconnected_user_data = user_data;

  return true;
}


bool
set_hello_handler( hello_handler callback, void *user_data ) {
  assert( callback != NULL );
  assert( openflow_switch_interface_initialized );

  debug( "Setting a hello handler ( callback = %p, user_data = %p ).", callback, user_data );

  event_handlers.hello_callback = callback;
  event_handlers.hello_user_data = user_data;

  return true;
}


bool
switch_set_error_handler( switch_error_handler callback, void *user_data ) {
  assert( callback != NULL );
  assert( openflow_switch_interface_initialized );

  debug( "Setting an error handler ( callback = %p, user_data = %p ).", callback, user_data );

  event_handlers.error_callback = callback;
  event_handlers.error_user_data = user_data;

  return true;
}


bool
switch_set_experimenter_error_handler( switch_experimenter_error_handler callback, void *user_data ) {
  assert( callback != NULL );
  assert( openflow_switch_interface_initialized );

  debug( "Setting an experimenter error handler ( callback = %p, user_data = %p ).", callback, user_data );

  event_handlers.experimenter_error_callback = callback;
  event_handlers.experimenter_error_user_data = user_data;

  return true;
}


bool
set_echo_request_handler( echo_request_handler callback, void *user_data ) {
  assert( callback != NULL );
  assert( openflow_switch_interface_initialized );

  debug( "Setting an echo request handler ( callback = %p, user_data = %p ).", callback, user_data );

  event_handlers.echo_request_callback = callback;
  event_handlers.echo_request_user_data = user_data;

  return true;
}


bool
switch_set_echo_reply_handler( switch_echo_reply_handler callback, void *user_data ) {
  assert( callback != NULL );
  assert( openflow_switch_interface_initialized );

  debug( "Setting an echo reply handler ( callback = %p, user_data = %p ).", callback, user_data );

  event_handlers.echo_reply_callback = callback;
  event_handlers.echo_reply_user_data = user_data;

  return true;
}


bool
switch_set_experimenter_handler( switch_experimenter_handler callback, void *user_data ) {
  assert( callback != NULL );
  assert( openflow_switch_interface_initialized );

  debug( "Setting a experimenter handler ( callback = %p, user_data = %p ).", callback, user_data );

  event_handlers.experimenter_callback = callback;
  event_handlers.experimenter_user_data = user_data;

  return true;
}


bool
set_features_request_handler( features_request_handler callback, void *user_data ) {
  assert( callback != NULL );
  assert( openflow_switch_interface_initialized );

  debug( "Setting a features request handler ( callback = %p, user_data = %p ).", callback, user_data );

  event_handlers.features_request_callback = callback;
  event_handlers.features_request_user_data = user_data;

  return true;
}


bool
set_get_config_request_handler( get_config_request_handler callback, void *user_data ) {
  assert( callback != NULL );
  assert( openflow_switch_interface_initialized );

  debug( "Setting a get config request handler ( callback = %p, user_data = %p ).", callback, user_data );

  event_handlers.get_config_request_callback = callback;
  event_handlers.get_config_request_user_data = user_data;

  return true;
}


bool
set_set_config_handler( set_config_handler callback, void *user_data ) {
  assert( callback != NULL );
  assert( openflow_switch_interface_initialized );

  debug( "Setting a set config handler ( callback = %p, user_data = %p ).", callback, user_data );

  event_handlers.set_config_callback = callback;
  event_handlers.set_config_user_data = user_data;

  return true;
}


bool
set_packet_out_handler( packet_out_handler callback, void *user_data ) {
  assert( callback != NULL );
  assert( openflow_switch_interface_initialized );

  debug( "Setting a packet out handler ( callback = %p, user_data = %p ).", callback, user_data );

  event_handlers.packet_out_callback = callback;
  event_handlers.packet_out_user_data = user_data;

  return true;
}


bool
set_flow_mod_handler( flow_mod_handler callback, void *user_data ) {
  assert( callback != NULL );
  assert( openflow_switch_interface_initialized );

  debug( "Setting a flow mod handler ( callback = %p, user_data = %p ).", callback, user_data );

  event_handlers.flow_mod_callback = callback;
  event_handlers.flow_mod_user_data = user_data;

  return true;
}


bool
set_group_mod_handler( group_mod_handler callback, void *user_data ) {
  assert( callback != NULL );
  assert( openflow_switch_interface_initialized );

  debug( "Setting a group mod handler ( callback = %p, user_data = %p ).", callback, user_data );

  event_handlers.group_mod_callback = callback;
  event_handlers.group_mod_user_data = user_data;

  return true;
}


bool
set_port_mod_handler( port_mod_handler callback, void *user_data ) {
  assert( callback != NULL );
  assert( openflow_switch_interface_initialized );

  debug( "Setting a port mod handler ( callback = %p, user_data = %p ).", callback, user_data );

  event_handlers.port_mod_callback = callback;
  event_handlers.port_mod_user_data = user_data;

  return true;
}


bool
set_table_mod_handler( table_mod_handler callback, void *user_data ) {
  assert( callback != NULL );
  assert( openflow_switch_interface_initialized );

  debug( "Setting a table mod handler ( callback = %p, user_data = %p ).", callback, user_data );

  event_handlers.table_mod_callback = callback;
  event_handlers.table_mod_user_data = user_data;

  return true;
}


bool
set_multipart_request_handler( multipart_request_handler callback, void *user_data ) {
  assert( callback != NULL );
  assert( openflow_switch_interface_initialized );

  debug( "Setting a multipart request handler ( callback = %p, user_data = %p ).", callback, user_data );

  event_handlers.multipart_request_callback = callback;
  event_handlers.multipart_request_user_data = user_data;

  return true;
}


bool
set_barrier_request_handler( barrier_request_handler callback, void *user_data ) {
  assert( callback != NULL );
  assert( openflow_switch_interface_initialized );

  debug( "Setting a barrier request handler ( callback = %p, user_data = %p ).", callback, user_data );

  event_handlers.barrier_request_callback = callback;
  event_handlers.barrier_request_user_data = user_data;

  return true;
}


bool
set_queue_get_config_request_handler( queue_get_config_request_handler callback, void *user_data ) {
  assert( callback != NULL );
  assert( openflow_switch_interface_initialized );

  debug( "Setting a queue get config request handler ( callback = %p, user_data = %p ).", callback, user_data );

  event_handlers.queue_get_config_request_callback = callback;
  event_handlers.queue_get_config_request_user_data = user_data;

  return true;
}


bool
set_role_request_handler( role_request_handler callback, void *user_data ) {
  assert( callback != NULL );
  assert( openflow_switch_interface_initialized );

  debug( "Setting a role request handler ( callback = %p, user_data = %p ).", callback, user_data );

  event_handlers.role_request_callback = callback;
  event_handlers.role_request_user_data = user_data;

  return true;
}


bool
set_get_async_request_handler( get_async_request_handler callback, void *user_data ) {
  assert( callback != NULL );
  assert( openflow_switch_interface_initialized );

  debug( "Setting a get async request handler ( callback = %p, user_data = %p ).", callback, user_data );

  event_handlers.get_async_request_callback = callback;
  event_handlers.get_async_request_user_data = user_data;

  return true;
}


bool
set_set_async_handler( set_async_handler callback, void *user_data ) {
  assert( callback != NULL );
  assert( openflow_switch_interface_initialized );

  debug( "Setting a set async handler ( callback = %p, user_data = %p ).", callback, user_data );

  event_handlers.set_async_callback = callback;
  event_handlers.set_async_user_data = user_data;

  return true;
}


bool
set_meter_mod_handler( meter_mod_handler callback, void *user_data ) {
  assert( callback != NULL );
  assert( openflow_switch_interface_initialized );

  debug( "Setting a meter mod handler ( callback = %p, user_data = %p ).", callback, user_data );

  event_handlers.meter_mod_callback = callback;
  event_handlers.meter_mod_user_data = user_data;

  return true;
}


static bool
empty( const buffer *data ) {
  if ( ( data == NULL ) || ( ( data != NULL ) && ( data->length == 0 ) ) ) {
    return true;
  }

  return false;
}


static void
handle_hello( buffer *data ) {
  assert( empty( data ) == false );

  struct ofp_hello *hello = data->data;

  uint32_t transaction_id = ntohl( hello->header.xid );
  uint8_t version = hello->header.version;

  buffer *elements = NULL;
  if ( ntohs( hello->header.length ) > sizeof( struct ofp_hello ) ) {
    elements = duplicate_buffer( data );
    remove_front_buffer( elements, offsetof( struct ofp_hello, elements ) );
    struct ofp_hello_elem_header *element = elements->data;
    size_t elements_length = ntohs( hello->header.length ) - offsetof( struct ofp_hello, elements );
    while ( elements_length >= sizeof( struct ofp_hello_elem_header ) ) {
      ntoh_hello_elem( element, element );
      uint16_t element_length = ( uint16_t ) ( element->length + PADLEN_TO_64( element->length ) );
      elements_length -= element_length;
      element = ( struct ofp_hello_elem_header * ) ( ( char * ) element + element_length );
    }
  }

  debug( "A hello message is received ( transaction_id = %#x, version = %#x ).", transaction_id, version );

  if ( event_handlers.hello_callback == NULL ) {
    debug( "Callback function for hello events is not set." );
    if ( elements != NULL ) {
      free_buffer( elements );
    }
    return;
  }

  debug( "Calling hello handler ( callback = %p, user_data = %p ).",
         event_handlers.hello_callback, event_handlers.hello_user_data );

  event_handlers.hello_callback( transaction_id,
                                 version,
                                 elements,
                                 event_handlers.hello_user_data );
  if ( elements != NULL ) {
    free_buffer( elements );
  }
}


static void
handle_experimenter_error( buffer *data );


static void
handle_error( buffer *data ) {
  assert( empty( data ) == false );

  struct ofp_error_msg *error_msg = ( struct ofp_error_msg * ) data->data;

  uint32_t transaction_id = ntohl( error_msg->header.xid );
  uint16_t type = ntohs( error_msg->type );

  if ( type == OFPET_EXPERIMENTER ) {
    handle_experimenter_error( data );
    return;
  }

  uint16_t code = ntohs( error_msg->code );

  buffer *body = duplicate_buffer( data );
  remove_front_buffer( body, offsetof( struct ofp_error_msg, data ) );

  debug( "An error message is received ( transaction_id = %#x, type = %#x, code = %#x, data length = %u ).",
         transaction_id, type, code, body->length );

  if ( event_handlers.error_callback == NULL ) {
    debug( "Callback function for error events is not set." );
    free_buffer( body );
    return;
  }

  debug( "Calling error handler ( callback = %p, user_data = %p ).",
         event_handlers.error_callback, event_handlers.error_user_data );

  event_handlers.error_callback( transaction_id,
                                 type,
                                 code,
                                 body,
                                 event_handlers.error_user_data );

  free_buffer( body );
}


static void
handle_experimenter_error( buffer *data ) {
  assert( empty( data ) == false );

  struct ofp_error_experimenter_msg *experimenter_error_msg = ( struct ofp_error_experimenter_msg * ) data->data;

  uint32_t transaction_id = ntohl( experimenter_error_msg->header.xid );
  uint16_t type = ntohs( experimenter_error_msg->type );
  uint16_t exp_type = ntohs( experimenter_error_msg->exp_type );
  uint32_t experimenter = ntohl( experimenter_error_msg->experimenter );

  buffer *body = duplicate_buffer( data );
  remove_front_buffer( body, offsetof( struct ofp_error_experimenter_msg, data ) );

  debug( "An experimenter error message is received ( transaction_id = %#x, "
         "type = %#x, exp_type = %#x, experimenter = %#x, data length = %u ).",
         transaction_id, type, exp_type, experimenter, body->length );

  if ( event_handlers.experimenter_error_callback == NULL ) {
    debug( "Callback function for experimenter_error events is not set." );
    free_buffer( body );
    return;
  }

  debug( "Calling experimenter_error handler ( callback = %p, user_data = %p ).",
         event_handlers.experimenter_error_callback, event_handlers.experimenter_error_user_data );

  event_handlers.experimenter_error_callback( transaction_id,
                                              type,
                                              exp_type,
                                              experimenter,
                                              body,
                                              event_handlers.experimenter_error_user_data );

  free_buffer( body );
}


static void
handle_echo_request( buffer *data ) {
  assert( empty( data ) == false );

  struct ofp_header *header = data->data;
  uint32_t transaction_id = htonl( header->xid );
  uint16_t length = htons( header->length );

  debug( "An echo request is received ( transaction_id = %#x, len = %u ).", transaction_id, length );

  if ( event_handlers.echo_request_callback == NULL ) {
    debug( "Callback function for echo request events is not set." );
    return;
  }

  buffer *body = NULL;
  if ( ( length - sizeof( struct ofp_header ) ) > 0 ) {
    body = duplicate_buffer( data );
    remove_front_buffer( body, sizeof( struct ofp_header ) );
  }

  debug( "Calling echo request handler ( callback = %p, body = %p, user_data = %p ).",
         event_handlers.echo_request_callback,
         body,
         event_handlers.echo_request_user_data );

  event_handlers.echo_request_callback( transaction_id, body, event_handlers.echo_request_user_data );

  if ( body != NULL ) {
    free_buffer( body );
  }
}


static void
handle_echo_reply( buffer *data ) {
  assert( empty( data ) == false );

  struct ofp_header *header = data->data;
  uint32_t transaction_id = htonl( header->xid );
  uint16_t length = htons( header->length );

  debug( "An echo reply is received ( transaction_id = %#x, len = %u ).", transaction_id, length );

  if ( event_handlers.echo_reply_callback == NULL ) {
    debug( "Callback function for echo reply events is not set." );
    return;
  }

  buffer *body = NULL;
  if ( ( length - sizeof( struct ofp_header ) ) > 0 ) {
    body = duplicate_buffer( data );
    remove_front_buffer( body, sizeof( struct ofp_header ) );
  }

  debug( "Calling echo reply handler ( callback = %p, body = %p, user_data = %p ).",
         event_handlers.echo_reply_callback,
         body,
         event_handlers.echo_reply_user_data );

  event_handlers.echo_reply_callback( transaction_id, body, event_handlers.echo_reply_user_data );

  if ( body != NULL ) {
    free_buffer( body );
  }
}


static void
handle_experimenter( buffer *data ) {
  assert( empty( data ) == false );

  struct ofp_experimenter_header *experimenter_header = ( struct ofp_experimenter_header * ) data->data;

  uint32_t transaction_id = ntohl( experimenter_header->header.xid );
  uint32_t experimenter = ntohl( experimenter_header->experimenter );
  uint32_t exp_type = ntohl( experimenter_header->exp_type );

  uint16_t body_length = ( uint16_t ) ( ntohs( experimenter_header->header.length )
                                        - sizeof( struct ofp_experimenter_header ) );

  debug( "A experimenter message is received ( transaction_id = %#x, experimenter = %#x, "
         "exp_type = %#x, body length = %u ).",
         transaction_id, experimenter, exp_type, body_length );

  if ( event_handlers.experimenter_callback == NULL ) {
    debug( "Callback function for experimenter events is not set." );
    return;
  }

  buffer *body = NULL;
  if ( body_length > 0 ) {
    body = duplicate_buffer( data );
    remove_front_buffer( body, sizeof( struct ofp_experimenter_header ) );
  }

  debug( "Calling experimenter handler ( callback = %p, user_data = %p ).",
         event_handlers.experimenter_callback, event_handlers.experimenter_user_data );

  event_handlers.experimenter_callback( transaction_id,
                                  experimenter,
                                  exp_type,
                                  body,
                                  event_handlers.experimenter_user_data );

  if ( body != NULL ) {
    free_buffer( body );
  }
}


static void
handle_features_request( buffer *data ) {
  assert( empty( data ) == false );

  struct ofp_header *header = data->data;

  uint32_t transaction_id = ntohl( header->xid );

  debug( "A features request is received ( transaction_id = %#x ).", transaction_id );

  if ( event_handlers.features_request_callback == NULL ) {
    debug( "Callback function for features request events is not set." );
    return;
  }

  debug( "Calling features request handler ( callback = %p, user_data = %p ).",
         event_handlers.features_request_callback,
         event_handlers.features_request_user_data );

  event_handlers.features_request_callback( transaction_id,
                                            event_handlers.features_request_user_data );
}


static void
handle_get_config_request( buffer *data ) {
  assert( empty( data ) == false );

  struct ofp_header *header = data->data;

  uint32_t transaction_id = ntohl( header->xid );

  debug( "A get config request is received ( transaction_id = %#x ).", transaction_id );

  if ( event_handlers.get_config_request_callback == NULL ) {
    debug( "Callback function for get config request events is not set." );
    return;
  }

  debug( "Calling get config request handler ( callback = %p, user_data = %p ).",
         event_handlers.get_config_request_callback,
         event_handlers.get_config_request_user_data );

  event_handlers.get_config_request_callback( transaction_id,
                                              event_handlers.get_config_request_user_data );
}


static void
handle_set_config( buffer *data ) {
  assert( empty( data ) == false );

  struct ofp_switch_config *config = data->data;

  uint32_t transaction_id = ntohl( config->header.xid );
  uint16_t flags = ntohs( config->flags );
  uint16_t miss_send_len = ntohs( config->miss_send_len );

  debug( "A set config is received ( transaction_id = %#x, flags = %#x, miss_send_len = %#x ).",
         transaction_id, flags, miss_send_len );

  if ( event_handlers.set_config_callback == NULL ) {
    debug( "Callback function for set config events is not set." );
    return;
  }

  debug( "Calling set config handler ( callback = %p, user_data = %p ).",
         event_handlers.set_config_callback,
         event_handlers.set_config_user_data );

  event_handlers.set_config_callback( transaction_id, flags, miss_send_len,
                                      event_handlers.set_config_user_data );
}


static void
handle_packet_out( buffer *data ) {
  assert( empty( data ) == false );

  struct ofp_packet_out *packet_out = data->data;

  uint32_t transaction_id = ntohl( packet_out->header.xid );
  uint32_t buffer_id = ntohl( packet_out->buffer_id );
  uint32_t in_port = ntohl( packet_out->in_port );
  size_t actions_len = ntohs( packet_out->actions_len );
  openflow_actions *actions = NULL;
  if ( actions_len > 0 ) {
    actions = create_actions();
    void *actions_p = packet_out->actions;
    while ( actions_len > 0 ) {
      struct ofp_action_header *ah = actions_p;
      ntoh_action( ah, ah );
      actions_len -= ah->len;
      actions_p = ( char * ) actions_p + ah->len;

      void *action = xmalloc( ah->len );
      memcpy( action, ah, ah->len );
      append_to_tail( &actions->list, ( void * ) action );
      actions->n_actions++;
    }
  }

  buffer *frame = NULL;
  actions_len = ntohs( packet_out->actions_len );
  size_t frame_length = ntohs( packet_out->header.length ) - offsetof( struct ofp_packet_out, actions ) - actions_len;
  if ( frame_length > 0 ) {
    frame = alloc_buffer_with_length( frame_length );
    void *p = append_back_buffer( frame, frame_length );
    size_t offset = offsetof( struct ofp_packet_out, actions ) + actions_len;
    memcpy( p, ( char * ) packet_out + offset, frame_length );
  }

  debug( "A packet-out is received ( transaction_id = %#x, buffer_id = %#x, in_port = %#x, "
         "actions_len = %u, frame_length = %u ).",
         transaction_id, buffer_id, in_port, actions_len, frame_length );

  if ( event_handlers.packet_out_callback == NULL ) {
    debug( "Callback function for packet-out events is not set." );
    goto END;
  }

  debug( "Calling packet-out handler ( callback = %p, user_data = %p ).",
         event_handlers.packet_out_callback,
         event_handlers.packet_out_user_data );

  event_handlers.packet_out_callback( transaction_id, buffer_id, in_port, actions, frame,
                                      event_handlers.packet_out_user_data );

END:
  if ( actions != NULL ) {
    delete_actions( actions );
  }
  if ( frame != NULL ) {
    free_buffer( frame );
  }
}


static void
handle_flow_mod( buffer *data ) {
  assert( empty( data ) == false );

  struct ofp_flow_mod *flow_mod = data->data;

  uint32_t transaction_id = ntohl( flow_mod->header.xid );
  uint64_t cookie = ntohll( flow_mod->cookie );
  uint64_t cookie_mask = ntohll( flow_mod->cookie_mask );
  uint8_t table_id = flow_mod->table_id;
  uint8_t command = flow_mod->command;
  uint16_t idle_timeout = ntohs( flow_mod->idle_timeout );
  uint16_t hard_timeout = ntohs( flow_mod->hard_timeout );
  uint16_t priority = ntohs( flow_mod->priority );
  uint32_t buffer_id = ntohl( flow_mod->buffer_id );
  uint32_t out_port = ntohl( flow_mod->out_port );
  uint32_t out_group = ntohl( flow_mod->out_group );
  uint16_t flags = ntohs( flow_mod->flags );
  oxm_matches *match = parse_ofp_match( &flow_mod->match );
  uint16_t match_len = ntohs( flow_mod->match.length );
  match_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );
  openflow_instructions *instructions = NULL;
  uint16_t offset = ( uint16_t ) ( offsetof( struct ofp_flow_mod, match ) + match_len );
  size_t instructions_length = ( uint16_t ) ( ntohs( flow_mod->header.length ) - offset );

  if ( instructions_length > 0 ) {
    instructions = create_instructions();
    void *instruction_p = ( char * ) &flow_mod->match + match_len;
    while ( instructions_length > 0 ) {
      struct ofp_instruction *inst = instruction_p;
      ntoh_instruction( inst, inst );
      instructions_length -= inst->len;
      instruction_p = ( char * ) instruction_p + inst->len;

      void *instruction = xmalloc( inst->len );
      memcpy( instruction, inst, inst->len );
      append_to_tail( &instructions->list, ( void * ) instruction );
      instructions->n_instructions++;
    }
  }

  if ( get_logging_level() >= LOG_DEBUG ) {
    char match_str[ MATCH_STRING_LENGTH ];
    match_to_string( match, match_str, sizeof( match_str ) );
    debug( "A flow modification is received ( transaction_id = %#x, cookie = %#" PRIx64 ", "
           "cookie_mask = %#" PRIx64 ", table_id = %#x, command = %#x, idle_timeout = %#x, "
           "hard_timeout = %#x, priority = %#x, buffer_id = %#x, "
           "out_port = %#x, out_group = %#x, flags = %#x, match = [%s] ).",
           transaction_id, cookie, cookie_mask, table_id, command,
           idle_timeout, hard_timeout, priority, buffer_id,
           out_port, out_group, flags, match_str );
  }

  if ( event_handlers.flow_mod_callback == NULL ) {
    debug( "Callback function for flow modification events is not set." );
    goto END;
  }

  debug( "Calling flow modification handler ( callback = %p, user_data = %p ).",
         event_handlers.flow_mod_callback,
         event_handlers.flow_mod_user_data );

  event_handlers.flow_mod_callback( transaction_id, cookie, cookie_mask, table_id, command,
                                    idle_timeout, hard_timeout, priority, buffer_id,
                                    out_port, out_group, flags, match, instructions,
                                    event_handlers.flow_mod_user_data );

END:
  if ( match != NULL ) {
    delete_oxm_matches( match );
  }
  if ( instructions != NULL ) {
    delete_instructions( instructions );
  }
}


static void
handle_group_mod( buffer *data ) {
  assert( empty( data ) == false );

  struct ofp_group_mod *group_mod = data->data;

  list_element *buckets_head = NULL;
  list_element *element = NULL;
  struct ofp_bucket *bkt, *bucket;
  uint32_t transaction_id = ntohl( group_mod->header.xid );
  uint16_t command = ntohs( group_mod->command );
  uint8_t type = group_mod->type;
  uint32_t group_id = ntohl( group_mod->group_id );
  size_t buckets_len = ntohs( group_mod->header.length ) - offsetof( struct ofp_group_mod, buckets );

  debug( "A group modification is received ( transaction_id = %#x, command = %#x, "
         "type = %#x, gruop_id = %#x, buckets length = %u ).",
         transaction_id, command, type, group_id, buckets_len );

  if ( event_handlers.group_mod_callback == NULL ) {
    debug( "Callback function for group modification events is not set." );
    return;
  }

  if ( buckets_len > 0 ) {
    create_list( &buckets_head );
    bucket = ( struct ofp_bucket * ) group_mod->buckets;

    while ( buckets_len > 0 ) {
      bkt = ( struct ofp_bucket * ) xcalloc( 1, ntohs( bucket->len ) );

      ntoh_bucket( bkt, bucket );
      append_to_tail( &buckets_head, bkt );

      bucket = ( struct ofp_bucket * ) ( ( char * ) bucket + bkt->len );
      buckets_len = ( uint16_t ) ( buckets_len - bkt->len );
    }
  }

  debug( "Calling group modification handler ( callback = %p, user_data = %p ).",
         event_handlers.group_mod_callback,
         event_handlers.group_mod_user_data );

  event_handlers.group_mod_callback( transaction_id, command, type, group_id, buckets_head,
                                    event_handlers.group_mod_user_data );

  if ( buckets_head != NULL ) {
    element = buckets_head;
    while ( element != NULL ) {
      xfree( element->data );
      element = element->next;
    }
    delete_list( buckets_head );
  }
}


static void
handle_port_mod( buffer *data ) {
  assert( empty( data ) == false );

  struct ofp_port_mod *port_mod = data->data;

  uint32_t transaction_id = ntohl( port_mod->header.xid );
  uint32_t port_no = ntohl( port_mod->port_no );
  uint8_t hw_addr[ OFP_ETH_ALEN ];
  memcpy( hw_addr, port_mod->hw_addr, OFP_ETH_ALEN );
  uint32_t config = ntohl( port_mod->config );
  uint32_t mask = ntohl( port_mod->mask );
  uint32_t advertise = ntohl( port_mod->advertise );

  debug( "A port modification is received ( transaction_id = %#x, port_no = %#x, "
         "hw_addr = %02x:%02x:%02x:%02x:%02x:%02x, config = %#x, mask = %#x, advertise = %#x ).",
         transaction_id, port_no,
         hw_addr[ 0 ], hw_addr[ 1 ], hw_addr[ 2 ], hw_addr[ 3 ], hw_addr[ 4 ], hw_addr[ 5 ],
         config, mask, advertise );

  if ( event_handlers.port_mod_callback == NULL ) {
    debug( "Callback function for port modification events is not set." );
    return;
  }

  debug( "Calling port modification handler ( callback = %p, user_data = %p ).",
         event_handlers.port_mod_callback,
         event_handlers.port_mod_user_data );

  event_handlers.port_mod_callback( transaction_id, port_no, hw_addr, config, mask, advertise,
                                    event_handlers.port_mod_user_data );
}


static void
handle_table_mod( buffer *data ) {
  assert( empty( data ) == false );

  struct ofp_table_mod *table_mod = data->data;

  uint32_t transaction_id = ntohl( table_mod->header.xid );
  uint8_t table_id = table_mod->table_id;
  uint32_t config = ntohl( table_mod->config );

  debug( "A table modification is received ( transaction_id = %#x, table_id = %#x, "
         "config = %#x ).",
         transaction_id, table_id, config );

  if ( event_handlers.table_mod_callback == NULL ) {
    debug( "Callback function for table modification events is not set." );
    return;
  }

  debug( "Calling table modification handler ( callback = %p, user_data = %p ).",
         event_handlers.table_mod_callback,
         event_handlers.table_mod_user_data );

  event_handlers.table_mod_callback( transaction_id, table_id, config,
                                     event_handlers.table_mod_user_data );
}


static void
handle_multipart_request( buffer *data ) {
  assert( empty( data ) == false );

  struct ofp_multipart_request *multipart_request = data->data;

  uint32_t transaction_id = ntohl( multipart_request->header.xid );
  uint16_t type = ntohs( multipart_request->type );
  uint16_t flags = ntohs( multipart_request->flags );

  size_t body_length = ntohs( multipart_request->header.length ) - offsetof( struct ofp_multipart_request, body );
  buffer *body = NULL;
  if ( body_length > 0 ) {
    body = alloc_buffer_with_length( body_length );
    void *p = append_back_buffer( body, body_length );
    memcpy( p, multipart_request->body, body_length );

    switch ( type ) {
    case OFPMP_FLOW:
    {
      struct ofp_flow_stats_request *flow = p;
      flow->out_port = ntohl( flow->out_port );
      flow->out_group = ntohl( flow->out_group );
      flow->cookie = ntohll( flow->cookie );
      flow->cookie_mask = ntohll( flow->cookie_mask );
      ntoh_match( &flow->match, &flow->match );
    }
    break;

    case OFPMP_AGGREGATE:
    {
      struct ofp_aggregate_stats_request *aggregate = p;
      aggregate->out_port = ntohl( aggregate->out_port );
      aggregate->out_group = ntohl( aggregate->out_group );
      aggregate->cookie = ntohll( aggregate->cookie );
      aggregate->cookie_mask = ntohll( aggregate->cookie_mask );
      ntoh_match( &aggregate->match, &aggregate->match );
    }
    break;

    case OFPMP_PORT_STATS:
    {
      struct ofp_port_stats_request *port = p;
      port->port_no = ntohl( port->port_no );
    }
    break;

    case OFPMP_QUEUE:
    {
      struct ofp_queue_stats_request *queue = p;
      queue->port_no = ntohl( queue->port_no );
      queue->queue_id = ntohl( queue->queue_id );
    }
    break;

    case OFPMP_GROUP:
    {
      struct ofp_group_stats_request *group = p;
      group->group_id = ntohl( group->group_id );
    }
    break;

    case OFPMP_METER:
    {
      struct ofp_meter_multipart_request *meter = p;
      meter->meter_id = ntohl( meter->meter_id );
    }
    break;

    case OFPMP_METER_CONFIG:
    {
      struct ofp_meter_multipart_request *meter = p;
      meter->meter_id = ntohl( meter->meter_id );
    }
    break;

    case OFPMP_TABLE_FEATURES:
    {
      size_t rest_length = body_length;
      void *rest_p = p;

      while ( rest_length >= sizeof( struct ofp_table_features ) ) {
        struct ofp_table_features *table = rest_p;
        ntoh_table_features( table, table );

        rest_p = ( char * ) rest_p + table->length;
        rest_length -= table->length;
      }
    }
    break;

    case OFPMP_EXPERIMENTER:
    {
      struct ofp_experimenter_multipart_header *exp = p;
      exp->experimenter = ntohl( exp->experimenter );
      exp->exp_type = ntohl( exp->exp_type );
    }
    break;

    default:
    break;
    }
  }

  debug( "A multipart request is received ( transaction_id = %#x, type = %#x, flags = %#x ).",
         transaction_id, type, flags );

  if ( event_handlers.multipart_request_callback == NULL ) {
    debug( "Callback function for multipart request events is not set." );
    return;
  }

  debug( "Calling multipart request handler ( callback = %p, user_data = %p ).",
         event_handlers.multipart_request_callback,
         event_handlers.multipart_request_user_data );

  event_handlers.multipart_request_callback( transaction_id, type, flags, body,
                                         event_handlers.multipart_request_user_data );

  if ( body_length > 0 && body != NULL ) {
    free_buffer( body );
  }
}


static void
handle_barrier_request( buffer *data ) {
  assert( empty( data ) == false );

  struct ofp_header *header = data->data;

  uint32_t transaction_id = ntohl( header->xid );

  debug( "A barrier request is received ( transaction_id = %#x ).", transaction_id );

  if ( event_handlers.barrier_request_callback == NULL ) {
    debug( "Callback function for barrier request events is not set." );
    return;
  }

  debug( "Calling barrier request handler ( callback = %p, user_data = %p ).",
         event_handlers.barrier_request_callback,
         event_handlers.barrier_request_user_data );

  event_handlers.barrier_request_callback( transaction_id,
                                           event_handlers.barrier_request_user_data );
}


static void
handle_queue_get_config_request( buffer *data ) {
  assert( empty( data ) == false );

  struct ofp_queue_get_config_request *queue_get_config_request = data->data;

  uint32_t transaction_id = ntohl( queue_get_config_request->header.xid );
  uint32_t port = ntohl( queue_get_config_request->port );

  debug( "A queue get config request is received ( transaction_id = %#x, port = %#x ).",
         transaction_id, port );

  if ( event_handlers.queue_get_config_request_callback == NULL ) {
    debug( "Callback function for queue get config request events is not set." );
    return;
  }

  debug( "Calling queue get config request handler ( callback = %p, user_data = %p ).",
         event_handlers.queue_get_config_request_callback,
         event_handlers.queue_get_config_request_user_data );

  event_handlers.queue_get_config_request_callback( transaction_id, port,
                                                    event_handlers.queue_get_config_request_user_data );
}


static void
handle_role_request( buffer *data ) {
  assert( empty( data ) == false );

  struct ofp_role_request *role_request = data->data;

  uint32_t transaction_id = ntohl( role_request->header.xid );
  uint32_t role = ntohl( role_request->role );
  uint64_t generation_id = ntohll( role_request->generation_id );

  debug( "A role request is received ( transaction_id = %#x, role = %#x, generation_id = %#" PRIx64 " ).",
         transaction_id, role, generation_id );

  if ( event_handlers.role_request_callback == NULL ) {
    debug( "Callback function for role request events is not set." );
    return;
  }

  debug( "Calling role request handler ( callback = %p, user_data = %p ).",
         event_handlers.role_request_callback,
         event_handlers.role_request_user_data );

  event_handlers.role_request_callback( transaction_id, role, generation_id,
                                        event_handlers.role_request_user_data );
}


static void
handle_get_async_request( buffer *data ) {
  assert( empty( data ) == false );

  struct ofp_header *get_async_request = data->data;

  uint32_t transaction_id = ntohl( get_async_request->xid );

  debug( "A get async request is received ( transaction_id = %#x ).",
         transaction_id );

  if ( event_handlers.get_async_request_callback == NULL ) {
    debug( "Callback function for role request events is not set." );
    return;
  }

  debug( "Calling get async request handler ( callback = %p, user_data = %p ).",
         event_handlers.get_async_request_callback,
         event_handlers.get_async_request_user_data );

  event_handlers.get_async_request_callback( transaction_id,
                                             event_handlers.get_async_request_user_data );
}


static void
handle_set_async( buffer *data ) {
  assert( empty( data ) == false );

  struct ofp_async_config *set_async = data->data;

  uint32_t transaction_id = ntohl( set_async->header.xid );
  uint32_t packet_in_mask[ 2 ];
  uint32_t port_status_mask[ 2 ];
  uint32_t flow_removed_mask[ 2 ];
  packet_in_mask[ 0 ] = ntohl( set_async->packet_in_mask[ 0 ] );
  packet_in_mask[ 1 ] = ntohl( set_async->packet_in_mask[ 1 ] );
  port_status_mask[ 0 ] = ntohl( set_async->port_status_mask[ 0 ] );
  port_status_mask[ 1 ] = ntohl( set_async->port_status_mask[ 1 ] );
  flow_removed_mask[ 0 ] = ntohl( set_async->flow_removed_mask[ 0 ] );
  flow_removed_mask[ 1 ] = ntohl( set_async->flow_removed_mask[ 1 ] );

  debug( "A set async is received ( transaction_id = %#x, "
         "packet_in_mask[0] = %#x, packet_in_mask[1] = %#x, "
         "port_status_mask[0] = %#x, port_status_mask[1] = %#x, "
         "flow_removed_mask[0] = %#x, flow_removed_mask[1] = %#x ).",
         transaction_id, packet_in_mask[0], packet_in_mask[1],
         port_status_mask[0], port_status_mask[1],
         flow_removed_mask[0], flow_removed_mask[1] );

  if ( event_handlers.set_async_callback == NULL ) {
    debug( "Callback function for set async events is not set." );
    return;
  }

  debug( "Calling set async handler ( callback = %p, user_data = %p ).",
         event_handlers.set_async_callback,
         event_handlers.set_async_user_data );

  event_handlers.set_async_callback( transaction_id, packet_in_mask,
                                             port_status_mask, flow_removed_mask,
                                             event_handlers.set_async_user_data );
}


static void
handle_meter_mod( buffer *data ) {
  assert( empty( data ) == false );

  struct ofp_meter_mod *meter_mod = data->data;

  list_element *meter_band_head = NULL;
  list_element *element = NULL;
  struct ofp_meter_band_header *mtbnd, *meter_band;
  uint32_t transaction_id = ntohl( meter_mod->header.xid );
  uint16_t command = ntohs( meter_mod->command );
  uint16_t flags = ntohs( meter_mod->flags );
  uint32_t meter_id = ntohl( meter_mod->meter_id );
  size_t meter_band_len = ntohs( meter_mod->header.length ) - offsetof( struct ofp_meter_mod, bands );

  debug( "A meter modification is received ( transaction_id = %#x, command = %#x, "
         "flags = %#x, meter_id = %#x, bands length = %u ).",
         transaction_id, command, flags, meter_id, meter_band_len );

  if ( event_handlers.meter_mod_callback == NULL ) {
    debug( "Callback function for meter modification events is not set." );
    return;
  }

  if ( meter_band_len > 0 ) {
    create_list( &meter_band_head );
    meter_band = ( struct ofp_meter_band_header * ) meter_mod->bands;

    while ( meter_band_len > 0 ) {
      mtbnd = ( struct ofp_meter_band_header * ) xcalloc( 1, ntohs( meter_band->len ) );

      ntoh_meter_band_header( mtbnd, meter_band );
      append_to_tail( &meter_band_head, mtbnd );

      meter_band = ( struct ofp_meter_band_header * ) ( ( char * ) meter_band + mtbnd->len );
      meter_band_len = ( uint16_t ) ( meter_band_len - mtbnd->len );
    }
  }

  debug( "Calling meter modification handler ( callback = %p, user_data = %p ).",
         event_handlers.meter_mod_callback,
         event_handlers.meter_mod_user_data );

  event_handlers.meter_mod_callback( transaction_id, command, flags, meter_id, meter_band_head,
                                     event_handlers.meter_mod_user_data );

  if ( meter_band_head != NULL ) {
    element = meter_band_head;
    while ( element != NULL ) {
      xfree( element->data );
      element = element->next;
    }
    delete_list( meter_band_head );
  }
}


static void
handle_controller_connected() {
  if ( event_handlers.controller_connected_callback == NULL ) {
    debug( "Callback function for controller connected events is not set." );
    return;
  }

  event_handlers.controller_connected_callback( event_handlers.controller_connected_user_data );
}


static void
handle_controller_disconnected() {
  if ( event_handlers.controller_disconnected_callback == NULL ) {
    debug( "Callback function for controller disconnected events is not set." );
    return;
  }

  event_handlers.controller_disconnected_callback( event_handlers.controller_disconnected_user_data );
}


static bool
handle_openflow_message( buffer *message ) {
  debug( "An OpenFlow message is received from remote." );

  assert( message != NULL );
  assert( message->length >= sizeof( struct ofp_header ) );

  struct ofp_header *header = ( struct ofp_header * ) message->data;

  int ret = validate_openflow_message( message );
  if ( ret < 0 ) {
    error( "Failed to validate an OpenFlow message ( code = %d, length = %u ).", ret, message->length );
    uint16_t type = OFPET_BAD_REQUEST;
    uint16_t code = OFPBRC_EPERM;
    get_error_type_and_code( header->type, ret, &type, &code );
    send_error_message( ntohl( header->xid ), type, code );
    return false;
  }

  ret = true;

  switch ( header->type ) {
  case OFPT_HELLO:
    handle_hello( message );
    break;
  case OFPT_ERROR:
    handle_error( message );
    break;
  case OFPT_ECHO_REQUEST:
    handle_echo_request( message );
    break;
  case OFPT_ECHO_REPLY:
    handle_echo_reply( message );
    break;
  case OFPT_EXPERIMENTER:
    handle_experimenter( message);
    break;
  case OFPT_FEATURES_REQUEST:
    handle_features_request( message );
    break;
  case OFPT_GET_CONFIG_REQUEST:
    handle_get_config_request( message );
    break;
  case OFPT_SET_CONFIG:
    handle_set_config( message );
    break;
  case OFPT_PACKET_OUT:
    handle_packet_out( message );
    break;
  case OFPT_FLOW_MOD:
    handle_flow_mod( message );
    break;
  case OFPT_GROUP_MOD:
    handle_group_mod( message );
    break;
  case OFPT_PORT_MOD:
    handle_port_mod( message );
    break;
  case OFPT_TABLE_MOD:
    handle_table_mod( message );
    break;
  case OFPT_MULTIPART_REQUEST:
    handle_multipart_request( message );
    break;
  case OFPT_BARRIER_REQUEST:
    handle_barrier_request( message );
    break;
  case OFPT_QUEUE_GET_CONFIG_REQUEST:
    handle_queue_get_config_request( message );
    break;
  case OFPT_ROLE_REQUEST:
    handle_role_request( message );
    break;
  case OFPT_GET_ASYNC_REQUEST:
    handle_get_async_request( message );
    break;
  case OFPT_SET_ASYNC:
    handle_set_async( message );
    break;
  case OFPT_METER_MOD:
    handle_meter_mod( message );
    break;
  default:
    error( "Unhandled OpenFlow message ( type = %u ).", header->type );
    ret = false;
    break;
  }

  return ret;
}


static bool
send_openflow_message_to_secure_channel( buffer *message, void *user_data ) {
  assert( user_data == NULL );

  return send_message_to_secure_channel( message );
}


static bool
send_openflow_message_to_local( buffer *message, void *user_data ) {
  char *service_name = user_data;
  size_t service_name_length = strlen( service_name ) + 1;
  size_t service_header_length = sizeof( openflow_service_header_t ) + service_name_length;
  openflow_service_header_t *service_header = append_front_buffer( message, service_header_length );
  service_header->service_name_length = htons( ( uint16_t ) service_name_length );
  memcpy( ( char * ) service_header + sizeof( openflow_service_header_t ), service_name, service_name_length );

  return send_message( service_name, MESSENGER_OPENFLOW_MESSAGE, message->data, message->length );
}


bool
switch_send_openflow_message( buffer *message ) {
  assert( message != NULL );
  assert( message->length >= sizeof( struct ofp_header ) );

  struct ofp_header *header = message->data;
  uint32_t transaction_id = ntohl( header->xid );
  openflow_context *context = lookup_context( transaction_id );
  if ( context != NULL ) {
    assert( context->send_callback != NULL );
    return context->send_callback( message, context->user_data );
  }

  return send_openflow_message_to_secure_channel( message, NULL );
}


bool
handle_secure_channel_message( buffer *message ) {
  assert( message != NULL );
  assert( message->length >= sizeof( struct ofp_header ) );

  debug( "A message is received from remote ( length = %u ).", message->length );

  struct ofp_header *header = message->data;

  save_context( ntohl( header->xid ), message, send_openflow_message_to_secure_channel, NULL );

  return handle_openflow_message( message );
}


static void
handle_local_message( uint16_t tag, void *data, size_t length ) {
  assert( data != NULL );
  assert( length >= sizeof( openflow_service_header_t ) );

  debug( "A message is received from local ( tag = %u, data = %p, length = %u ).", tag, data, length );

  switch ( tag ) {
  case MESSENGER_OPENFLOW_MESSAGE:
  {
    openflow_service_header_t *header = data;
    uint16_t service_name_length = ntohs( header->service_name_length );
    size_t ofp_offset = sizeof( openflow_service_header_t ) + service_name_length;
    size_t ofp_length = length - ofp_offset;
    buffer *message = alloc_buffer_with_length( ofp_length );
    char *p = append_back_buffer( message, ofp_length );
    memcpy( p, ( char * ) data + ofp_offset, ofp_length );
    char *service_name = strndup( ( char * ) data + sizeof( openflow_service_header_t ), service_name_length );

    save_context( ntohl( ( ( struct ofp_header * ) p )->xid ), message, send_openflow_message_to_local,
                  service_name );

    handle_openflow_message( message );
  }
  break;
  default:
    break;
  }
}


bool
init_openflow_switch_interface( const uint64_t datapath_id, uint32_t controller_ip, uint16_t controller_port ) {
  debug( "Initializing OpenFlow Switch Interface ( datapath_id = %#" PRIx64 ", controller_ip = %#x, controller_port = %u ).",
         datapath_id, controller_ip, controller_port );

  if ( openflow_switch_interface_is_initialized() ) {
    error( "OpenFlow Switch Interface is already initialized." );
    return false;
  }

  bool ret = init_secure_channel( controller_ip, controller_port,
                                  handle_controller_connected, handle_controller_disconnected );
  if ( ret == false ) {
    error( "Failed to initialize a secure chanel." );
    return false;
  }


  memset( &event_handlers, 0, sizeof( openflow_switch_event_handlers ) );
  memset( &config, 0, sizeof( openflow_switch_config ) );

  config.datapath_id = datapath_id;
  config.controller.ip = controller_ip;
  config.controller.port = controller_port;

  init_context();

  add_periodic_event_callback_safe( 5, age_contexts, NULL );
  add_message_received_callback( "switch", handle_local_message );

  openflow_switch_interface_initialized = true;

  return true;
}


bool
finalize_openflow_switch_interface() {
  if ( !openflow_switch_interface_is_initialized() ) {
    error( "OpenFlow Switch Interface is not initialized." );
    return false;
  }

  finalize_secure_channel();

  delete_timer_event_safe( age_contexts, NULL );
  finalize_context();

  openflow_switch_interface_initialized = false;

  return true;
}


static const buffer *
get_openflow_message( uint32_t transaction_id ) {
  openflow_context *context = lookup_context( transaction_id );
  if ( context == NULL ) {
    return NULL;
  }

  return context->message;
}


bool
send_error_message( uint32_t transaction_id, uint16_t type, uint16_t code ) {
  buffer *data = NULL;
  switch ( type ) {
  case OFPET_HELLO_FAILED:
  {
    switch ( code ) {
    case OFPHFC_INCOMPATIBLE:
    {
      const char *description = "Incompatible OpenFlow version.";
      size_t length = strlen( description ) + 1;
      data = alloc_buffer_with_length ( length );
      void *p = append_back_buffer( data, length );
      strncpy( p, description, length );
    }
    break;
    case OFPHFC_EPERM:
    {
      const char *description = "Permissions error.";
      size_t length = strlen( description ) + 1;
      data = alloc_buffer_with_length ( length );
      void *p = append_back_buffer( data, length );
      strncpy( p, description, length );
    }
    break;
    default:
      error( "Undefined error code ( type = %#x, code = %#x ).", type, code );
      return false;
    }
  }
  break;

  case OFPET_BAD_REQUEST:
  {
    switch ( code ) {
    case OFPBRC_BAD_VERSION:
    case OFPBRC_BAD_TYPE:
    case OFPBRC_BAD_MULTIPART:
    case OFPBRC_BAD_EXPERIMENTER:
    case OFPBRC_BAD_EXP_TYPE:
    case OFPBRC_EPERM:
    case OFPBRC_BAD_LEN:
    case OFPBRC_BUFFER_EMPTY:
    case OFPBRC_BUFFER_UNKNOWN:
    case OFPBRC_BAD_TABLE_ID:
    case OFPBRC_IS_SLAVE:
    case OFPBRC_BAD_PORT:
    case OFPBRC_BAD_PACKET:
    case OFPBRC_MULTIPART_BUFFER_OVERFLOW:
    {
      const buffer *original_message = get_openflow_message( transaction_id );
      if ( original_message != NULL ) {
        data = duplicate_buffer( original_message );
        if ( data->length > 64 ) {
          data->length = 64;
        }
      }
    }
    break;
    default:
      error( "Undefined error code ( type = %#x, code = %#x ).", type, code );
      return false;
    }
  }
  break;

  case OFPET_BAD_ACTION:
  {
    switch ( code ) {
    case OFPBAC_BAD_TYPE:
    case OFPBAC_BAD_LEN:
    case OFPBAC_BAD_EXPERIMENTER:
    case OFPBAC_BAD_EXP_TYPE:
    case OFPBAC_BAD_OUT_PORT:
    case OFPBAC_BAD_ARGUMENT:
    case OFPBAC_EPERM:
    case OFPBAC_TOO_MANY:
    case OFPBAC_BAD_QUEUE:
    case OFPBAC_BAD_OUT_GROUP:
    case OFPBAC_MATCH_INCONSISTENT:
    case OFPBAC_UNSUPPORTED_ORDER:
    case OFPBAC_BAD_TAG:
    case OFPBAC_BAD_SET_TYPE:
    case OFPBAC_BAD_SET_LEN:
    case OFPBAC_BAD_SET_ARGUMENT:
    {
      const buffer *original_message = get_openflow_message( transaction_id );
      if ( original_message != NULL ) {
        data = duplicate_buffer( original_message );
        if ( data->length > 64 ) {
          data->length = 64;
        }
      }
    }
    break;
    default:
      error( "Undefined error code ( type = %#x, code = %#x ).", type, code );
      return false;
    }

  }
  break;

  case OFPET_BAD_INSTRUCTION:
  {
    switch ( code ) {
    case OFPBIC_UNKNOWN_INST:
    case OFPBIC_UNSUP_INST:
    case OFPBIC_BAD_TABLE_ID:
    case OFPBIC_UNSUP_METADATA:
    case OFPBIC_UNSUP_METADATA_MASK:
    case OFPBIC_BAD_EXPERIMENTER:
    case OFPBIC_BAD_EXP_TYPE:
    case OFPBIC_BAD_LEN:
    case OFPBIC_EPERM:
    {
      const buffer *original_message = get_openflow_message( transaction_id );
      if ( original_message != NULL ) {
        data = duplicate_buffer( original_message );
        if ( data->length > 64 ) {
          data->length = 64;
        }
      }
    }
    break;
    default:
      error( "Undefined error code ( type = %#x, code = %#x ).", type, code );
      return false;
    }

  }
  break;

  case OFPET_BAD_MATCH:
  {
    switch ( code ) {
    case OFPBMC_BAD_TYPE:
    case OFPBMC_BAD_LEN:
    case OFPBMC_BAD_TAG:
    case OFPBMC_BAD_DL_ADDR_MASK:
    case OFPBMC_BAD_NW_ADDR_MASK:
    case OFPBMC_BAD_WILDCARDS:
    case OFPBMC_BAD_FIELD:
    case OFPBMC_BAD_VALUE:
    case OFPBMC_BAD_MASK:
    case OFPBMC_BAD_PREREQ:
    case OFPBMC_DUP_FIELD:
    case OFPBMC_EPERM:
    {
      const buffer *original_message = get_openflow_message( transaction_id );
      if ( original_message != NULL ) {
        data = duplicate_buffer( original_message );
        if ( data->length > 64 ) {
          data->length = 64;
        }
      }
    }
    break;
    default:
      error( "Undefined error code ( type = %#x, code = %#x ).", type, code );
      return false;
    }

  }
  break;

  case OFPET_FLOW_MOD_FAILED:
  {
    switch ( code ) {
    case OFPFMFC_UNKNOWN:
    case OFPFMFC_TABLE_FULL:
    case OFPFMFC_BAD_TABLE_ID:
    case OFPFMFC_OVERLAP:
    case OFPFMFC_EPERM:
    case OFPFMFC_BAD_TIMEOUT:
    case OFPFMFC_BAD_COMMAND:
    case OFPFMFC_BAD_FLAGS:
    {
      const buffer *original_message = get_openflow_message( transaction_id );
      if ( original_message != NULL ) {
        data = duplicate_buffer( original_message );
        if ( data->length > 64 ) {
          data->length = 64;
        }
      }
    }
    break;
    default:
      error( "Undefined error code ( type = %#x, code = %#x ).", type, code );
      return false;
    }
  }
  break;

  case OFPET_GROUP_MOD_FAILED:
  {
    switch ( code ) {
    case OFPGMFC_GROUP_EXISTS:
    case OFPGMFC_INVALID_GROUP:
    case OFPGMFC_WEIGHT_UNSUPPORTED:
    case OFPGMFC_OUT_OF_GROUPS:
    case OFPGMFC_OUT_OF_BUCKETS:
    case OFPGMFC_CHAINING_UNSUPPORTED:
    case OFPGMFC_WATCH_UNSUPPORTED:
    case OFPGMFC_LOOP:
    case OFPGMFC_UNKNOWN_GROUP:
    case OFPGMFC_CHAINED_GROUP:
    case OFPGMFC_BAD_TYPE:
    case OFPGMFC_BAD_COMMAND:
    case OFPGMFC_BAD_BUCKET:
    case OFPGMFC_BAD_WATCH:
    case OFPGMFC_EPERM:
    {
      const buffer *original_message = get_openflow_message( transaction_id );
      if ( original_message != NULL ) {
        data = duplicate_buffer( original_message );
        if ( data->length > 64 ) {
          data->length = 64;
        }
      }
    }
    break;
    default:
      error( "Undefined error code ( type = %#x, code = %#x ).", type, code );
      return false;
    }
  }
  break;

  case OFPET_PORT_MOD_FAILED:
  {
    switch ( code ) {
    case OFPPMFC_BAD_PORT:
    case OFPPMFC_BAD_HW_ADDR:
    case OFPPMFC_BAD_CONFIG:
    case OFPPMFC_BAD_ADVERTISE:
    case OFPPMFC_EPERM:
    {
      const buffer *original_message = get_openflow_message( transaction_id );
      if ( original_message != NULL ) {
        data = duplicate_buffer( original_message );
        if ( data->length > 64 ) {
          data->length = 64;
        }
      }
    }
    break;
    default:
      error( "Undefined error code ( type = %#x, code = %#x ).", type, code );
      return false;
    }
  }
  break;

  case OFPET_TABLE_MOD_FAILED:
  {
    switch ( code ) {
    case OFPTMFC_BAD_TABLE:
    case OFPTMFC_BAD_CONFIG:
    case OFPTMFC_EPERM:
    {
      const buffer *original_message = get_openflow_message( transaction_id );
      if ( original_message != NULL ) {
        data = duplicate_buffer( original_message );
        if ( data->length > 64 ) {
          data->length = 64;
        }
      }
    }
    break;
    default:
      error( "Undefined error code ( type = %#x, code = %#x ).", type, code );
      return false;
    }
  }
  break;

  case OFPET_QUEUE_OP_FAILED:
  {
    switch ( code ) {
    case OFPQOFC_BAD_PORT:
    case OFPQOFC_BAD_QUEUE:
    case OFPQOFC_EPERM:
    {
      const buffer *original_message = get_openflow_message( transaction_id );
      if ( original_message != NULL ) {
        data = duplicate_buffer( original_message );
        if ( data->length > 64 ) {
          data->length = 64;
        }
      }
    }
    break;
    default:
      error( "Undefined error code ( type = %#x, code = %#x ).", type, code );
      return false;
    }
  }
  break;

  case OFPET_SWITCH_CONFIG_FAILED:
  {
    switch ( code ) {
    case OFPSCFC_BAD_FLAGS:
    case OFPSCFC_BAD_LEN:
    case OFPSCFC_EPERM:
    {
      const buffer *original_message = get_openflow_message( transaction_id );
      if ( original_message != NULL ) {
        data = duplicate_buffer( original_message );
        if ( data->length > 64 ) {
          data->length = 64;
        }
      }
    }
    break;
    default:
      error( "Undefined error code ( type = %#x, code = %#x ).", type, code );
      return false;
    }
  }
  break;

  case OFPET_ROLE_REQUEST_FAILED:
  {
    switch ( code ) {
    case OFPRRFC_STALE:
    case OFPRRFC_UNSUP:
    case OFPRRFC_BAD_ROLE:
    {
      const buffer *original_message = get_openflow_message( transaction_id );
      if ( original_message != NULL ) {
        data = duplicate_buffer( original_message );
        if ( data->length > 64 ) {
          data->length = 64;
        }
      }
    }
    break;
    default:
      error( "Undefined error code ( type = %#x, code = %#x ).", type, code );
      return false;
    }
  }
  break;

  case OFPET_METER_MOD_FAILED:
  {
    switch ( code ) {
    case OFPMMFC_UNKNOWN:
    case OFPMMFC_METER_EXISTS:
    case OFPMMFC_INVALID_METER:
    case OFPMMFC_UNKNOWN_METER:
    case OFPMMFC_BAD_COMMAND:
    case OFPMMFC_BAD_FLAGS:
    case OFPMMFC_BAD_RATE:
    case OFPMMFC_BAD_BURST:
    case OFPMMFC_BAD_BAND:
    case OFPMMFC_BAD_BAND_VALUE:
    case OFPMMFC_OUT_OF_METERS:
    case OFPMMFC_OUT_OF_BANDS:
    {
      const buffer *original_message = get_openflow_message( transaction_id );
      if ( original_message != NULL ) {
        data = duplicate_buffer( original_message );
        if ( data->length > 64 ) {
          data->length = 64;
        }
      }
    }
    break;
    default:
      error( "Undefined error code ( type = %#x, code = %#x ).", type, code );
      return false;
    }
  }
  break;

  case OFPET_TABLE_FEATURES_FAILED:
  {
    switch ( code ) {
    case OFPTFFC_BAD_TABLE:
    case OFPTFFC_BAD_METADATA:
    case OFPTFFC_BAD_TYPE:
    case OFPTFFC_BAD_LEN:
    case OFPTFFC_BAD_ARGUMENT:
    case OFPTFFC_EPERM:
    {
      const buffer *original_message = get_openflow_message( transaction_id );
      if ( original_message != NULL ) {
        data = duplicate_buffer( original_message );
        if ( data->length > 64 ) {
          data->length = 64;
        }
      }
    }
    break;
    default:
      error( "Undefined error code ( type = %#x, code = %#x ).", type, code );
      return false;
    }
  }
  break;

  default:
    error( "Undefined error type ( type = %#x, code = %#x ).", type, code );
    return false;
  }

  buffer *err = create_error( transaction_id, type, code, data );
  bool ret = switch_send_openflow_message( err );
  if ( !ret ) {
    error( "Failed to send an error message ( transaction_id = %#x, type = %#x, code = %#x ).",
           transaction_id, type, code );
  }

  free_buffer( err );
  if ( data != NULL ) {
    free_buffer( data );
  }

  return ret;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
