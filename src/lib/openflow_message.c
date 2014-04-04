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


#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include "openflow_message.h"
#include "packet_info.h"
#include "wrapper.h"
#include "log.h"


#ifdef UNIT_TESTING

// Allow static functions to be called from unit tests.
#define static

/* Redirect getpid to a function in the test application so it's
 * possible to test if pid value is correctly used. */
#ifdef getpid
#undef getpid
#endif // getpid
#define getpid mock_getpid
extern pid_t mock_getpid( void );

/* Redirect debug to a function in the test application so it's
 * possible to test if debug messages are generated expectedly. */
#ifdef debug
#undef debug
#endif // debug
#define debug mock_debug
extern void mock_debug( const char *format, ... );

#endif // UNIT_TESTING


#define VLAN_VID_MASK 0x1fff // 12 + 1 bits
#define VLAN_PCP_MASK 0x07   // 3 bits
#define IP_DSCP_MASK 0x3f    // 6 bits
#define IP_ECN_MASK 0x03     // 2 bits
#define ARP_OP_MASK 0x00ff   // 8 bits
#define IPV6_FLABEL_MASK 0x000fffff // 20 bits
#define MPLS_LABEL_MASK 0x000fffff  // 20 bits
#define MPLS_TC_MASK 0x07    // 3 bits
#define MPLS_BOS_MASK 0x01   // 1 bits
#define PBB_ISID_MASK 0x00ffffff    // 24 bits
#define IPV6_EXTHDR_MASK 0x01ff     // 9 bits

#define GROUP_COMMAND_MAX OFPGC_DELETE
#define GROUP_TYPE ( ( 1 << OFPGT_ALL ) | ( 1 << OFPGT_SELECT ) | ( 1 << OFPGT_INDIRECT ) | ( 1 << OFPGT_FF ) )
#define GROUP_TYPE_MAX OFPGT_FF
#define METER_COMMAND_MAX OFPMC_DELETE
#define METER_BAND_TYPE ( ( 1 << OFPMBT_DROP ) | ( 1 << OFPMBT_DSCP_REMARK ) )
#define METER_BAND_MAX OFPMBT_DSCP_REMARK
#define METER_FLAGS ( OFPMF_KBPS | OFPMF_PKTPS | OFPMF_BURST | OFPMF_STATS )
#define PORT_CONFIG ( OFPPC_PORT_DOWN | OFPPC_NO_RECV      \
                      | OFPPC_NO_FWD | OFPPC_NO_PACKET_IN )
#define PORT_STATE ( OFPPS_LINK_DOWN | OFPPS_BLOCKED | OFPPS_LIVE )
#define PORT_FEATURES ( OFPPF_10MB_HD | OFPPF_10MB_FD | OFPPF_100MB_HD    \
                        | OFPPF_100MB_FD | OFPPF_1GB_HD | OFPPF_1GB_FD    \
                        | OFPPF_10GB_FD | OFPPF_40GB_FD | OFPPF_100GB_FD  \
                        | OFPPF_1TB_FD | OFPPF_OTHER | OFPPF_COPPER       \
                        | OFPPF_FIBER | OFPPF_AUTONEG | OFPPF_PAUSE       \
                        | OFPPF_PAUSE_ASYM )
#define FLOW_MOD_FLAGS ( OFPFF_SEND_FLOW_REM | OFPFF_CHECK_OVERLAP    \
                        | OFPFF_RESET_COUNTS | OFPFF_NO_PKT_COUNTS    \
                        | OFPFF_NO_BYT_COUNTS )
#define CONTROLLER_ROLE_MAX OFPCR_ROLE_SLAVE
#define PACKET_IN_MASK ( ( 1 << OFPR_NO_MATCH ) | ( 1 << OFPR_ACTION ) | ( 1 << OFPR_INVALID_TTL ) )
#define PORT_STATUS_MASK ( ( 1 << OFPPR_ADD ) | ( 1 << OFPPR_DELETE ) | ( 1 << OFPPR_MODIFY ) )
#define FLOW_REMOVED_MASK ( ( 1 << OFPRR_IDLE_TIMEOUT ) | ( 1 << OFPRR_HARD_TIMEOUT ) \
                            | ( 1 << OFPRR_DELETE ) | ( 1 << OFPRR_GROUP_DELETE ) )

static uint32_t transaction_id = 0;
static pthread_mutex_t transaction_id_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

static uint64_t cookie = 0;
static pthread_mutex_t cookie_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;


bool
init_openflow_message( void ) {
  pid_t pid;

  pid = getpid();

  pthread_mutex_lock( &transaction_id_mutex );
  transaction_id = ( uint32_t ) pid << 16;
  pthread_mutex_unlock( &transaction_id_mutex );

  pthread_mutex_lock( &cookie_mutex );
  cookie = ( uint64_t ) pid << 48;
  pthread_mutex_unlock( &cookie_mutex );

  debug( "transaction_id and cookie are initialized ( transaction_id = %#x, cookie = %#" PRIx64 " ).",
         transaction_id, cookie );

  return true;
}


static buffer *
create_header( const uint32_t transaction_id, const uint8_t type, const uint16_t length ) {
  debug( "Creating an OpenFlow header (version = %#x, type = %#x, length = %u, xid = %#x).",
         OFP_VERSION, type, length, transaction_id );

  assert( length >= sizeof( struct ofp_header ) );

  buffer *buffer = alloc_buffer();
  assert( buffer != NULL );

  struct ofp_header *header = append_back_buffer( buffer, length );
  assert( header != NULL );
  memset( header, 0, length );

  header->version = OFP_VERSION;
  header->type = type;
  header->length = htons( length );
  header->xid = htonl( transaction_id );

  return buffer;
}


buffer *
create_error( const uint32_t transaction_id, const uint16_t type,
              const uint16_t code, const buffer *data ) {
  uint16_t length;
  uint16_t data_len = 0;
  buffer *buffer;
  struct ofp_error_msg *error_msg;

  if ( ( data != NULL ) && ( data->length > 0 ) ) {
    data_len = ( uint16_t ) data->length;
  }

  debug( "Creating an error ( xid = %#x, type = %#x, code = %#x, data length = %u ).",
         transaction_id, type, code, data_len );

  length = ( uint16_t ) ( sizeof( struct ofp_error_msg ) + data_len );
  buffer = create_header( transaction_id, OFPT_ERROR, length );
  assert( buffer != NULL );

  error_msg = ( struct ofp_error_msg * ) buffer->data;
  error_msg->type = htons( type );
  error_msg->code = htons( code );

  if ( data_len > 0 ) {
    memcpy( error_msg->data, data->data, data->length );
  }

  return buffer;
}


buffer *
create_error_experimenter( const uint32_t transaction_id, const uint16_t type,
                           const uint16_t exp_type, uint32_t experimenter,
                           const buffer *data ) {
  uint16_t length;
  uint16_t data_len = 0;
  buffer *buffer;
  struct ofp_error_experimenter_msg *experimenter_error_msg;

  if ( ( data != NULL ) && ( data->length > 0 ) ) {
    data_len = ( uint16_t ) data->length;
  }

  debug( "Creating an experimenter error ( xid = %#x, type = %#x, exp_type = %#x, experimenter = %#x, data length = %u ).",
         transaction_id, type, exp_type, experimenter, data_len );

  length = ( uint16_t ) ( sizeof( struct ofp_error_experimenter_msg ) + data_len );
  buffer = create_header( transaction_id, OFPT_ERROR, length );
  assert( buffer != NULL );

  experimenter_error_msg = ( struct ofp_error_experimenter_msg * ) buffer->data;
  experimenter_error_msg->type = htons( type );
  experimenter_error_msg->exp_type = htons( exp_type );
  experimenter_error_msg->experimenter = htonl( experimenter );

  if ( data_len > 0 ) {
    memcpy( experimenter_error_msg->data, data->data, data->length );
  }

  return buffer;
}


buffer *
create_hello_elem_versionbitmap( const uint8_t *ofp_versions, const uint16_t n_versions ) {
  assert( ofp_versions != NULL );
  assert( n_versions > 0 );

  int max_version = 0;
  for ( int i = 0; i < n_versions; i++ ) {
    if ( ofp_versions[ i ] > max_version ) {
      max_version = ofp_versions[ i ];
    }
  }
  size_t n_bitmaps = ( size_t ) ( max_version / 32 + 1 );

  uint16_t element_length = ( uint16_t ) ( offsetof( struct ofp_hello_elem_versionbitmap, bitmaps ) + n_bitmaps * sizeof( uint32_t ) );

  size_t buffer_length = ( size_t ) element_length + PADLEN_TO_64( element_length );
  buffer *buf = alloc_buffer_with_length( buffer_length );
  struct ofp_hello_elem_versionbitmap *element = append_back_buffer( buf, buffer_length );
  memset( element, 0, buffer_length );

  element->type = htons( OFPHET_VERSIONBITMAP );
  element->length = htons( element_length );

  for ( int i = 0; i < n_versions; i++ ) {
    int index = ofp_versions[ i ] / 32;
    uint32_t bit = ( uint32_t ) 1 << ( ofp_versions[ i ] - index * 32 );
    element->bitmaps[ index ] |= htonl( bit );
  }

  return buf;
}


buffer *
create_hello( const uint32_t transaction_id, const buffer *elements ) {
  uint16_t elements_length = 0;

  if ( ( elements != NULL ) && ( elements->length > 0 ) ) {
    elements_length = ( uint16_t ) elements->length;
  }

  debug( "Creating a hello ( xid = %#x, data length = %u ).", transaction_id, elements_length );

  buffer *hello = create_header( transaction_id, OFPT_HELLO, ( uint16_t ) ( sizeof( struct ofp_hello ) + elements_length ) );
  assert( hello != NULL );

  if ( elements_length > 0 ) {
    memcpy( ( char * ) hello->data + offsetof( struct ofp_hello, elements ), elements->data, elements_length );
  }

  return hello;
}


buffer *
create_echo_request( const uint32_t transaction_id, const buffer *body ) {
  uint16_t data_length = 0;

  if ( ( body != NULL ) && ( body->length > 0 ) ) {
    data_length = ( uint16_t ) body->length;
  }

  debug( "Creating an echo request ( xid = %#x, data length = %u ).", transaction_id, data_length );

  buffer *echo_request = create_header( transaction_id, OFPT_ECHO_REQUEST, ( uint16_t ) ( sizeof( struct ofp_header ) + data_length ) );
  assert( echo_request != NULL );

  if ( data_length > 0 ) {
    memcpy( ( char * ) echo_request->data + sizeof( struct ofp_header ), body->data, data_length );
  }

  return echo_request;
}


buffer *
create_echo_reply( const uint32_t transaction_id, const buffer *body ) {
  uint16_t data_length = 0;

  if ( ( body != NULL ) && ( body->length > 0 ) ) {
    data_length = ( uint16_t ) body->length;
  }

  debug( "Creating an echo reply ( xid = %#x, data length = %u ).", transaction_id, data_length );

  buffer *echo_reply = create_header( transaction_id, OFPT_ECHO_REPLY, ( uint16_t ) ( sizeof( struct ofp_header ) + data_length ) );
  assert( echo_reply != NULL );

  if ( data_length > 0 ) {
    memcpy( ( char * ) echo_reply->data + sizeof( struct ofp_header ), body->data, data_length );
  }

  return echo_reply;
}


buffer *
create_experimenter( const uint32_t transaction_id, const uint32_t experimenter,
                     const uint32_t exp_type, const buffer *data ) {
  void *d;
  uint16_t length;
  uint16_t data_length = 0;
  buffer *buffer;
  struct ofp_experimenter_header *experimenter_header;

  if ( ( data != NULL ) && ( data->length > 0 ) ) {
    data_length = ( uint16_t ) data->length;
  }

  debug( "Creating a experimenter ( xid = %#x, experimenter = %#x, exp_type = %#x, data length = %u ).",
         transaction_id, experimenter, exp_type, data_length );

  length =  ( uint16_t ) ( sizeof( struct ofp_experimenter_header ) + data_length );
  buffer = create_header( transaction_id, OFPT_EXPERIMENTER, length );
  assert( buffer != NULL );

  experimenter_header = ( struct ofp_experimenter_header * ) buffer->data;
  experimenter_header->experimenter = htonl( experimenter );
  experimenter_header->exp_type = htonl( exp_type );

  if ( data_length > 0 ) {
    d = ( void * ) ( ( char * ) buffer->data + sizeof( struct ofp_experimenter_header ) );
    memcpy( d, data->data, data_length );
  }

  return buffer;
}


buffer *
create_features_request( const uint32_t transaction_id ) {
  debug( "Creating a features request ( xid = %#x ).", transaction_id );

  return create_header( transaction_id, OFPT_FEATURES_REQUEST, sizeof( struct ofp_header ) );
}


buffer *
create_features_reply( const uint32_t transaction_id, const uint64_t datapath_id,
                       const uint32_t n_buffers, const uint8_t n_tables,
                       const uint8_t auxiliary_id, const uint32_t capabilities ) {
  buffer *buffer;
  struct ofp_switch_features *switch_features;

  debug( "Creating a features reply "
         "( xid = %#x, datapath_id = %#" PRIx64 ", n_buffers = %#x, n_tables = %#x, auxiliary_id = %#x, capabilities = %#x ).",
         transaction_id, datapath_id, n_buffers, n_tables, auxiliary_id, capabilities );

  buffer = create_header( transaction_id, OFPT_FEATURES_REPLY, sizeof( struct ofp_switch_features ) );
  assert( buffer != NULL );

  switch_features = ( struct ofp_switch_features * ) buffer->data;
  switch_features->datapath_id = htonll( datapath_id );
  switch_features->n_buffers = htonl( n_buffers );
  switch_features->n_tables = n_tables;
  switch_features->auxiliary_id = auxiliary_id;
  switch_features->capabilities = htonl( capabilities );
  switch_features->reserved = 0;

  return buffer;
}


buffer *
create_get_config_request( const uint32_t transaction_id ) {
  debug( "Creating a get config request ( xid = %#x ).", transaction_id );

  return create_header( transaction_id, OFPT_GET_CONFIG_REQUEST, sizeof( struct ofp_header ) );
}


buffer *
create_get_config_reply( const uint32_t transaction_id, const uint16_t flags,
                         const uint16_t miss_send_len ) {
  buffer *buffer;
  struct ofp_switch_config *switch_config;

  debug( "Creating a get config reply ( xid = %#x, flags = %#x, miss_send_len = %#x ).",
         transaction_id, flags, miss_send_len );

  buffer = create_header( transaction_id, OFPT_GET_CONFIG_REPLY, sizeof( struct ofp_switch_config ) );
  assert( buffer != NULL );

  switch_config = ( struct ofp_switch_config * ) buffer->data;
  switch_config->flags = htons( flags );
  switch_config->miss_send_len = htons( miss_send_len );

  return buffer;
}


buffer *
create_set_config( const uint32_t transaction_id, const uint16_t flags, uint16_t miss_send_len ) {
  debug( "Creating a set config ( xid = %#x, flags = %#x, miss_send_len = %#x ).",
         transaction_id, flags, miss_send_len );
  if ( ( miss_send_len > OFPCML_MAX ) && ( miss_send_len != OFPCML_NO_BUFFER ) ) {
    warn( "Invalid miss_send_len ( change %#x to %#x )", miss_send_len, OFPCML_MAX );
    miss_send_len = OFPCML_MAX;
  }


  buffer *set_config = create_header( transaction_id, OFPT_SET_CONFIG, sizeof( struct ofp_switch_config ) );
  assert( set_config != NULL );

  struct ofp_switch_config *switch_config = ( struct ofp_switch_config * ) set_config->data;
  switch_config->flags = htons( flags );
  switch_config->miss_send_len = htons( miss_send_len );
  return set_config;
}


buffer *
create_packet_in( const uint32_t transaction_id, const uint32_t buffer_id,
                  const uint16_t total_len, const uint8_t reason,
                  const uint8_t table_id, const uint64_t cookie,
                  const oxm_matches *match, const buffer *data ) {
  uint16_t length;
  uint16_t match_len;
  uint16_t pad_len = 2;
  uint16_t data_length = 0;
  char match_str[ MATCH_STRING_LENGTH ];
  buffer *buffer;
  struct ofp_packet_in *packet_in;
  void *d;

  if ( ( data != NULL ) && ( data->length > 0 ) ) {
    data_length = ( uint16_t ) data->length;
  }

  // Because match_to_string() is costly, we check logging_level first.
  if ( get_logging_level() >= LOG_DEBUG ) {
    match_to_string( match, match_str, sizeof( match_str ) );
    debug( "Creating a packet-in "
           "( xid = %#x, buffer_id = %#x, total_len = %#x, "
           "reason = %#x, table_id = %#x, cookie = %#" PRIx64 ", match = [%s], data length = %u ).",
           transaction_id, buffer_id, total_len,
           reason, table_id, cookie, match_str, data_length );
  }

  match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields ) + get_oxm_matches_length( match ) );
  match_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );
  length = ( uint16_t ) ( offsetof( struct ofp_packet_in, match ) + match_len + pad_len + data_length );
  buffer = create_header( transaction_id, OFPT_PACKET_IN, length );
  assert( buffer != NULL );

  packet_in = ( struct ofp_packet_in * ) buffer->data;
  packet_in->buffer_id = htonl( buffer_id );
  packet_in->total_len = htons( total_len );
  packet_in->reason = reason;
  packet_in->table_id = table_id;
  packet_in->cookie = htonll( cookie );
  construct_ofp_match( &packet_in->match, match );

  d = ( void * ) ( ( char * ) buffer->data + offsetof( struct ofp_packet_in, match ) + match_len );
  memset( d, 0, pad_len );

  if ( data_length > 0 ) {
    d = ( void * ) ( ( char * ) buffer->data
                     + offsetof( struct ofp_packet_in, match ) + match_len + pad_len );
    memcpy( d, data->data, data_length );
  }

  return buffer;
}


buffer *
create_flow_removed( const uint32_t transaction_id, const uint64_t cookie,
                     const uint16_t priority, const uint8_t reason, const uint8_t table_id,
                     const uint32_t duration_sec, const uint32_t duration_nsec,
                     const uint16_t idle_timeout, const uint16_t hard_timeout,
                     const uint64_t packet_count, const uint64_t byte_count,
                     const oxm_matches *match ) {
  uint16_t length;
  uint16_t match_len;
  char match_str[ MATCH_STRING_LENGTH ];
  buffer *buffer;
  
  struct ofp_flow_removed *flow_removed;

  // Because match_to_string() is costly, we check logging_level first.
  if ( get_logging_level() >= LOG_DEBUG ) {
    match_to_string( match, match_str, sizeof( match_str ) );
    debug( "Creating a flow removed "
           "( xid = %#x, cookie = %#" PRIx64 ", priority = %#x, "
           "reason = %#x, table_id = %#x, duration_sec = %#x, duration_nsec = %#x, "
           "idle_timeout = %#x, hard_timeout = %#x packet_count = %" PRIu64 ", byte_count = %" PRIu64 ", match = [%s] ).",
           transaction_id, cookie, priority,
           reason, table_id, duration_sec, duration_nsec,
           idle_timeout, hard_timeout, packet_count, byte_count, match_str );
  }

  match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields ) + get_oxm_matches_length( match ) );
  match_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );
  length = ( uint16_t ) ( offsetof( struct ofp_flow_removed, match ) + match_len );

  buffer = create_header( transaction_id, OFPT_FLOW_REMOVED, length );
  assert( buffer != NULL );

  flow_removed = ( struct ofp_flow_removed * ) buffer->data;
  flow_removed->cookie = htonll( cookie );
  flow_removed->priority = htons( priority );
  flow_removed->reason = reason;
  flow_removed->table_id = table_id;
  flow_removed->duration_sec = htonl( duration_sec );
  flow_removed->duration_nsec = htonl( duration_nsec );
  flow_removed->idle_timeout = htons( idle_timeout );
  flow_removed->hard_timeout = htons( hard_timeout );
  flow_removed->packet_count = htonll( packet_count );
  flow_removed->byte_count = htonll( byte_count );
  construct_ofp_match( &flow_removed->match, match );

  return buffer;
}


buffer *
create_port_status( const uint32_t transaction_id, const uint8_t reason,
                    const struct ofp_port desc) {
  char desc_str[ 1024 ];
  buffer *buffer;
  struct ofp_port d = desc;
  struct ofp_port_status *port_status;

  port_to_string( &d, desc_str, sizeof( desc_str ) );
  debug( "Creating a port status ( xid = %#x, reason = %#x, desc = [%s] ).",
         transaction_id, reason, desc_str );

  buffer = create_header( transaction_id, OFPT_PORT_STATUS, sizeof( struct ofp_port_status ) );
  assert( buffer != NULL );

  port_status = ( struct ofp_port_status * ) buffer->data;
  port_status->reason = reason;
  memset( &port_status->pad, 0, sizeof( port_status->pad ) );
  hton_port( &port_status->desc, &d );

  return buffer;
}


uint16_t
get_actions_length( const openflow_actions *actions ) {
  int actions_length = 0;
  struct ofp_action_header *action_header;
  list_element *action;

  debug( "Calculating the total length of actions." );

  assert( actions != NULL );

  action = actions->list;
  while ( action != NULL ) {
    action_header = ( struct ofp_action_header * ) action->data;

    switch ( action_header->type ) {
    case OFPAT_OUTPUT:
    case OFPAT_COPY_TTL_OUT:
    case OFPAT_COPY_TTL_IN:
    case OFPAT_SET_MPLS_TTL:
    case OFPAT_DEC_MPLS_TTL:
    case OFPAT_PUSH_VLAN:
    case OFPAT_POP_VLAN:
    case OFPAT_PUSH_MPLS:
    case OFPAT_POP_MPLS:
    case OFPAT_SET_QUEUE:
    case OFPAT_GROUP:
    case OFPAT_SET_NW_TTL:
    case OFPAT_DEC_NW_TTL:
    case OFPAT_SET_FIELD:
    case OFPAT_PUSH_PBB:
    case OFPAT_POP_PBB:
    case OFPAT_EXPERIMENTER:
      actions_length += action_header->len;
      break;
    default:
      critical( "Undefined action type ( type = %#x ).", action_header->type );
      assert( 0 );
      break;
    }

    action = action->next;
  }

  debug( "Total length of actions = %u.", actions_length );

  if ( actions_length > UINT16_MAX ) {
    critical( "Too many actions ( # of actions = %d, actions length = %u ).",
              actions->n_actions, actions_length );
    assert( 0 );
  }

  return ( uint16_t ) actions_length;
}


buffer *
create_packet_out( const uint32_t transaction_id, const uint32_t buffer_id,
                   const uint32_t in_port, const openflow_actions *actions,
                   const buffer *data ) {
  void *a, *d;
  uint16_t length;
  uint16_t data_length = 0;
  uint16_t action_length = 0;
  uint16_t actions_length = 0;
  buffer *buffer;
  struct ofp_packet_out *packet_out;
  struct ofp_action_header *action_header;
  list_element *action;

  if ( ( data != NULL ) && ( data->length > 0 ) ) {
    data_length = ( uint16_t ) data->length;
  }

  debug( "Creating a packet-out ( xid = %#x, buffer_id = %#x, in_port = %#x, data length = %u ).",
         transaction_id, buffer_id, in_port, data_length );

  if ( buffer_id == OFP_NO_BUFFER ) {
    if ( data == NULL ) {
      die( "An Ethernet frame must be provided if buffer_id is equal to %#x", OFP_NO_BUFFER );
    }
    if ( data->length + ETH_FCS_LENGTH < ETH_MINIMUM_LENGTH ) {
      die( "The length of the provided Ethernet frame is shorter than the minimum length of an Ethernet frame (= %d bytes).", ETH_MINIMUM_LENGTH );
    }
  }

  if ( actions != NULL ) {
    debug( "# of actions = %d.", actions->n_actions );
    actions_length = get_actions_length( actions );
  }

  length = ( uint16_t ) ( offsetof( struct ofp_packet_out, actions ) + actions_length + data_length );
  buffer = create_header( transaction_id, OFPT_PACKET_OUT, length );
  assert( buffer != NULL );

  packet_out = ( struct ofp_packet_out * ) buffer->data;
  packet_out->buffer_id = htonl( buffer_id );
  packet_out->in_port = htonl( in_port );
  packet_out->actions_len = htons( actions_length );

  if ( actions_length > 0 ) {
    a = ( void * ) ( ( char * ) buffer->data + offsetof( struct ofp_packet_out, actions ) );

    action = actions->list;
    while ( action != NULL ) {
      action_header = ( struct ofp_action_header * ) action->data;
      action_length = action_header->len;
      hton_action( ( struct ofp_action_header * ) a, action_header );
      a = ( void * ) ( ( char * ) a + action_length );
      action = action->next;
    }
  }

  if ( data_length > 0 ) {
    d = ( void * ) ( ( char * ) buffer->data
                     + offsetof( struct ofp_packet_out, actions ) + actions_length );
    memcpy( d, data->data, data_length );
  }

  return buffer;
}


uint16_t
get_instructions_length( const openflow_instructions *instructions ) {
  int instructions_length = 0;
  struct ofp_instruction *instruction;
  list_element *instruction_element;

  debug( "Calculating the total length of instructions." );

  assert( instructions != NULL );

  instruction_element = instructions->list;
  while ( instruction_element != NULL ) {
    instruction = ( struct ofp_instruction * ) instruction_element->data;

    switch ( instruction->type ) {
    case OFPIT_GOTO_TABLE:
    case OFPIT_WRITE_METADATA:
    case OFPIT_WRITE_ACTIONS:
    case OFPIT_APPLY_ACTIONS:
    case OFPIT_CLEAR_ACTIONS:
    case OFPIT_METER:
    case OFPIT_EXPERIMENTER:
      instructions_length += instruction->len;
      break;
    default:
      critical( "Undefined instruction type ( type = %#x ).", instruction->type );
      assert( 0 );
      break;
    }

    instruction_element = instruction_element->next;
  }

  debug( "Total length of instructions = %u.", instructions_length );

  if ( instructions_length > UINT16_MAX ) {
    critical( "Too many instructions ( # of instructions = %d, instructions length = %u ).",
              instructions->n_instructions, instructions_length );
    assert( 0 );
  }

  return ( uint16_t ) instructions_length;
}


buffer *
create_flow_mod( const uint32_t transaction_id, const uint64_t cookie, const uint64_t cookie_mask,
                 const uint8_t table_id, const uint8_t command, const uint16_t idle_timeout,
                 const uint16_t hard_timeout, const uint16_t priority,
                 const uint32_t buffer_id, const uint32_t out_port, const uint32_t out_group,
                 const uint16_t flags, const oxm_matches *match,
                 const openflow_instructions *instructions ) {
  void *inst;
  char match_str[ MATCH_STRING_LENGTH ];
  char inst_str[ 2048 ];
  uint16_t length;
  uint16_t match_len;
  uint16_t instruction_length = 0;
  uint16_t instructions_length = 0;
  buffer *buffer;
  struct ofp_flow_mod *flow_mod;
  struct ofp_instruction *instruction, *tmp_insts;
  list_element *instruction_element;

  if ( instructions != NULL ) {
    debug( "# of instructions = %d.", instructions->n_instructions );
    instructions_length = get_instructions_length( instructions );
  }

  // Because match_to_string() is costly, we check logging_level first.
  if ( get_logging_level() >= LOG_DEBUG ) {
    match_to_string( match, match_str, sizeof( match_str ) );
    inst_str[ 0 ] = '\0';
    if ( instructions != NULL ) {
      tmp_insts = xcalloc( 1, instructions_length );
      inst = ( void * ) tmp_insts;
      instruction_element = instructions->list;
      while ( instruction_element != NULL ) {
        instruction = ( struct ofp_instruction * ) instruction_element->data;
        instruction_length = instruction->len;
        memcpy( inst, instruction, instruction_length );
        inst = ( void * ) ( ( char * ) inst + instruction_length );
        instruction_element = instruction_element->next;
      }
      instructions_to_string( tmp_insts, instructions_length, inst_str, sizeof( inst_str ) );
      xfree( tmp_insts );
      tmp_insts = NULL;
    }
    debug( "Creating a flow modification "
           "( xid = %#x, cookie = %#" PRIx64 ", cookie_mask = %#" PRIx64 ", table_id = %#x, "
           "command = %#x, idle_timeout = %#x, hard_timeout = %#x, priority = %#x, "
           "buffer_id = %#x, out_port = %#x, out_group = %#X, flags = %#x, match = [%s], instructions = [%s] ).",
           transaction_id, cookie, cookie_mask, table_id, command,
           idle_timeout, hard_timeout, priority,
           buffer_id, out_port, out_group, flags, match_str, inst_str );
  }

  match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields ) + get_oxm_matches_length( match ) );
  match_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );
  length = ( uint16_t ) ( offsetof( struct ofp_flow_mod, match ) + match_len + instructions_length );
  buffer = create_header( transaction_id, OFPT_FLOW_MOD, length );
  assert( buffer != NULL );

  flow_mod = ( struct ofp_flow_mod * ) buffer->data;
  flow_mod->cookie = htonll( cookie );
  flow_mod->cookie_mask = htonll( cookie_mask );
  flow_mod->table_id = table_id;
  flow_mod->command = command;
  flow_mod->idle_timeout = htons( idle_timeout );
  flow_mod->hard_timeout = htons( hard_timeout );
  flow_mod->priority = htons( priority );
  flow_mod->buffer_id = htonl( buffer_id );
  flow_mod->out_port = htonl( out_port );
  flow_mod->out_group = htonl( out_group );
  flow_mod->flags = htons( flags );
  memset( &flow_mod->pad, 0, sizeof( flow_mod->pad ) );
  construct_ofp_match( &flow_mod->match, match );

  if ( instructions_length > 0 ) {
    inst = ( void * ) ( ( char * ) buffer->data + offsetof( struct ofp_flow_mod, match ) + match_len );

    instruction_element = instructions->list;
    while ( instruction_element != NULL ) {
      instruction = ( struct ofp_instruction * ) instruction_element->data;
      instruction_length = instruction->len;
      hton_instruction( ( struct ofp_instruction * ) inst, instruction );
      inst = ( void * ) ( ( char * ) inst + instruction_length );
      instruction_element = instruction_element->next;
    }
  }

  return buffer;
}


buffer *
create_group_mod( const uint32_t transaction_id, const uint16_t command,
                  const uint8_t type, const uint32_t group_id, const openflow_buckets *buckets ) {
  uint16_t length = 0;
  uint16_t bucket_length = 0;
  uint16_t buckets_length = 0;
  buffer *buffer;
  struct ofp_group_mod *group_mod;
  struct ofp_bucket *bucket_src, *bucket_dst;
  list_element *bucket_element;

  debug( "Creating a group modification "
         "( xid = %#x, command = %#x, type = %#x, group_id = %#x ).",
         transaction_id, command, type, group_id );

  if ( buckets != NULL ) {
    debug( "# of buckets = %u.", buckets->n_buckets );
    buckets_length = get_buckets_length( buckets );
  }

  length = ( uint16_t ) ( offsetof( struct ofp_group_mod, buckets ) + buckets_length );

  buffer = create_header( transaction_id, OFPT_GROUP_MOD, length );
  assert( buffer != NULL );

  group_mod = ( struct ofp_group_mod * ) buffer->data;
  group_mod->command = htons( command );
  group_mod->type = type;
  memset( &group_mod->pad, 0, sizeof( group_mod->pad ) );
  group_mod->group_id = htonl( group_id );

  if ( buckets_length > 0 ) {
    bucket_dst = ( struct ofp_bucket * ) ( ( char * ) buffer->data + offsetof( struct ofp_group_mod, buckets ) );
    bucket_element = buckets->list;
    while ( bucket_element != NULL ) {
      bucket_src = ( struct ofp_bucket * ) bucket_element->data;
      bucket_length = bucket_src->len;
      hton_bucket( bucket_dst, bucket_src );
      bucket_dst = ( struct ofp_bucket * ) ( ( char * ) bucket_dst + bucket_length );
      bucket_element = bucket_element->next;
    }
  }

  return buffer;
}


buffer *
create_port_mod( const uint32_t transaction_id, const uint32_t port_no,
                 const uint8_t hw_addr[ OFP_ETH_ALEN ], const uint32_t config,
                 const uint32_t mask, const uint32_t advertise ) {
  buffer *buffer;
  struct ofp_port_mod *port_mod;

  debug( "Creating a port modification "
         "( xid = %#x, port_no = %#x, hw_addr = %02x:%02x:%02x:%02x:%02x:%02x, "
         "config = %#x, mask = %#x, advertise = %#x ).",
         transaction_id, port_no,
         hw_addr[ 0 ], hw_addr[ 1 ], hw_addr[ 2 ], hw_addr[ 3 ], hw_addr[ 4 ], hw_addr[ 5 ],
         config, mask, advertise );

  buffer = create_header( transaction_id, OFPT_PORT_MOD, sizeof( struct ofp_port_mod ) );
  assert( buffer != NULL );

  port_mod = ( struct ofp_port_mod * ) buffer->data;
  port_mod->port_no = htonl( port_no );
  memcpy( port_mod->hw_addr, hw_addr, OFP_ETH_ALEN );
  port_mod->config = htonl( config );
  port_mod->mask = htonl( mask );
  port_mod->advertise = htonl( advertise );
  memset( &port_mod->pad, 0, sizeof( port_mod->pad ) );

  return buffer;
}


buffer *
create_table_mod( const uint32_t transaction_id, const uint8_t table_id, uint32_t config ) {
  buffer *buffer;
  struct ofp_table_mod *table_mod;

  debug( "Creating a table modification ( xid = %#x, table_id = %#x, config = %#x ).",
         transaction_id, table_id, config );

  buffer = create_header( transaction_id, OFPT_TABLE_MOD, sizeof( struct ofp_table_mod ) );
  assert( buffer != NULL );

  table_mod = ( struct ofp_table_mod * ) buffer->data;
  table_mod->table_id = table_id;
  memset( &table_mod->pad, 0, sizeof( table_mod->pad ) );
  table_mod->config = htonl( config );

  return buffer;
}


static buffer *
create_multipart_request( const uint32_t transaction_id, const uint16_t type,
                          const uint16_t length, const uint16_t flags ) {
  buffer *buffer;
  struct ofp_multipart_request *multipart_request;

  debug( "Creating a multipart request ( xid = %#x, type = %#x, length = %u, flags = %#x ).",
         transaction_id, type, length, flags );

  buffer = create_header( transaction_id, OFPT_MULTIPART_REQUEST, length );
  assert( buffer != NULL );

  multipart_request = ( struct ofp_multipart_request * ) buffer->data;
  multipart_request->type = htons( type );
  multipart_request->flags = htons( flags );
  memset( &multipart_request->pad, 0, sizeof( multipart_request->pad ) );

  return buffer;
}


buffer *
create_desc_multipart_request( const uint32_t transaction_id, const uint16_t flags ) {
  debug( "Creating a description multipart request ( xid = %#x, flags = %#x ).",
         transaction_id, flags );

  return create_multipart_request( transaction_id, OFPMP_DESC,
                               sizeof( struct ofp_multipart_request ), flags );
}


buffer *
create_flow_multipart_request( const uint32_t transaction_id, const uint16_t flags,
                               const uint8_t table_id, const uint32_t out_port,
                               const uint32_t out_group, const uint64_t cookie,
                               const uint64_t cookie_mask, const oxm_matches *match ) {
  char match_str[ MATCH_STRING_LENGTH ];
  uint16_t length;
  uint16_t match_len;
  buffer *buffer;
  struct ofp_flow_stats_request *flow_multipart_request;

  // Because match_to_string() is costly, we check logging_level first.
  if ( get_logging_level() >= LOG_DEBUG ) {
    match_to_string( match, match_str, sizeof( match_str ) );
    debug( "Creating a flow multipart request ( xid = %#x, flags = %#x, table_id = %#x, out_port = %#x, "
           "out_group = %#x, cookie = %#" PRIx64 ", cookie_mask = %#" PRIx64 ", match = [%s] ).",
           transaction_id, flags, table_id, out_port, out_group, cookie, cookie_mask, match_str );
  }

  match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields ) + get_oxm_matches_length( match ) );
  match_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );
  length = ( uint16_t ) ( offsetof( struct ofp_multipart_request, body )
                         + offsetof( struct ofp_flow_stats_request, match ) + match_len );
  buffer = create_multipart_request( transaction_id, OFPMP_FLOW, length, flags );
  assert( buffer != NULL );

  flow_multipart_request = ( struct ofp_flow_stats_request * ) ( ( char * ) buffer->data
                       + offsetof( struct ofp_multipart_request, body ) );
  flow_multipart_request->table_id = table_id;
  memset( &flow_multipart_request->pad, 0, sizeof( flow_multipart_request->pad ) );
  flow_multipart_request->out_port = htonl( out_port );
  flow_multipart_request->out_group = htonl( out_group );
  memset( &flow_multipart_request->pad2, 0, sizeof( flow_multipart_request->pad2 ) );
  flow_multipart_request->cookie = htonll( cookie );
  flow_multipart_request->cookie_mask = htonll( cookie_mask );
  construct_ofp_match( &flow_multipart_request->match, match );

  return buffer;
}


buffer *
create_aggregate_multipart_request( const uint32_t transaction_id,
                                    const uint16_t flags, const uint8_t table_id,
                                    const uint32_t out_port, const uint32_t out_group,
                                    const uint64_t cookie, const uint64_t cookie_mask,
                                    const oxm_matches *match ) {
  char match_str[ MATCH_STRING_LENGTH ];
  uint16_t length;
  uint16_t match_len;
  buffer *buffer;
  struct ofp_aggregate_stats_request *aggregate_multipart_request;

  // Because match_to_string() is costly, we check logging_level first.
  if ( get_logging_level() >= LOG_DEBUG ) {
    match_to_string( match, match_str, sizeof( match_str ) );
    debug( "Creating an aggregate multipart request ( xid = %#x, flags = %#x, table_id = %#x, out_port = %#x, "
           "out_group = %#x, cookie = %#" PRIx64 ", cookie_mask = %#" PRIx64 ", match = [%s] ).",
           transaction_id, flags, table_id, out_port, out_group, cookie, cookie_mask, match_str );
  }

  match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields ) + get_oxm_matches_length( match ) );
  match_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );
  length = ( uint16_t ) ( offsetof( struct ofp_multipart_request, body )
           + offsetof( struct ofp_aggregate_stats_request, match ) + match_len );
  buffer = create_multipart_request( transaction_id, OFPMP_AGGREGATE, length, flags );
  assert( buffer != NULL );

  aggregate_multipart_request = ( struct ofp_aggregate_stats_request * ) ( ( char * ) buffer->data
                            + offsetof( struct ofp_multipart_request, body ) );
  aggregate_multipart_request->table_id = table_id;
  memset( &aggregate_multipart_request->pad, 0, sizeof( aggregate_multipart_request->pad ) );
  aggregate_multipart_request->out_port = htonl( out_port );
  aggregate_multipart_request->out_group = htonl( out_group );
  memset( &aggregate_multipart_request->pad2, 0, sizeof( aggregate_multipart_request->pad2 ) );
  aggregate_multipart_request->cookie = htonll( cookie );
  aggregate_multipart_request->cookie_mask = htonll( cookie_mask );
  construct_ofp_match( &aggregate_multipart_request->match, match );

  return buffer;
}


buffer *
create_table_multipart_request( const uint32_t transaction_id, const uint16_t flags ) {
  debug( "Creating a table multipart request ( xid = %#x, flags = %#x ).", transaction_id, flags );

  return create_multipart_request( transaction_id, OFPMP_TABLE,
                               sizeof( struct ofp_multipart_request ), flags );
}


buffer *
create_port_multipart_request( const uint32_t transaction_id, const uint16_t flags,
                               const uint32_t port_no ) {
  uint16_t length;
  buffer *buffer;
  struct ofp_port_stats_request *port_multipart_request;

  debug( "Creating a port multipart request ( xid = %#x, flags = %#x, port_no = %#x ).",
         transaction_id, flags, port_no );

  length = ( uint16_t ) ( offsetof( struct ofp_multipart_request, body )
           + sizeof( struct ofp_port_stats_request ) );
  buffer = create_multipart_request( transaction_id, OFPMP_PORT_STATS, length, flags );
  assert( buffer != NULL );

  port_multipart_request = ( struct ofp_port_stats_request * ) ( ( char * ) buffer->data
                       + offsetof( struct ofp_multipart_request, body ) );
  port_multipart_request->port_no = htonl( port_no );
  memset( &port_multipart_request->pad, 0, sizeof( port_multipart_request->pad ) );

  return buffer;
}


buffer *
create_queue_multipart_request( const uint32_t transaction_id, const uint16_t flags,
                                const uint32_t port_no, const uint32_t queue_id ) {
  uint16_t length;
  buffer *buffer;
  struct ofp_queue_stats_request *queue_multipart_request;

  debug( "Creating a queue multipart request ( xid = %#x, flags = %#x, port_no = %#x, queue_id = %#x ).",
         transaction_id, flags, port_no, queue_id );

  length = ( uint16_t ) ( offsetof( struct ofp_multipart_request, body )
                        + sizeof( struct ofp_queue_stats_request ) );
  buffer = create_multipart_request( transaction_id, OFPMP_QUEUE, length, flags );
  assert( buffer != NULL );

  queue_multipart_request = ( struct ofp_queue_stats_request * ) ( ( char * ) buffer->data
                        + offsetof( struct ofp_multipart_request, body ) );
  queue_multipart_request->port_no = htonl( port_no );
  queue_multipart_request->queue_id = htonl( queue_id );

  return buffer;
}


buffer *
create_group_multipart_request( const uint32_t transaction_id, const uint16_t flags,
                                const uint32_t group_id ) {
  uint16_t length;
  buffer *buffer;
  struct ofp_group_stats_request *group_multipart_request;

  debug( "Creating a group multipart request ( xid = %#x, flags = %#x, group_id = %#x ).",
         transaction_id, flags, group_id );

  length = ( uint16_t ) ( offsetof( struct ofp_multipart_request, body )
                        + sizeof( struct ofp_group_stats_request ) );
  buffer = create_multipart_request( transaction_id, OFPMP_GROUP, length, flags );
  assert( buffer != NULL );

  group_multipart_request = ( struct ofp_group_stats_request * ) ( ( char * ) buffer->data
                        + offsetof( struct ofp_multipart_request, body ) );
  group_multipart_request->group_id = htonl( group_id );
  memset( &group_multipart_request->pad, 0, sizeof( group_multipart_request->pad ) );

  return buffer;
}


buffer *
create_group_desc_multipart_request( const uint32_t transaction_id, const uint16_t flags ) {
  debug( "Creating a group desc multipart request ( xid = %#x, flags = %#x ).", transaction_id, flags );

  return create_multipart_request( transaction_id, OFPMP_GROUP_DESC,
                                   sizeof( struct ofp_multipart_request ), flags );
}


buffer *
create_group_features_multipart_request( const uint32_t transaction_id, const uint16_t flags ) {
  debug( "Creating a group features multipart request ( xid = %#x, flags = %#x ).", transaction_id, flags );

  return create_multipart_request( transaction_id, OFPMP_GROUP_FEATURES,
                                   sizeof( struct ofp_multipart_request ), flags );
}


buffer *
create_meter_multipart_request( const uint32_t transaction_id, const uint16_t flags,
                                const uint32_t meter_id ) {
  uint16_t length;
  buffer *buffer;
  struct ofp_meter_multipart_request *meter_multipart_request;

  debug( "Creating a meter multipart request ( xid = %#x, flags = %#x, meter_id = %#x ).",
         transaction_id, flags, meter_id );

  length = ( uint16_t ) ( offsetof( struct ofp_multipart_request, body )
                        + sizeof( struct ofp_meter_multipart_request ) );
  buffer = create_multipart_request( transaction_id, OFPMP_METER, length, flags );
  assert( buffer != NULL );

  meter_multipart_request = ( struct ofp_meter_multipart_request * ) ( ( char * ) buffer->data
                        + offsetof( struct ofp_multipart_request, body ) );
  meter_multipart_request->meter_id = htonl( meter_id );
  memset( &meter_multipart_request->pad, 0, sizeof( meter_multipart_request->pad ) );

  return buffer;
}


buffer *
create_meter_config_multipart_request( const uint32_t transaction_id, const uint16_t flags,
                                       const uint32_t meter_id ) {
  uint16_t length;
  buffer *buffer;
  struct ofp_meter_multipart_request *meter_config_multipart_request;

  debug( "Creating a meter config multipart request ( xid = %#x, flags = %#x, meter_id = %#x ).",
         transaction_id, flags, meter_id );

  length = ( uint16_t ) ( offsetof( struct ofp_multipart_request, body )
                        + sizeof( struct ofp_meter_multipart_request ) );
  buffer = create_multipart_request( transaction_id, OFPMP_METER_CONFIG, length, flags );
  assert( buffer != NULL );

  meter_config_multipart_request = ( struct ofp_meter_multipart_request * ) ( ( char * ) buffer->data
                                   + offsetof( struct ofp_multipart_request, body ) );
  meter_config_multipart_request->meter_id = htonl( meter_id );
  memset( &meter_config_multipart_request->pad, 0, sizeof( meter_config_multipart_request->pad ) );

  return buffer;
}


buffer *
create_meter_features_multipart_request( const uint32_t transaction_id, const uint16_t flags ) {
  debug( "Creating a meter features multipart request ( xid = %#x, flags = %#x ).", transaction_id, flags );

  return create_multipart_request( transaction_id, OFPMP_METER_FEATURES,
                               sizeof( struct ofp_multipart_request ), flags );

}


buffer *
create_table_features_multipart_request( const uint32_t transaction_id, const uint16_t flags,
                                         const list_element *table_features_head ) {
  int n_tblftrs = 0;
  uint16_t tblftrs_len = 0;
  uint16_t length;
  buffer *buffer;
  list_element *l = NULL, *list = NULL;
  struct ofp_multipart_request *stats_request;
  struct ofp_table_features *tblftr, *table_features;

  debug( "Creating a table features multipart request ( xid = %#x, flags = %#x ).", transaction_id, flags );

  if ( table_features_head != NULL ) {
    l = ( list_element * ) xmalloc( sizeof( list_element ) );
    memcpy( l, table_features_head, sizeof( list_element ) );
  }

  list = l;
  while ( list != NULL ) {
    table_features = ( struct ofp_table_features * ) list->data;
    tblftrs_len = ( uint16_t ) ( tblftrs_len + table_features->length );
    n_tblftrs++;
    list = list->next;
  }

  debug( "# of table_features = %u.", n_tblftrs );
  length = ( uint16_t ) ( offsetof( struct ofp_multipart_request, body )
                        + tblftrs_len );
  buffer = create_multipart_request( transaction_id, OFPMP_TABLE_FEATURES, length, flags );
  assert( buffer != NULL );

  stats_request = ( struct ofp_multipart_request * ) buffer->data;
  tblftr = ( struct ofp_table_features * ) stats_request->body;

  list = l;
  while ( list != NULL ) {
    table_features = ( struct ofp_table_features * ) list->data;
    hton_table_features( tblftr, table_features );
    tblftr = ( struct ofp_table_features * ) ( ( char * ) tblftr + table_features->length );
    list = list->next;
  }

  if ( l != NULL ) {
    xfree( l );
  }

  return buffer;
}


buffer *
create_port_desc_multipart_request( const uint32_t transaction_id, const uint16_t flags ) {
  debug( "Creating a port desc multipart request ( xid = %#x, flags = %#x ).", transaction_id, flags );

  return create_multipart_request( transaction_id, OFPMP_PORT_DESC,
                                   sizeof( struct ofp_multipart_request ), flags );
}


buffer *
create_experimenter_multipart_request( const uint32_t transaction_id, const uint16_t flags,
                                       const uint32_t experimenter, const uint32_t exp_type, const buffer *data ) {
  uint16_t length;
  buffer *buffer;
  uint16_t data_length = 0;
  void *d;
  struct ofp_experimenter_multipart_header *experimenter_multipart_request;

  if ( ( data != NULL ) && ( data->length > 0 ) ) {
    data_length = ( uint16_t ) data->length;
  }

  debug( "Creating a experimenter multipart request ( xid = %#x, flags = %#x,"
         " experimenter = %#x, exp_type = %#x, data length = %u ).",
         transaction_id, flags, experimenter, exp_type, data_length );

  length = ( uint16_t ) ( offsetof( struct ofp_multipart_request, body )
                        + sizeof( struct ofp_experimenter_multipart_header )
                        + data_length );
  buffer = create_multipart_request( transaction_id, OFPMP_EXPERIMENTER, length, flags );
  assert( buffer != NULL );

  experimenter_multipart_request = ( struct ofp_experimenter_multipart_header * ) ( ( char * ) buffer->data
                        + offsetof( struct ofp_multipart_request, body ) );
  experimenter_multipart_request->experimenter = htonl( experimenter );
  experimenter_multipart_request->exp_type = htonl( exp_type );

  if ( data_length > 0 ) {
    d = ( void * ) ( ( char * ) experimenter_multipart_request + sizeof( struct ofp_experimenter_multipart_header ) );
    memcpy( d, data->data, data_length );
  }

  return buffer;
}


static buffer *
create_multipart_reply( const uint32_t transaction_id, const uint16_t type,
                        const uint16_t length, const uint16_t flags ) {
  buffer *buffer;
  struct ofp_multipart_reply *multipart_reply;

  debug( "Creating a multipart reply ( xid = %#x, type = %#x, length = %u, flags = %#x ).",
         transaction_id, type, length, flags );

  buffer = create_header( transaction_id, OFPT_MULTIPART_REPLY, length );
  assert( buffer != NULL );

  multipart_reply = ( struct ofp_multipart_reply * ) buffer->data;
  multipart_reply->type = htons( type );
  multipart_reply->flags = htons( flags );

  return buffer;
}


buffer *
create_desc_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                             const char mfr_desc[ DESC_STR_LEN ],
                             const char hw_desc[ DESC_STR_LEN ],
                             const char sw_desc[ DESC_STR_LEN ],
                             const char serial_num[ SERIAL_NUM_LEN ],
                             const char dp_desc[ DESC_STR_LEN ] ) {
  uint16_t length;
  buffer *buffer;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_desc *desc_stats;

  debug( "Creating a description multipart reply "
         "( xid = %#x, flags = %#x, mfr_desc = %s, hw_desc = %s, sw_desc = %s, serial_num = %s, dp_desc = %s ).",
         transaction_id, flags, mfr_desc, hw_desc, sw_desc, serial_num, dp_desc );

  length = ( uint16_t ) ( offsetof( struct ofp_multipart_reply, body )
                        + sizeof( struct ofp_desc ) );
  buffer = create_multipart_reply( transaction_id, OFPMP_DESC, length, flags );
  assert( buffer != NULL );

  stats_reply = ( struct ofp_multipart_reply * ) buffer->data;
  desc_stats = ( struct ofp_desc * ) stats_reply->body;
  memcpy( desc_stats->mfr_desc, mfr_desc, DESC_STR_LEN );
  memcpy( desc_stats->hw_desc, hw_desc, DESC_STR_LEN );
  memcpy( desc_stats->sw_desc, sw_desc, DESC_STR_LEN );
  memcpy( desc_stats->serial_num, serial_num, SERIAL_NUM_LEN );
  memcpy( desc_stats->dp_desc, dp_desc, DESC_STR_LEN );

  return buffer;
}


buffer *
create_flow_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                             const list_element *flows_stats_head, int *more, int *offset ) {
  int n_flows = 0;
  uint16_t msg_flags = flags;
  uint16_t length = 0;
  buffer *buffer;
  list_element *f = NULL;
  list_element *flow = NULL;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_flow_stats *fs, *flow_stats;

  debug( "Creating a flow multipart reply ( xid = %#x, flags = %#x ).", transaction_id, flags );

  if ( flows_stats_head != NULL ) {
    int cur = 0;
    while ( offset != NULL && cur < *offset ) {
      flows_stats_head = flows_stats_head->next;
      cur++;
    }
    f = ( list_element * ) xmalloc( sizeof( list_element ) );
    memcpy( f, flows_stats_head, sizeof( list_element ) );
  }

  flow = f;
  *more = 0;
  while ( flow != NULL ) {
    flow_stats = flow->data;
    if ( offsetof( struct ofp_multipart_reply, body )
         + length + flow_stats->length > ( size_t ) UINT16_MAX ) {
      *more = 1;
      msg_flags |= OFPMPF_REPLY_MORE;
      break;
    }
    length = ( uint16_t ) ( length + flow_stats->length );
    n_flows++;
    flow = flow->next;
  }

  debug( "# of flows = %u.", n_flows );

  length = ( uint16_t ) ( offsetof( struct ofp_multipart_reply, body ) + length );

  buffer = create_multipart_reply( transaction_id, OFPMP_FLOW, length, msg_flags );
  assert( buffer != NULL );

  stats_reply = ( struct ofp_multipart_reply * ) buffer->data;
  flow_stats = ( struct ofp_flow_stats * ) stats_reply->body;

  flow = f;
  int n_data = 0;
  while ( flow != NULL && n_data < n_flows ) {
    fs = ( struct ofp_flow_stats * ) flow->data;
    hton_flow_stats( flow_stats, fs );
    flow_stats = ( struct ofp_flow_stats * ) ( ( char * ) flow_stats + fs->length );
    flow = flow->next;
    n_data++;
  }

  *offset += n_flows;
  if ( f != NULL ) {
    xfree( f );
  }

  return buffer;
}


buffer *
create_aggregate_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                                  const uint64_t packet_count, const uint64_t byte_count,
                                  const uint32_t flow_count ) {
  uint16_t length;
  buffer *buffer;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_aggregate_stats_reply *aggregate_stats_reply;

  debug( "Creating an aggregate multipart reply "
         "( xid = %#x, flags = %#x, packet_count = %" PRIu64 ", byte_count = %" PRIu64 ", flow_count = %u ).",
         transaction_id, flags, packet_count, byte_count, flow_count );

  length = ( uint16_t ) ( offsetof( struct ofp_multipart_reply, body )
                        + sizeof( struct ofp_aggregate_stats_reply ) );
  buffer = create_multipart_reply( transaction_id, OFPMP_AGGREGATE, length, flags );
  assert( buffer != NULL );

  stats_reply = ( struct ofp_multipart_reply * ) buffer->data;
  aggregate_stats_reply = ( struct ofp_aggregate_stats_reply * ) stats_reply->body;
  aggregate_stats_reply->packet_count = htonll( packet_count );
  aggregate_stats_reply->byte_count = htonll( byte_count );
  aggregate_stats_reply->flow_count = htonl( flow_count );
  memset( &aggregate_stats_reply->pad, 0, sizeof( aggregate_stats_reply->pad ) );

  return buffer;
}


buffer *
create_table_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                              const list_element *table_stats_head, int *more, int *offset ) {
  uint16_t length;
  uint16_t msg_flags = flags;
  uint16_t n_tables = 0;
  buffer *buffer;
  list_element *t = NULL;
  list_element *table = NULL;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_table_stats *ts, *table_stats;

  debug( "Creating a table multipart reply ( xid = %#x, flags = %#x ).", transaction_id, flags );

  if ( table_stats_head != NULL ) {
    int cur = 0;
    while ( offset != NULL && cur < *offset ) {
      table_stats_head = table_stats_head->next;
      cur++;
    }
    t = ( list_element * ) xmalloc( sizeof( list_element ) );
    memcpy( t, table_stats_head, sizeof( list_element ) );
  }

  table = t;
  *more = 0;
  while ( table != NULL ) {
    if ( offsetof( struct ofp_multipart_reply, body )
         + sizeof( struct ofp_table_stats ) * ( ( size_t ) n_tables + 1 ) > ( size_t ) UINT16_MAX ) {
      *more = 1;
      msg_flags |= OFPMPF_REPLY_MORE;
      break;
    }
    n_tables++;
    table = table->next;
  }

  debug( "# of tables = %u.", n_tables );

  length = ( uint16_t ) ( offsetof( struct ofp_multipart_reply, body )
                        + sizeof( struct ofp_table_stats ) * n_tables );
  buffer = create_multipart_reply( transaction_id, OFPMP_TABLE, length, msg_flags );
  assert( buffer != NULL );

  stats_reply = ( struct ofp_multipart_reply * ) buffer->data;
  table_stats = ( struct ofp_table_stats * ) stats_reply->body;

  table = t;
  int n_data = 0;
  while ( table != NULL && n_data < n_tables ) {
    ts = ( struct ofp_table_stats * ) table->data;
    hton_table_stats( table_stats, ts );
    table = table->next;
    table_stats++;
    n_data++;
  }

  *offset += n_tables;
  if ( t != NULL ) {
    xfree( t );
  }

  return buffer;
}


buffer *
create_port_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                             const list_element *port_stats_head, int *more, int *offset ) {
  uint16_t length;
  uint16_t msg_flags = flags;
  uint16_t n_ports = 0;
  buffer *buffer;
  list_element *p = NULL;
  list_element *port = NULL;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_port_stats *ps, *port_stats;

  debug( "Creating a port multipart reply ( xid = %#x, flags = %#x ).", transaction_id, flags );

  if ( port_stats_head != NULL ) {
    int cur = 0;
    while ( offset != NULL && cur < *offset ) {
      port_stats_head = port_stats_head->next;
      cur++;
    }
    p = ( list_element * ) xmalloc( sizeof( list_element ) );
    memcpy( p, port_stats_head, sizeof( list_element ) );
  }

  port = p;
  *more = 0;
  while ( port != NULL ) {
    if ( offsetof( struct ofp_multipart_reply, body )
         + sizeof( struct ofp_port_stats ) * ( ( size_t ) n_ports + 1 ) > ( size_t ) UINT16_MAX ) {
      *more = 1;
      msg_flags |= OFPMPF_REPLY_MORE;
      break;
    }
    n_ports++;
    port = port->next;
  }

  debug( "# of ports = %u.", n_ports );

  length = ( uint16_t ) ( offsetof( struct ofp_multipart_reply, body )
                          + sizeof( struct ofp_port_stats ) * n_ports );
  buffer = create_multipart_reply( transaction_id, OFPMP_PORT_STATS, length, msg_flags );
  assert( buffer != NULL );

  stats_reply = ( struct ofp_multipart_reply * ) buffer->data;
  port_stats = ( struct ofp_port_stats * ) stats_reply->body;

  port = p;
  int n_data = 0;
  while ( port != NULL && n_data < n_ports ) {
    ps = ( struct ofp_port_stats * ) port->data;
    hton_port_stats( port_stats, ps );
    port = port->next;
    port_stats++;
    n_data++;
  }

  *offset += n_ports;
  if ( p != NULL ) {
    xfree( p );
  }

  return buffer;
}


buffer *
create_queue_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                              const list_element *queue_stats_head, int *more, int *offset ) {
  uint16_t length;
  uint16_t msg_flags = flags;
  uint16_t n_queues = 0;
  buffer *buffer;
  list_element *q = NULL;
  list_element *queue = NULL;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_queue_stats *qs, *queue_stats;

  debug( "Creating a queue multipart reply ( xid = %#x, flags = %#x ).", transaction_id, flags );

  if ( queue_stats_head != NULL ) {
    int cur = 0;
    while ( offset != NULL && cur < *offset ) {
      queue_stats_head = queue_stats_head->next;
      cur++;
    }
    q = ( list_element * ) xmalloc( sizeof( list_element ) );
    memcpy( q, queue_stats_head, sizeof( list_element ) );
  }

  queue = q;
  *more = 0;
  while ( queue != NULL ) {
    if ( offsetof( struct ofp_multipart_reply, body )
         + sizeof( struct ofp_queue_stats ) * ( ( size_t ) n_queues + 1 ) > ( size_t ) UINT16_MAX ) {
      *more = 1;
      msg_flags |= OFPMPF_REPLY_MORE;
      break;
    }
    n_queues++;
    queue = queue->next;
  }

  debug( "# of queues = %u.", n_queues );

  length = ( uint16_t ) ( offsetof( struct ofp_multipart_reply, body )
                          + sizeof( struct ofp_queue_stats ) * n_queues );
  buffer = create_multipart_reply( transaction_id, OFPMP_QUEUE, length, msg_flags );
  assert( buffer != NULL );

  stats_reply = ( struct ofp_multipart_reply * ) buffer->data;
  queue_stats = ( struct ofp_queue_stats * ) stats_reply->body;

  queue = q;
  int n_data = 0;
  while ( queue != NULL && n_data < n_queues ) {
    qs = ( struct ofp_queue_stats * ) queue->data;
    hton_queue_stats( queue_stats, qs );
    queue = queue->next;
    queue_stats++;
    n_data++;
  }

  *offset += n_queues;
  if ( q != NULL ) {
    xfree( q );
  }

  return buffer;
}


buffer *
create_group_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                              const list_element *group_multipart_head, int *more, int *offset ) {
  uint16_t length;
  uint16_t msg_flags = flags;
  uint16_t n_queues = 0;
  uint16_t queues_len = 0;
  buffer *buffer;
  list_element *q = NULL;
  list_element *queue = NULL;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_group_stats *qs, *group_stats;

  debug( "Creating a group multipart reply ( xid = %#x, flags = %#x ).", transaction_id, flags );

  if ( group_multipart_head != NULL ) {
    int cur = 0;
    while ( offset != NULL && cur < *offset ){
      group_multipart_head = group_multipart_head->next;
      cur++;
    }
    q = ( list_element * ) xmalloc( sizeof( list_element ) );
    memcpy( q, group_multipart_head, sizeof( list_element ) );
  }

  queue = q;
  *more = 0;
  while ( queue != NULL ) {
    group_stats = ( struct ofp_group_stats * ) queue->data;
    if ( offsetof( struct ofp_multipart_reply, body )
         + queues_len + group_stats->length > UINT16_MAX ) {
      *more = 1;
      msg_flags |= OFPMPF_REPLY_MORE;
      break;
    }
    queues_len = ( uint16_t ) ( queues_len + group_stats->length );
    queue = queue->next;
    n_queues++;
  }

  debug( "# of groups = %u.", n_queues );

  length = ( uint16_t ) ( offsetof( struct ofp_multipart_reply, body )
                          + queues_len );
  buffer = create_multipart_reply( transaction_id, OFPMP_GROUP, length, msg_flags );
  assert( buffer != NULL );

  stats_reply = ( struct ofp_multipart_reply * ) buffer->data;
  group_stats = ( struct ofp_group_stats * ) stats_reply->body;

  queue = q;
  int n_data = 0;
  while ( queue != NULL && n_data < n_queues) {
    qs = ( struct ofp_group_stats * ) queue->data;
    hton_group_stats( group_stats, qs );
    queue = queue->next;
    group_stats = ( struct ofp_group_stats * ) ( ( char * ) group_stats + qs->length );
    n_data++;
  }

  *offset += n_queues;
  if ( q != NULL ) {
    xfree( q );
  }

  return buffer;
}


buffer *
create_group_desc_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                                   const list_element *group_desc_multipart_head, int *more, int *offset ) {
  uint16_t length;
  uint16_t msg_flags = flags;
  uint16_t n_queues = 0;
  uint16_t group_descs_len = 0;
  buffer *buffer;
  list_element *q = NULL;
  list_element *queue = NULL;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_group_desc *qs, *group_desc;

  debug( "Creating a group desc multipart reply ( xid = %#x, flags = %#x ).", transaction_id, flags );

  if ( group_desc_multipart_head != NULL ) {
    int cur = 0;
    while ( offset != NULL && cur < *offset ) {
      group_desc_multipart_head = group_desc_multipart_head->next;
      cur++;
    }
    q = ( list_element * ) xmalloc( sizeof( list_element ) );
    memcpy( q, group_desc_multipart_head, sizeof( list_element ) );
  }

  queue = q;
  *more = 0;
  while ( queue != NULL ) {
    group_desc = ( struct ofp_group_desc * ) queue->data;
    if ( offsetof( struct ofp_multipart_reply, body )
         + group_descs_len + group_desc->length > UINT16_MAX ) {
      *more = 1;
      msg_flags |= OFPMPF_REPLY_MORE;
      break;
    }
    group_descs_len = ( uint16_t ) ( group_descs_len + group_desc->length );
    queue = queue->next;
    n_queues++;
  }

  debug( "# of group_descs = %u.", n_queues );

  length = ( uint16_t ) ( offsetof( struct ofp_multipart_reply, body )
                          + group_descs_len );
  buffer = create_multipart_reply( transaction_id, OFPMP_GROUP_DESC, length, msg_flags );
  assert( buffer != NULL );

  stats_reply = ( struct ofp_multipart_reply * ) buffer->data;
  group_desc = ( struct ofp_group_desc * ) stats_reply->body;

  queue = q;
  int n_data = 0;
  while ( queue != NULL && n_data < n_queues ) {
    qs = ( struct ofp_group_desc * ) queue->data;
    hton_group_desc( group_desc, qs );
    queue = queue->next;
    group_desc = ( struct ofp_group_desc * ) ( ( char * ) group_desc + qs->length );
    n_data++;
  }

  *offset += n_queues;
  if ( q != NULL ) {
    xfree( q );
  }

  return buffer;
}


buffer *
create_group_features_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                                       const uint32_t types, const uint32_t capabilities,
                                       const uint32_t max_groups[ 4 ], const uint32_t actions[ 4 ] ) {
  uint16_t length;
  buffer *buffer;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_group_features *group_features_stats;

  debug( "Creating a group features multipart reply ( xid = %#x, flags = %#x, types = %#x,"
         " capabilities = %#x, max_groups[0] = %#x, max_groups[1] = %#x, max_groups[2] = %#x, max_groups[3] = %#x,"
         " actions[0] = %#x, actions[1] = %#x, actions[2] = %#x, actions[3] = %#x ).", transaction_id, flags,
         types, capabilities, max_groups[ 0 ], max_groups[ 1 ], max_groups[ 2 ], max_groups[ 3 ],
         actions[ 0 ], actions[ 1 ], actions[ 2 ], actions[ 3 ] );

  length = ( uint16_t ) ( offsetof( struct ofp_multipart_reply, body )
                          + sizeof( struct ofp_group_features ) );
  buffer = create_multipart_reply( transaction_id, OFPMP_GROUP_FEATURES, length, flags );
  assert( buffer != NULL );

  stats_reply = ( struct ofp_multipart_reply * ) buffer->data;
  group_features_stats = ( struct ofp_group_features * ) stats_reply->body;
  group_features_stats->types = htonl( types );
  group_features_stats->capabilities = htonl( capabilities );
  for ( int i = 0; i < 4; i++ ) {
    group_features_stats->max_groups[ i ] = htonl( max_groups[ i ] );
    group_features_stats->actions[ i ] = htonl( actions[ i ] );
  }

  return buffer;
}


buffer *
create_meter_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                              const list_element *meter_multipart_head, int *more, int *offset ) {
  uint16_t length;
  uint16_t msg_flags = flags;
  uint16_t n_queues = 0;
  uint16_t meter_len = 0;
  buffer *buffer;
  list_element *q = NULL;
  list_element *queue = NULL;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_meter_stats *qs, *meter_stats;

  debug( "Creating a meter multipart reply ( xid = %#x, flags = %#x ).", transaction_id, flags );

  if ( meter_multipart_head != NULL ) {
    int cur = 0;
    while ( offset != NULL && cur < *offset ) {
      meter_multipart_head = meter_multipart_head->next;
      cur++;
    }
    q = ( list_element * ) xmalloc( sizeof( list_element ) );
    memcpy( q, meter_multipart_head, sizeof( list_element ) );
  }

  queue = q;
  *more = 0;
  while ( queue != NULL ) {
    meter_stats = ( struct ofp_meter_stats * ) queue->data;
    if ( offsetof( struct ofp_multipart_reply, body )
         + meter_len + meter_stats->len > UINT16_MAX ) {
      *more = 1;
      msg_flags |= OFPMPF_REPLY_MORE;
      break;
    }
    meter_len = ( uint16_t ) ( meter_len + meter_stats->len );
    queue = queue->next;
    n_queues++;
  }

  debug( "# of meters = %u.", n_queues );

  length = ( uint16_t ) ( offsetof( struct ofp_multipart_reply, body )
                          + meter_len );
  buffer = create_multipart_reply( transaction_id, OFPMP_METER, length, msg_flags );
  assert( buffer != NULL );

  stats_reply = ( struct ofp_multipart_reply * ) buffer->data;
  meter_stats = ( struct ofp_meter_stats * ) stats_reply->body;

  queue = q;
  int n_data = 0;
  while ( queue != NULL && n_data < n_queues ) {
    qs = ( struct ofp_meter_stats * ) queue->data;
    hton_meter_stats( meter_stats, qs );
    queue = queue->next;
    meter_stats = ( struct ofp_meter_stats * ) ( ( char * ) meter_stats + qs->len );
    n_data++;
  }

  *offset += n_queues;
  if ( q != NULL ) {
    xfree( q );
  }

  return buffer;
}


buffer *
create_meter_config_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                                     const list_element *meter_config_multipart_head, int *more, int *offset ) {
  uint16_t length;
  uint16_t msg_flags = flags;
  uint16_t n_queues = 0;
  uint16_t meter_len = 0;
  buffer *buffer;
  list_element *q = NULL;
  list_element *queue = NULL;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_meter_config *qs, *meter_config;

  debug( "Creating a meter config multipart reply ( xid = %#x, flags = %#x ).", transaction_id, flags );

  if ( meter_config_multipart_head != NULL ) {
    int cur = 0;
    while ( offset != NULL && cur < *offset ) {
      meter_config_multipart_head = meter_config_multipart_head->next;
      cur++;
    }
    q = ( list_element * ) xmalloc( sizeof( list_element ) );
    memcpy( q, meter_config_multipart_head, sizeof( list_element ) );
  }

  queue = q;
  *more = 0;
  while ( queue != NULL ) {
    meter_config = ( struct ofp_meter_config * ) queue->data;
    if ( offsetof( struct ofp_multipart_reply, body )
         + meter_len + meter_config->length > UINT16_MAX ) {
      *more = 1;
      msg_flags |= OFPMPF_REPLY_MORE;
      break;
    }
    meter_len = ( uint16_t ) ( meter_len + meter_config->length );
    queue = queue->next;
    n_queues++;
  }

  debug( "# of meter_configs = %u.", n_queues );

  length = ( uint16_t ) ( offsetof( struct ofp_multipart_reply, body )
                          + meter_len );
  buffer = create_multipart_reply( transaction_id, OFPMP_METER_CONFIG, length, msg_flags );
  assert( buffer != NULL );

  stats_reply = ( struct ofp_multipart_reply * ) buffer->data;
  meter_config = ( struct ofp_meter_config * ) stats_reply->body;

  queue = q;
  int n_data = 0;
  while ( queue != NULL && n_data < n_queues ) {
    qs = ( struct ofp_meter_config * ) queue->data;
    hton_meter_config( meter_config, qs );
    queue = queue->next;
    meter_config = ( struct ofp_meter_config * ) ( ( char * ) meter_config + qs->length );
    n_data++;
  }

  *offset += n_queues;
  if ( q != NULL ) {
    xfree( q );
  }

  return buffer;
}


buffer *
create_meter_features_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                                       const uint32_t max_meter, const uint32_t band_types,
                                       const uint32_t capabilities, const uint8_t max_bands,
                                       const uint8_t max_color ) {
  uint16_t length;
  buffer *buffer;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_meter_features *meter_features;

  debug( "Creating a meter features multipart reply ( xid = %#x, flags = %#x, max_meter = %#x,"
         " band_types = %#x, capabilities = %#x, max_bands = %#x, max_color = %#x ).",
         transaction_id, flags, max_meter, band_types, capabilities, max_bands, max_color );

  length = ( uint16_t ) ( offsetof( struct ofp_multipart_reply, body )
                          + sizeof( struct ofp_meter_features ) );
  buffer = create_multipart_reply( transaction_id, OFPMP_METER_FEATURES, length, flags );
  assert( buffer != NULL );

  stats_reply = ( struct ofp_multipart_reply * ) buffer->data;
  meter_features = ( struct ofp_meter_features * ) stats_reply->body;
  meter_features->max_meter = htonl( max_meter );
  meter_features->band_types = htonl( band_types );
  meter_features->capabilities = htonl( capabilities );
  meter_features->max_bands = max_bands;
  meter_features->max_color = max_color;

  return buffer;
}


buffer *
create_table_features_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                                       const list_element *table_features_multipart_head, int *more, int *offset ) {
  uint16_t length;
  uint16_t msg_flags = flags;
  uint16_t n_tblftrs = 0;
  uint16_t tblftrs_len = 0;
  buffer *buffer;
  list_element *l = NULL, *list = NULL;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_table_features *tblftr, *table_features;

  debug( "Creating a table features multipart reply ( xid = %#x, flags = %#x ).", transaction_id, flags );

  if ( table_features_multipart_head != NULL ) {
    int cur = 0;
    while ( offset != NULL && cur < *offset ) {
      table_features_multipart_head = table_features_multipart_head->next;
      cur++;
    }
    l = ( list_element * ) xmalloc( sizeof( list_element ) );
    memcpy( l, table_features_multipart_head, sizeof( list_element ) );
  }

  list = l;
  *more = 0;
  while ( list != NULL ) {
    table_features = ( struct ofp_table_features * ) list->data;
    if ( offsetof( struct ofp_multipart_reply, body )
         + tblftrs_len + table_features->length > UINT16_MAX ) {
      *more = 1;
      msg_flags |= OFPMPF_REPLY_MORE;
      break;
    }
    tblftrs_len = ( uint16_t ) ( tblftrs_len + table_features->length );
    list = list->next;
    n_tblftrs++;
  }

  debug( "# of table_features = %u.", n_tblftrs );

  length = ( uint16_t ) ( offsetof( struct ofp_multipart_reply, body )
                          + tblftrs_len );
  buffer = create_multipart_reply( transaction_id, OFPMP_TABLE_FEATURES, length, msg_flags );
  assert( buffer != NULL );

  stats_reply = ( struct ofp_multipart_reply * ) buffer->data;
  table_features = ( struct ofp_table_features * ) stats_reply->body;

  list = l;
  int n_data = 0;
  while ( list != NULL && n_data < n_tblftrs ) {
    tblftr = ( struct ofp_table_features * ) list->data;
    hton_table_features( table_features, tblftr );
    list = list->next;
    table_features = ( struct ofp_table_features * ) ( ( char * ) table_features + tblftr->length );
  }

  *offset += n_tblftrs;
  if ( l != NULL ) {
    xfree( l );
  }

  return buffer;
}


buffer *
create_port_desc_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                                  const list_element *port_desc_multipart_head, int *more, int *offset ) {
  uint16_t length;
  uint16_t msg_flags = flags;
  uint16_t n_queues = 0;
  buffer *buffer;
  list_element *q = NULL;
  list_element *queue = NULL;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_port *qs, *port_desc;

  debug( "Creating a port desc multipart reply ( xid = %#x, flags = %#x ).", transaction_id, flags );

  if ( port_desc_multipart_head != NULL ) {
    int cur = 0;
    while ( offset != NULL && cur < *offset ) {
      port_desc_multipart_head = port_desc_multipart_head->next;
      cur++;
    }
    q = ( list_element * ) xmalloc( sizeof( list_element ) );
    memcpy( q, port_desc_multipart_head, sizeof( list_element ) );
  }

  queue = q;
  *more = 0;
  while ( queue != NULL ) {
    if ( offsetof( struct ofp_multipart_reply, body )
         + sizeof( struct ofp_port ) * ( ( size_t ) n_queues + 1 ) > ( size_t ) UINT16_MAX ) {
      *more = 1;
      msg_flags |= OFPMPF_REPLY_MORE;
      break;
    }
    n_queues++;
    queue = queue->next;
  }

  debug( "# of port_descs = %u.", n_queues );

  length = ( uint16_t ) ( offsetof( struct ofp_multipart_reply, body )
                          + sizeof( struct ofp_port ) * n_queues );
  buffer = create_multipart_reply( transaction_id, OFPMP_PORT_DESC, length, msg_flags );
  assert( buffer != NULL );

  stats_reply = ( struct ofp_multipart_reply * ) buffer->data;
  port_desc = ( struct ofp_port * ) stats_reply->body;

  queue = q;
  int n_data = 0;
  while ( queue != NULL && n_data < n_queues ) {
    qs = ( struct ofp_port * ) queue->data;
    hton_port( port_desc, qs );
    queue = queue->next;
    port_desc++;
    n_data++;
  }

  *offset += n_queues;
  if ( q != NULL ) {
    xfree( q );
  }

  return buffer;
}


buffer *
create_experimenter_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                                     const uint32_t experimenter, const uint32_t exp_type, const buffer *body ) {
  void *b;
  uint16_t length;
  uint16_t data_length = 0;
  struct ofp_experimenter_multipart_header *experimenter_multipart_reply;
  buffer *buffer;

  if ( ( body != NULL ) && ( body->length > 0 ) ) {
    data_length = ( uint16_t ) body->length;
  }

  debug( "Creating a experimenter multipart reply ( xid = %#x, flags = %#x, experimenter = %#x, "
         "exp_type = %#x, data length = %u ).",
         transaction_id, flags, experimenter, exp_type, data_length );

  length = ( uint16_t ) ( offsetof( struct ofp_multipart_reply, body )
                        + sizeof( struct ofp_experimenter_multipart_header ) + data_length );
  buffer = create_multipart_reply( transaction_id, OFPMP_EXPERIMENTER, length, flags );
  assert( buffer != NULL );

  experimenter_multipart_reply
   = ( struct ofp_experimenter_multipart_header * ) ( ( char * ) buffer->data
     + offsetof( struct ofp_multipart_reply, body ) );
  experimenter_multipart_reply->experimenter = htonl( experimenter );
  experimenter_multipart_reply->exp_type = htonl( exp_type );

  if ( data_length > 0 ) {
    b = ( void * ) ( ( char * ) buffer->data
                   + offsetof( struct ofp_multipart_reply, body )
                   + sizeof( struct ofp_experimenter_multipart_header ) );

    memcpy( b, body->data, data_length );
  }

  return buffer;
}


buffer *
create_barrier_request( const uint32_t transaction_id ) {
  debug( "Creating a barrier request ( xid = %#x ).", transaction_id );

  return create_header( transaction_id, OFPT_BARRIER_REQUEST, sizeof( struct ofp_header ) );
}


buffer *
create_barrier_reply( const uint32_t transaction_id ) {
  debug( "Creating a barrier reply ( xid = %#x ).", transaction_id );

  return create_header( transaction_id, OFPT_BARRIER_REPLY, sizeof( struct ofp_header ) );
}


buffer *
create_queue_get_config_request( const uint32_t transaction_id, const uint32_t port ) {
  buffer *buffer;
  struct ofp_queue_get_config_request *queue_get_config_request;

  debug( "Creating a queue get config request ( xid = %#x, port = %#x ).", transaction_id, port );

  buffer = create_header( transaction_id, OFPT_QUEUE_GET_CONFIG_REQUEST,
                          sizeof( struct ofp_queue_get_config_request ) );
  assert( buffer != NULL );

  queue_get_config_request = ( struct ofp_queue_get_config_request * ) buffer->data;
  queue_get_config_request->port = htonl( port );
  memset( queue_get_config_request->pad, 0, sizeof( queue_get_config_request->pad ) );

  return buffer;
}


buffer *
create_queue_get_config_reply( const uint32_t transaction_id, const uint32_t port,
                               const list_element *queues ) {
  uint16_t length;
  uint16_t n_queues = 0;
  uint16_t queues_length = 0;
  buffer *buffer;
  list_element *q, *queue;
  struct ofp_queue_get_config_reply *queue_get_config_reply;
  struct ofp_packet_queue *pq, *packet_queue;

  debug( "Creating a queue get config reply ( xid = %#x, port = %#x ).", transaction_id, port );

#ifndef UNIT_TESTING
  assert( queues != NULL );
#endif

  if ( queues != NULL ) {
    q = ( list_element * ) xmalloc( sizeof( list_element ) );
    memcpy( q, queues, sizeof( list_element ) );

    queue = q;
    while ( queue != NULL ) {
      packet_queue = ( struct ofp_packet_queue * ) queue->data;
      queues_length = ( uint16_t ) ( queues_length + packet_queue->len );
      n_queues++;
      queue = queue->next;
    }
  }

  debug( "# of queues = %u.", n_queues );

  length = ( uint16_t ) ( offsetof( struct ofp_queue_get_config_reply, queues ) + queues_length );
  buffer = create_header( transaction_id, OFPT_QUEUE_GET_CONFIG_REPLY, length );
  assert( buffer != NULL );

  queue_get_config_reply = ( struct ofp_queue_get_config_reply * ) buffer->data;
  queue_get_config_reply->port = htonl( port );
  memset( &queue_get_config_reply->pad, 0, sizeof( queue_get_config_reply->pad ) );
  packet_queue = ( struct ofp_packet_queue * ) queue_get_config_reply->queues;

  if ( n_queues ) {
    queue = q;
    while ( queue != NULL ) {
      pq = ( struct ofp_packet_queue * ) queue->data;

      hton_packet_queue( packet_queue, pq );

      packet_queue = ( struct ofp_packet_queue * ) ( ( char * ) packet_queue + pq->len );
      queue = queue->next;
    }

    xfree( q );
  }

  return buffer;
}


buffer *
create_role_request( const uint32_t transaction_id, const uint32_t role,
                     const uint64_t generation_id ) {
  buffer *buffer;
  struct ofp_role_request *role_request;

  debug( "Creating a role request ( xid = %#x, role = %#x, generation_id = %#" PRIx64 " ).", transaction_id, role, generation_id );

  buffer = create_header( transaction_id, OFPT_ROLE_REQUEST,
                          sizeof( struct ofp_role_request ) );
  assert( buffer != NULL );

  role_request = ( struct ofp_role_request * ) buffer->data;
  role_request->role = htonl( role );
  memset( role_request->pad, 0, sizeof( role_request->pad ) );
  role_request->generation_id = htonll( generation_id );

  return buffer;
}


buffer *
create_role_reply( const uint32_t transaction_id, const uint32_t role,
                   const uint64_t generation_id ) {
  buffer *buffer;
  struct ofp_role_request *role_reply;

  debug( "Creating a role reply ( xid = %#x, role = %#x, generation_id = %#" PRIx64 " ).", transaction_id, role, generation_id );

  buffer = create_header( transaction_id, OFPT_ROLE_REPLY, sizeof( struct ofp_role_request ) );
  assert( buffer != NULL );

  role_reply = ( struct ofp_role_request * ) buffer->data;
  role_reply->role = htonl( role );
  memset( role_reply->pad, 0, sizeof( role_reply->pad ) );
  role_reply->generation_id = htonll( generation_id );

  return buffer;
}


buffer *
create_get_async_request( const uint32_t transaction_id ) {
  debug( "Creating a get async request ( xid = %#x ).", transaction_id );

  return create_header( transaction_id, OFPT_GET_ASYNC_REQUEST, sizeof( struct ofp_header ) );
}


buffer *
create_get_async_reply( const uint32_t transaction_id, const uint32_t packet_in_mask[ 2 ],
                        const uint32_t port_status_mask[ 2 ], const uint32_t flow_removed_mask[ 2 ] ) {
  buffer *buffer;
  struct ofp_async_config *get_async;

  debug( "Creating a get async reply ( xid = %#x,"
         " packet_in_mask[0] = %#x, packet_in_mask[1] = %#x,"
         " port_status_mask[0] = %#x, port_status_mask[1] = %#x,"
         " flow_removed_mask[0] = %#x, flow_removed_mask[1] = %#x ).",
         transaction_id, packet_in_mask[ 0 ],  packet_in_mask[ 1 ],
         port_status_mask[ 0 ],  port_status_mask[ 1 ],
         flow_removed_mask[ 0 ],  flow_removed_mask[ 1 ] );

  buffer = create_header( transaction_id, OFPT_GET_ASYNC_REPLY, sizeof( struct ofp_async_config ) );
  assert( buffer != NULL );

  get_async = ( struct ofp_async_config * ) buffer->data;
  get_async->packet_in_mask[ 0 ] = htonl( packet_in_mask[ 0 ] );
  get_async->packet_in_mask[ 1 ] = htonl( packet_in_mask[ 1 ] );
  get_async->port_status_mask[ 0 ] = htonl( port_status_mask[ 0 ] );
  get_async->port_status_mask[ 1 ] = htonl( port_status_mask[ 1 ] );
  get_async->flow_removed_mask[ 0 ] = htonl( flow_removed_mask[ 0 ] );
  get_async->flow_removed_mask[ 1 ] = htonl( flow_removed_mask[ 1 ] );

  return buffer;
}


buffer *
create_set_async( const uint32_t transaction_id, const uint32_t packet_in_mask[ 2 ],
                  const uint32_t port_status_mask[ 2 ], const uint32_t flow_removed_mask[ 2 ] ) {
  buffer *buffer;
  struct ofp_async_config *set_async;

  debug( "Creating a set async ( xid = %#x,"
         " packet_in_mask[0] = %#x, packet_in_mask[1] = %#x,"
         " port_status_mask[0] = %#x, port_status_mask[1] = %#x,"
         " flow_removed_mask[0] = %#x, flow_removed_mask[1] = %#x ).",
         transaction_id, packet_in_mask[ 0 ],  packet_in_mask[ 1 ],
         port_status_mask[ 0 ],  port_status_mask[ 1 ],
         flow_removed_mask[ 0 ],  flow_removed_mask[ 1 ] );

  buffer = create_header( transaction_id, OFPT_SET_ASYNC, sizeof( struct ofp_async_config ) );
  assert( buffer != NULL );

  set_async = ( struct ofp_async_config * ) buffer->data;
  set_async->packet_in_mask[ 0 ] = htonl( packet_in_mask[ 0 ] );
  set_async->packet_in_mask[ 1 ] = htonl( packet_in_mask[ 1 ] );
  set_async->port_status_mask[ 0 ] = htonl( port_status_mask[ 0 ] );
  set_async->port_status_mask[ 1 ] = htonl( port_status_mask[ 1 ] );
  set_async->flow_removed_mask[ 0 ] = htonl( flow_removed_mask[ 0 ] );
  set_async->flow_removed_mask[ 1 ] = htonl( flow_removed_mask[ 1 ] );

  return buffer;
}


buffer *
create_meter_mod( const uint32_t transaction_id, const uint16_t command,
                  const uint16_t flags, const uint32_t meter_id, const list_element *bands ) {
  uint16_t length;
  uint16_t n_bands = 0;
  uint16_t bands_length = 0;
  buffer *buffer;
  list_element *q = NULL, *queue;
  struct ofp_meter_mod *meter_mod;
  struct ofp_meter_band_header *pq, *packet_queue;

  debug( "Creating a meter modification ( xid = %#x, command = %#x, flags = %#x, meter_id = %#x ).",
         transaction_id, command, flags, meter_id );

  if ( bands != NULL ) {
    q = ( list_element * ) xmalloc( sizeof( list_element ) );
    memcpy( q, bands, sizeof( list_element ) );

    queue = q;
    while ( queue != NULL ) {
      packet_queue = ( struct ofp_meter_band_header * ) queue->data;
      bands_length = ( uint16_t ) ( bands_length + packet_queue->len );
      n_bands++;
      queue = queue->next;
    }
  }

  debug( "# of bands = %u.", n_bands );

  length = ( uint16_t ) ( offsetof( struct ofp_meter_mod, bands ) + bands_length );
  buffer = create_header( transaction_id, OFPT_METER_MOD, length );
  assert( buffer != NULL );

  meter_mod = ( struct ofp_meter_mod * ) buffer->data;
  meter_mod->command = htons( command );
  meter_mod->flags = htons( flags );
  meter_mod->meter_id = htonl( meter_id );
  packet_queue = ( struct ofp_meter_band_header * ) meter_mod->bands;

  if ( n_bands ) {
    queue = q;
    while ( queue != NULL ) {
      pq = ( struct ofp_meter_band_header * ) queue->data;

      hton_meter_band_header( packet_queue, pq );

      packet_queue = ( struct ofp_meter_band_header * ) ( ( char * ) packet_queue + pq->len );
      queue = queue->next;
    }

    xfree( q );
  }

  return buffer;
}


uint32_t
get_transaction_id( void ) {
  debug( "Generating a transaction id." );

  pthread_mutex_lock( &transaction_id_mutex );

  if ( ( transaction_id & 0xffff ) == 0xffff ) {
    transaction_id = transaction_id & 0xffff0000;
  }
  else {
    transaction_id++;
  }

  pthread_mutex_unlock( &transaction_id_mutex );

  debug( "Transaction id = %#x.", transaction_id );

  return transaction_id;
}


uint64_t
get_cookie( void ) {
  debug( "Generating a cookie." );

  pthread_mutex_lock( &cookie_mutex );

  if ( ( cookie & 0x0000ffffffffffffULL ) == 0x0000ffffffffffffULL ) {
    cookie = cookie & 0xffff000000000000ULL;
  }
  else {
    cookie++;
  }

  pthread_mutex_unlock( &cookie_mutex );

  debug( "Cookie = %#" PRIx64 ".", cookie );

  return cookie;
}


openflow_actions *
create_actions() {
  openflow_actions *actions;

  debug( "Creating an empty actions list." );

  actions = ( openflow_actions * ) xmalloc( sizeof( openflow_actions ) );

  if ( create_list( &actions->list ) == false ) {
    assert( 0 );
  }

  actions->n_actions = 0;

  return actions;
}


bool
delete_actions( openflow_actions *actions ) {
  list_element *element;

  debug( "Deleting an actions list." );

  assert( actions != NULL );

  debug( "# of actions = %d.", actions->n_actions );

  element = actions->list;
  while ( element != NULL ) {
    xfree( element->data );
    element = element->next;
  }

  delete_list( actions->list );
  xfree( actions );

  return true;
}


bool
append_action_output( openflow_actions *actions, const uint32_t port, uint16_t max_len ) {
  bool ret;
  struct ofp_action_output *action_output;

  debug( "Appending an output action ( port = %#x, max_len = %#x ).", port, max_len );

  assert( actions != NULL );

  if ( ( max_len > OFPCML_MAX ) && ( max_len != OFPCML_NO_BUFFER ) ) {
    warn( "Invalid max_len ( change %#x to %#x )", max_len, OFPCML_MAX );
    max_len = OFPCML_MAX;
  }

  action_output = ( struct ofp_action_output * ) xcalloc( 1, sizeof( struct ofp_action_output ) );
  action_output->type = OFPAT_OUTPUT;
  action_output->len = sizeof( struct ofp_action_output );
  action_output->port = port;
  action_output->max_len = max_len;

  ret = append_to_tail( &actions->list, ( void * ) action_output );
  if ( ret ) {
    actions->n_actions++;
  }

  return ret;
}


bool
append_action_copy_ttl_out( openflow_actions *actions ) {
  bool ret;
  struct ofp_action_header *action_copy_ttl_out;

  debug( "Appending a copy ttl out action." );

  assert( actions != NULL );

  action_copy_ttl_out = ( struct ofp_action_header * ) xcalloc( 1, sizeof( struct ofp_action_header ) );
  action_copy_ttl_out->type = OFPAT_COPY_TTL_OUT;
  action_copy_ttl_out->len = sizeof( struct ofp_action_header );

  ret = append_to_tail( &actions->list, ( void * ) action_copy_ttl_out );
  if ( ret ) {
    actions->n_actions++;
  }

  return ret;
}


bool
append_action_copy_ttl_in( openflow_actions *actions ) {
  bool ret;
  struct ofp_action_header *action_copy_ttl_in;

  debug( "Appending a copy ttl in action." );

  assert( actions != NULL );

  action_copy_ttl_in = ( struct ofp_action_header * ) xcalloc( 1, sizeof( struct ofp_action_header ) );
  action_copy_ttl_in->type = OFPAT_COPY_TTL_IN;
  action_copy_ttl_in->len = sizeof( struct ofp_action_header );

  ret = append_to_tail( &actions->list, ( void * ) action_copy_ttl_in );
  if ( ret ) {
    actions->n_actions++;
  }

  return ret;
}


bool
append_action_set_mpls_ttl( openflow_actions *actions, const uint8_t mpls_ttl ) {
  bool ret;
  struct ofp_action_mpls_ttl *action_mpls_ttl;

  debug( "Appending a set mpls ttl action ( mpls_ttl = %#x ).", mpls_ttl );

  assert( actions != NULL );

  action_mpls_ttl = ( struct ofp_action_mpls_ttl * ) xcalloc( 1, sizeof( struct ofp_action_mpls_ttl ) );
  action_mpls_ttl->type = OFPAT_SET_MPLS_TTL;
  action_mpls_ttl->len = sizeof( struct ofp_action_mpls_ttl );
  action_mpls_ttl->mpls_ttl = mpls_ttl;

  ret = append_to_tail( &actions->list, ( void * ) action_mpls_ttl );
  if ( ret ) {
    actions->n_actions++;
  }

  return ret;
}


bool
append_action_dec_mpls_ttl( openflow_actions *actions ) {
  bool ret;
  struct ofp_action_header *action_dec_mpls_ttl;

  debug( "Appending a dec mpls ttl in action." );

  assert( actions != NULL );

  action_dec_mpls_ttl = ( struct ofp_action_header * ) xcalloc( 1, sizeof( struct ofp_action_header ) );
  action_dec_mpls_ttl->type = OFPAT_DEC_MPLS_TTL;
  action_dec_mpls_ttl->len = sizeof( struct ofp_action_header );

  ret = append_to_tail( &actions->list, ( void * ) action_dec_mpls_ttl );
  if ( ret ) {
    actions->n_actions++;
  }

  return ret;
}


bool
append_action_push_vlan( openflow_actions *actions, const uint16_t ethertype ) {
  bool ret;
  struct ofp_action_push *action_push_vlan;

  debug( "Appending a push vlan action ( ethertype = %#x ).", ethertype );

  assert( actions != NULL );

  action_push_vlan = ( struct ofp_action_push * ) xcalloc( 1, sizeof( struct ofp_action_push ) );
  action_push_vlan->type = OFPAT_PUSH_VLAN;
  action_push_vlan->len = sizeof( struct ofp_action_push );
  action_push_vlan->ethertype = ethertype;

  ret = append_to_tail( &actions->list, ( void * ) action_push_vlan );
  if ( ret ) {
    actions->n_actions++;
  }

  return ret;
}


bool
append_action_pop_vlan( openflow_actions *actions ) {
  bool ret;
  struct ofp_action_header *action_pop_vlan;

  debug( "Appending a pop vlan action." );

  assert( actions != NULL );

  action_pop_vlan = ( struct ofp_action_header * ) xcalloc( 1, sizeof( struct ofp_action_header ) );
  action_pop_vlan->type = OFPAT_POP_VLAN;
  action_pop_vlan->len = sizeof( struct ofp_action_header );

  ret = append_to_tail( &actions->list, ( void * ) action_pop_vlan );
  if ( ret ) {
    actions->n_actions++;
  }

  return ret;
}


bool
append_action_push_mpls( openflow_actions *actions, const uint16_t ethertype ) {
  bool ret;
  struct ofp_action_push *action_push_mpls;

  debug( "Appending a push mpls action ( ethertype = %#x ).", ethertype );

  assert( actions != NULL );

  action_push_mpls = ( struct ofp_action_push * ) xcalloc( 1, sizeof( struct ofp_action_push ) );
  action_push_mpls->type = OFPAT_PUSH_MPLS;
  action_push_mpls->len = sizeof( struct ofp_action_push );
  action_push_mpls->ethertype = ethertype;

  ret = append_to_tail( &actions->list, ( void * ) action_push_mpls );
  if ( ret ) {
    actions->n_actions++;
  }

  return ret;
}


bool
append_action_pop_mpls( openflow_actions *actions, const uint16_t ethertype ) {
  bool ret;
  struct ofp_action_push *action_pop_mpls;

  debug( "Appending a pop mpls action ( ethertype = %#x ).", ethertype );

  assert( actions != NULL );

  action_pop_mpls = ( struct ofp_action_push * ) xcalloc( 1, sizeof( struct ofp_action_push ) );
  action_pop_mpls->type = OFPAT_POP_MPLS;
  action_pop_mpls->len = sizeof( struct ofp_action_push );
  action_pop_mpls->ethertype = ethertype;

  ret = append_to_tail( &actions->list, ( void * ) action_pop_mpls );
  if ( ret ) {
    actions->n_actions++;
  }

  return ret;
}


bool
append_action_set_queue( openflow_actions *actions, const uint32_t queue_id ) {
  bool ret;
  struct ofp_action_set_queue *action_set_queue;

  debug( "Appending a set queue action ( queue_id = %#x ).", queue_id );

  assert( actions != NULL );

  action_set_queue = ( struct ofp_action_set_queue * ) xcalloc( 1, sizeof( struct ofp_action_set_queue ) );
  action_set_queue->type = OFPAT_SET_QUEUE;
  action_set_queue->len = sizeof( struct ofp_action_set_queue );
  action_set_queue->queue_id = queue_id;

  ret = append_to_tail( &actions->list, ( void * ) action_set_queue );
  if ( ret ) {
    actions->n_actions++;
  }

  return ret;
}


bool
append_action_group( openflow_actions *actions, const uint32_t group_id ) {
  bool ret;
  struct ofp_action_group *action_set_queue;

  debug( "Appending a group action ( group_id = %#x ).", group_id );

  assert( actions != NULL );

  action_set_queue = ( struct ofp_action_group * ) xcalloc( 1, sizeof( struct ofp_action_group ) );
  action_set_queue->type = OFPAT_GROUP;
  action_set_queue->len = sizeof( struct ofp_action_group );
  action_set_queue->group_id = group_id;

  ret = append_to_tail( &actions->list, ( void * ) action_set_queue );
  if ( ret ) {
    actions->n_actions++;
  }

  return ret;
}


bool
append_action_set_nw_ttl( openflow_actions *actions, const uint8_t nw_ttl ) {
  bool ret;
  struct ofp_action_nw_ttl *action_set_nw_ttl;

  debug( "Appending a nw ttl action ( nw_ttl = %#x ).", nw_ttl );

  assert( actions != NULL );

  action_set_nw_ttl = ( struct ofp_action_nw_ttl * ) xcalloc( 1, sizeof( struct ofp_action_nw_ttl ) );
  action_set_nw_ttl->type = OFPAT_SET_NW_TTL;
  action_set_nw_ttl->len = sizeof( struct ofp_action_nw_ttl );
  action_set_nw_ttl->nw_ttl = nw_ttl;

  ret = append_to_tail( &actions->list, ( void * ) action_set_nw_ttl );
  if ( ret ) {
    actions->n_actions++;
  }

  return ret;
}


bool
append_action_dec_nw_ttl( openflow_actions *actions ) {
  bool ret;
  struct ofp_action_header *action_dec_nw_ttl;

  debug( "Appending a dec nw ttl in action." );

  assert( actions != NULL );

  action_dec_nw_ttl = ( struct ofp_action_header * ) xcalloc( 1, sizeof( struct ofp_action_header ) );
  action_dec_nw_ttl->type = OFPAT_DEC_NW_TTL;
  action_dec_nw_ttl->len = sizeof( struct ofp_action_header );

  ret = append_to_tail( &actions->list, ( void * ) action_dec_nw_ttl );
  if ( ret ) {
    actions->n_actions++;
  }

  return ret;
}


bool
append_action_push_pbb( openflow_actions *actions, const uint16_t ethertype ) {
  bool ret;
  struct ofp_action_push *action_push_pbb;

  debug( "Appending a push pbb action ( ethertype = %#x ).", ethertype );

  assert( actions != NULL );

  action_push_pbb = ( struct ofp_action_push * ) xcalloc( 1, sizeof( struct ofp_action_push ) );
  action_push_pbb->type = OFPAT_PUSH_PBB;
  action_push_pbb->len = sizeof( struct ofp_action_push );
  action_push_pbb->ethertype = ethertype;

  ret = append_to_tail( &actions->list, ( void * ) action_push_pbb );
  if ( ret ) {
    actions->n_actions++;
  }

  return ret;
}


bool
append_action_pop_pbb( openflow_actions *actions ) {
  bool ret;
  struct ofp_action_header *action_pop_pbb;

  debug( "Appending a pop pbb in action." );

  assert( actions != NULL );

  action_pop_pbb = ( struct ofp_action_header * ) xcalloc( 1, sizeof( struct ofp_action_header ) );
  action_pop_pbb->type = OFPAT_POP_PBB;
  action_pop_pbb->len = sizeof( struct ofp_action_header );

  ret = append_to_tail( &actions->list, ( void * ) action_pop_pbb );
  if ( ret ) {
    actions->n_actions++;
  }

  return ret;
}


bool
append_action_experimenter( openflow_actions *actions, uint32_t experimenter, const buffer *data ) {
  bool ret;
  uint16_t data_length = 0;
  uint16_t offset;
  void *d;
  struct ofp_action_experimenter_header *action_experimenter;

  if ( ( data != NULL ) && ( data->length > 0 ) ) {
    data_length = ( uint16_t ) data->length;
  }

  debug( "Appending a experimenter action ( experimenter = %#x, data length = %u ).",
          experimenter, data_length );

  assert( actions != NULL );

  offset = sizeof( struct ofp_action_experimenter_header );
  action_experimenter = ( struct ofp_action_experimenter_header * ) xcalloc( 1, ( uint16_t ) ( offset + data_length ) );
  action_experimenter->type = OFPAT_EXPERIMENTER;
  action_experimenter->len = ( uint16_t ) ( offset + data_length );
  action_experimenter->experimenter = experimenter;

  if ( data_length > 0 ) {
    d = ( void * ) ( ( char * ) action_experimenter + offset );
    memcpy( d, data->data, data_length );
  }

  ret = append_to_tail( &actions->list, ( void * ) action_experimenter );
  if ( ret ) {
    actions->n_actions++;
  }

  return ret;
}


static bool
_append_action_set_field( openflow_actions *actions, oxm_match_header *oxm_tlv, size_t oxm_len ) {
  bool ret;
  uint16_t sf_total_len;
  struct ofp_action_set_field *new_sf;

  uint16_t offset = ( uint16_t ) offsetof( struct ofp_action_set_field, field );
  sf_total_len = ( uint16_t ) ( offset + oxm_len + PADLEN_TO_64( offset + oxm_len ) );

  new_sf = ( struct ofp_action_set_field * ) xcalloc( 1, sf_total_len );
  new_sf->type = OFPAT_SET_FIELD;
  new_sf->len = sf_total_len; // include padding length
  memcpy( new_sf->field, oxm_tlv, oxm_len );

  ret = append_to_tail( &actions->list, ( void * ) new_sf );
  if ( ret ) {
    actions->n_actions++;
  }

  return ret;
}


static bool
append_action_set_field( openflow_actions *actions, oxm_match_header oxm_hdr, const void *value ) {
  bool ret;

  size_t oxm_len = ( uint16_t ) ( sizeof( oxm_match_header ) + OXM_LENGTH( oxm_hdr ) );
  oxm_match_header *oxm_tlv = ( oxm_match_header * ) xcalloc( 1, oxm_len );
  *oxm_tlv = oxm_hdr;
  void *v = ( char * ) oxm_tlv + sizeof( oxm_match_header );
  memcpy( v, value, OXM_LENGTH( oxm_hdr ) );

  ret = _append_action_set_field( actions, oxm_tlv, oxm_len );

  xfree( oxm_tlv );

  return ret;
}


bool
append_action_set_field_in_port( openflow_actions *actions, const uint32_t in_port ) {
  bool ret;

  debug( "Appending a set field in port action ( in_port = %#x ).", in_port );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_IN_PORT, &in_port );

  return ret;
}


bool
append_action_set_field_in_phy_port( openflow_actions *actions, const uint32_t in_phy_port ) {
  bool ret;

  debug( "Appending a set field in phy port action ( in_phy_port = %#x ).", in_phy_port );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_IN_PHY_PORT, &in_phy_port );

  return ret;
}


bool
append_action_set_field_metadata( openflow_actions *actions, const uint64_t metadata ) {
  bool ret;

  debug( "Appending a set field metadata action ( metadata = %" PRIu64 " ).", metadata );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_METADATA, &metadata );

  return ret;
}


bool
append_action_set_field_eth_dst( openflow_actions *actions, const uint8_t eth_dst[ OFP_ETH_ALEN ] ) {
  bool ret;

  debug( "Appending a set field eth dst action ( eth_dst = %02x:%02x:%02x:%02x:%02x:%02x ).",
          eth_dst[ 0 ], eth_dst[ 1 ], eth_dst[ 2 ], eth_dst[ 3 ], eth_dst[ 4 ], eth_dst[ 5 ] );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_ETH_DST, eth_dst );

  return ret;
}


bool
append_action_set_field_eth_src( openflow_actions *actions, const uint8_t eth_src[ OFP_ETH_ALEN ] ) {
  bool ret;

  debug( "Appending a set field eth src action ( eth_src = %02x:%02x:%02x:%02x:%02x:%02x ).",
          eth_src[ 0 ], eth_src[ 1 ], eth_src[ 2 ], eth_src[ 3 ], eth_src[ 4 ], eth_src[ 5 ] );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_ETH_SRC, eth_src );

  return ret;
}


bool
append_action_set_field_eth_type( openflow_actions *actions, const uint16_t eth_type ) {
  bool ret;

  debug( "Appending a set field eth type action ( eth_type = %#x ).", eth_type );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_ETH_TYPE, &eth_type );

  return ret;
}


bool
append_action_set_field_vlan_vid( openflow_actions *actions, const uint16_t vlan_vid ) {
  bool ret;

  debug( "Appending a set field vlan vid action ( vlan_vid = %#x ).", vlan_vid );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_VLAN_VID, &vlan_vid );

  return ret;
}


bool
append_action_set_field_vlan_pcp( openflow_actions *actions, const uint8_t vlan_pcp ) {
  bool ret;

  debug( "Appending a set field vlan pcap action ( vlan_pcp = %#x ).", vlan_pcp );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_VLAN_PCP, &vlan_pcp );

  return ret;
}


bool
append_action_set_field_ip_dscp( openflow_actions *actions, const uint8_t ip_dscp ) {
  bool ret;

  debug( "Appending a set field ip dscp action ( ip_dscp = %#x ).", ip_dscp );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_IP_DSCP, &ip_dscp );

  return ret;
}


bool
append_action_set_field_ip_ecn( openflow_actions *actions, const uint8_t ip_ecn ) {
  bool ret;

  debug( "Appending a set field ip ecn action ( ip_ecn = %#x ).", ip_ecn );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_IP_ECN, &ip_ecn );

  return ret;
}


bool
append_action_set_field_ip_proto( openflow_actions *actions, const uint8_t ip_proto ) {
  bool ret;

  debug( "Appending a set field ip proto action ( ip_proto = %#x ).", ip_proto );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_IP_PROTO, &ip_proto );

  return ret;
}


bool
append_action_set_field_ipv4_src( openflow_actions *actions, const uint32_t ipv4_src ) {
  bool ret;

  debug( "Appending a set field ipv4 src action ( ipv4_src = %#x ).", ipv4_src );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_IPV4_SRC, &ipv4_src );

  return ret;
}


bool
append_action_set_field_ipv4_dst( openflow_actions *actions, const uint32_t ipv4_dst ) {
  bool ret;

  debug( "Appending a set field ipv4 dst action ( ipv4_dst = %#x ).", ipv4_dst );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_IPV4_DST, &ipv4_dst );

  return ret;
}


bool
append_action_set_field_tcp_src( openflow_actions *actions, const uint16_t tcp_src ) {
  bool ret;

  debug( "Appending a set field tcp src action ( tcp_src = %#x ).", tcp_src );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_TCP_SRC, &tcp_src );

  return ret;
}


bool
append_action_set_field_tcp_dst( openflow_actions *actions, const uint16_t tcp_dst ) {
  bool ret;

  debug( "Appending a set field tcp dst action ( tcp_dst = %#x ).", tcp_dst );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_TCP_DST, &tcp_dst );

  return ret;
}


bool
append_action_set_field_udp_src( openflow_actions *actions, const uint16_t udp_src ) {
  bool ret;

  debug( "Appending a set field udp src action ( udp_src = %#x ).", udp_src );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_UDP_SRC, &udp_src );

  return ret;
}


bool
append_action_set_field_udp_dst( openflow_actions *actions, const uint16_t udp_dst ) {
  bool ret;

  debug( "Appending a set field udp dst action ( udp_dst = %#x ).", udp_dst );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_UDP_DST, &udp_dst );

  return ret;
}


bool
append_action_set_field_sctp_src( openflow_actions *actions, const uint16_t sctp_src ) {
  bool ret;

  debug( "Appending a set field sctp src action ( sctp_src = %#x ).", sctp_src );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_SCTP_SRC, &sctp_src );

  return ret;
}


bool
append_action_set_field_sctp_dst( openflow_actions *actions, const uint16_t sctp_dst ) {
  bool ret;

  debug( "Appending a set field sctp dst action ( sctp_dst = %#x ).", sctp_dst );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_SCTP_DST, &sctp_dst );

  return ret;
}


bool
append_action_set_field_icmpv4_type( openflow_actions *actions, const uint8_t icmpv4_type ) {
  bool ret;

  debug( "Appending a set field icmpv4 type action ( icmpv4_type = %#x ).", icmpv4_type );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_ICMPV4_TYPE, &icmpv4_type );

  return ret;
}


bool
append_action_set_field_icmpv4_code( openflow_actions *actions, const uint8_t icmpv4_code ) {
  bool ret;

  debug( "Appending a set field icmpv4 code action ( icmpv4_code = %#x ).", icmpv4_code );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_ICMPV4_CODE, &icmpv4_code );

  return ret;
}


bool
append_action_set_field_arp_op( openflow_actions *actions, const uint16_t arp_opcode ) {
  bool ret;

  debug( "Appending a set field arp op action ( arp_op = %#x ).", arp_opcode );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_ARP_OP, &arp_opcode );

  return ret;
}


bool
append_action_set_field_arp_spa( openflow_actions *actions, const uint32_t arp_spa ) {
  bool ret;

  debug( "Appending a set field arp spa action ( arp_spa = %#x ).", arp_spa );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_ARP_SPA, &arp_spa );

  return ret;
}


bool
append_action_set_field_arp_tpa( openflow_actions *actions, const uint32_t arp_tpa ) {
  bool ret;

  debug( "Appending a set field arp tpa action ( arp_tpa = %#x ).", arp_tpa );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_ARP_TPA, &arp_tpa );

  return ret;
}


bool
append_action_set_field_arp_sha( openflow_actions *actions, const uint8_t arp_sha[ OFP_ETH_ALEN ] ) {
  bool ret;

  debug( "Appending a set field arp sha action ( arp_sha = %02x:%02x:%02x:%02x:%02x:%02x ).",
          arp_sha[ 0 ], arp_sha[ 1 ], arp_sha[ 2 ], arp_sha[ 3 ], arp_sha[ 4 ], arp_sha[ 5 ] );
  
  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_ARP_SHA, arp_sha );

  return ret;
}


bool
append_action_set_field_arp_tha( openflow_actions *actions, const uint8_t arp_tha[ OFP_ETH_ALEN ] ) {
  bool ret;

  debug( "Appending a set field arp tha action ( arp_tha = %02x:%02x:%02x:%02x:%02x:%02x ).",
          arp_tha[ 0 ], arp_tha[ 1 ], arp_tha[ 2 ], arp_tha[ 3 ], arp_tha[ 4 ], arp_tha[ 5 ] );
  
  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_ARP_THA, arp_tha );

  return ret;
}


bool
append_action_set_field_ipv6_src( openflow_actions *actions, const struct in6_addr ipv6_src ) {
  bool ret;
  char ipv6_src_str[ INET6_ADDRSTRLEN ];
  memset( ipv6_src_str, '\0', sizeof( ipv6_src_str ) );

  if ( NULL != inet_ntop( AF_INET6, &ipv6_src, ipv6_src_str, sizeof( ipv6_src_str ) ) ) {
    debug( "Appending a set field ipv6 src action ( ipv6_src = %s ).", ipv6_src_str );
  }
  else {
    debug( "Appending a set field ipv6 src action ( inet_ntop error. )." );
  }
  
  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_IPV6_SRC, &ipv6_src );

  return ret;
}


bool
append_action_set_field_ipv6_dst( openflow_actions *actions, const struct in6_addr ipv6_dst ) {
  bool ret;
  char ipv6_dst_str[ INET6_ADDRSTRLEN ];
  memset( ipv6_dst_str, '\0', sizeof( ipv6_dst_str ) );

  if ( NULL != inet_ntop( AF_INET6, &ipv6_dst, ipv6_dst_str, sizeof( ipv6_dst_str ) ) ) {
    debug( "Appending a set field ipv6 dst action ( ipv6_dst = %s ).", ipv6_dst_str );
  }
  else {
    debug( "Appending a set field ipv6 dst action ( inet_ntop error. )." );
  }
  
  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_IPV6_DST, &ipv6_dst );

  return ret;
}


bool
append_action_set_field_ipv6_flabel( openflow_actions *actions, const uint32_t ipv6_flabel ) {
  bool ret;

  debug( "Appending a set field ipv6 flabel action ( ipv6_flabel = %#x ).", ipv6_flabel );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_IPV6_FLABEL, &ipv6_flabel );

  return ret;
}


bool
append_action_set_field_icmpv6_type( openflow_actions *actions, const uint8_t icmpv6_type ) {
  bool ret;

  debug( "Appending a set field ipv6 type action ( icmpv6_type = %#x ).", icmpv6_type );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_ICMPV6_TYPE, &icmpv6_type );

  return ret;
}


bool
append_action_set_field_icmpv6_code( openflow_actions *actions, const uint8_t icmpv6_code ) {
  bool ret;

  debug( "Appending a set field icmpv6 code action ( icmpv6_code = %#x ).", icmpv6_code );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_ICMPV6_CODE, &icmpv6_code );

  return ret;
}


bool
append_action_set_field_ipv6_nd_target( openflow_actions *actions, const struct in6_addr ipv6_nd_target ) {
  bool ret;
  char ipv6_nd_target_str[ INET6_ADDRSTRLEN ];
  memset( ipv6_nd_target_str, '\0', sizeof( ipv6_nd_target_str ) );

  if (NULL != inet_ntop( AF_INET6, &ipv6_nd_target, ipv6_nd_target_str, sizeof( ipv6_nd_target_str ) ) ) {
    debug( "Appending a set field ipv6 nd target action ( ipv6_nd_target = %s ).", ipv6_nd_target_str );
  }
  else {
    debug( "Appending a set field ipv6 nd target action ( inet_ntop error. )." );
  }
  
  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_IPV6_ND_TARGET, &ipv6_nd_target );

  return ret;
}


bool
append_action_set_field_ipv6_nd_sll( openflow_actions *actions, const uint8_t ipv6_nd_sll[ OFP_ETH_ALEN ] ) {
  bool ret;

  debug( "Appending a set field ipv6 nd sll action ( ipv6_nd_sll = %02x:%02x:%02x:%02x:%02x:%02x ).",
          ipv6_nd_sll[ 0 ], ipv6_nd_sll[ 1 ], ipv6_nd_sll[ 2 ], ipv6_nd_sll[ 3 ], ipv6_nd_sll[ 4 ], ipv6_nd_sll[ 5 ] );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_IPV6_ND_SLL, ipv6_nd_sll );

  return ret;
}


bool
append_action_set_field_ipv6_nd_tll( openflow_actions *actions, const uint8_t ipv6_nd_tll[ OFP_ETH_ALEN ] ) {
  bool ret;

  debug( "Appending a set field ipv6 nd tll action ( ipv6_nd_tll = %02x:%02x:%02x:%02x:%02x:%02x ).",
          ipv6_nd_tll[ 0 ], ipv6_nd_tll[ 1 ], ipv6_nd_tll[ 2 ], ipv6_nd_tll[ 3 ], ipv6_nd_tll[ 4 ], ipv6_nd_tll[ 5 ] );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_IPV6_ND_TLL, ipv6_nd_tll );

  return ret;
}


bool
append_action_set_field_mpls_label( openflow_actions *actions, const uint32_t mpls_label ) {
  bool ret;

  debug( "Appending a set field mpls label action ( mpls_label = %#x ).", mpls_label );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_MPLS_LABEL, &mpls_label );

  return ret;
}


bool
append_action_set_field_mpls_tc( openflow_actions *actions, const uint8_t mpls_tc ) {
  bool ret;

  debug( "Appending a set field mpls tc action ( mpls_tc = %#x ).", mpls_tc );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_MPLS_TC, &mpls_tc );

  return ret;
}


bool
append_action_set_field_mpls_bos( openflow_actions *actions, const uint8_t mpls_bos ) {
  bool ret;

  debug( "Appending a set field mpls bos action ( mpls_bos = %#x ).", mpls_bos );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_MPLS_BOS, &mpls_bos );

  return ret;
}


bool
append_action_set_field_pbb_isid( openflow_actions *actions, const uint32_t pbb_isid ) {
  bool ret;

  debug( "Appending a set field pbb isid action ( pbb_isid = %#x ).", pbb_isid );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_PBB_ISID, &pbb_isid );

  return ret;
}


bool
append_action_set_field_tunnel_id( openflow_actions *actions, const uint64_t tunnel_id ) {
  bool ret;

  debug( "Appending a set field tunnel id action ( tunnel_id = %" PRIu64 " ).", tunnel_id );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_TUNNEL_ID, &tunnel_id );

  return ret;
}


bool
append_action_set_field_ipv6_exthdr( openflow_actions *actions, const uint16_t ipv6_exthdr ) {
  bool ret;

  debug( "Appending a set field ipv6_exthdr action ( ipv6_exthdr = %#x ).", ipv6_exthdr );

  assert( actions != NULL );

  ret = append_action_set_field( actions, OXM_OF_IPV6_EXTHDR, &ipv6_exthdr );

  return ret;
}


openflow_instructions *
create_instructions( void ) {
  openflow_instructions *instructions;

  debug( "Creating an empty instructions list." );

  instructions = ( openflow_instructions * ) xmalloc( sizeof( openflow_instructions ) );

  if ( create_list( &instructions->list ) == false ) {
    assert( 0 );
  }

  instructions->n_instructions = 0;

  return instructions;
}


bool
delete_instructions( openflow_instructions *instructions ) {
  list_element *element;

  debug( "Deleting an instructions list." );

  assert( instructions != NULL );

  debug( "# of instructions = %d.", instructions->n_instructions );

  element = instructions->list;
  while ( element != NULL ) {
    xfree( element->data );
    element = element->next;
  }

  delete_list( instructions->list );
  xfree( instructions );

  return true;
}


bool
append_instructions_goto_table( openflow_instructions *instructions, uint8_t table_id ) {
  bool ret;
  struct ofp_instruction_goto_table *instruction_goto_table;

  debug( "Appending a goto table instruction ( table_id = %#x ).", table_id );

  assert( instructions != NULL );

  instruction_goto_table = ( struct ofp_instruction_goto_table * ) xcalloc( 1, sizeof( struct ofp_instruction_goto_table ) );
  instruction_goto_table->type = OFPIT_GOTO_TABLE;
  instruction_goto_table->len = sizeof( struct ofp_instruction_goto_table );
  instruction_goto_table->table_id = table_id;
  memset( instruction_goto_table->pad, 0, sizeof( instruction_goto_table->pad ) );

  ret = append_to_tail( &instructions->list, ( void * ) instruction_goto_table );
  if ( ret ) {
    instructions->n_instructions++;
  }

  return ret;
}


bool
append_instructions_write_metadata( openflow_instructions *instructions, uint64_t metadata, uint64_t metadata_mask ) {
  bool ret;
  struct ofp_instruction_write_metadata *instruction_write_metadata;

  debug( "Appending a write metadata instruction ( metadata = %" PRIu64 " , metadata_mask = %" PRIu64 " ).",
          metadata, metadata_mask );

  assert( instructions != NULL );

  instruction_write_metadata = ( struct ofp_instruction_write_metadata * ) xcalloc( 1, sizeof( struct ofp_instruction_write_metadata ) );
  instruction_write_metadata->type = OFPIT_WRITE_METADATA;
  instruction_write_metadata->len = sizeof( struct ofp_instruction_write_metadata );
  memset( instruction_write_metadata->pad, 0, sizeof( instruction_write_metadata->pad ) );
  instruction_write_metadata->metadata = metadata;
  instruction_write_metadata->metadata_mask = metadata_mask;

  ret = append_to_tail( &instructions->list, ( void * ) instruction_write_metadata );
  if ( ret ) {
    instructions->n_instructions++;
  }

  return ret;
}


bool
append_instructions_write_actions( openflow_instructions *instructions, openflow_actions *actions ) {
  bool ret;
  void *a;
  uint16_t action_length = 0;
  uint16_t actions_length = 0;
  struct ofp_instruction_actions *instruction_actions;
  struct ofp_action_header *action_header;
  list_element *action;

  debug( "Appending a write action instruction." );
  if ( actions != NULL ) {
    debug( "# of actions = %d.", actions->n_actions );
    actions_length = get_actions_length( actions );
  }

  assert( instructions != NULL );

  instruction_actions = ( struct ofp_instruction_actions * ) xcalloc( 1, sizeof( struct ofp_instruction_actions ) + actions_length );
  instruction_actions->type = OFPIT_WRITE_ACTIONS;
  instruction_actions->len = ( uint16_t ) ( sizeof( struct ofp_instruction_actions ) + actions_length );
  memset( instruction_actions->pad, 0, sizeof( instruction_actions->pad ) );
  if ( actions_length > 0 ) {
    a = ( void * ) ( ( char * ) instruction_actions + offsetof( struct ofp_instruction_actions, actions ) );

    action = actions->list;
    while ( action != NULL ) {
      action_header = ( struct ofp_action_header * ) action->data;
      action_length = action_header->len;
      memcpy( a, action_header, action_length );
      a = ( void * ) ( ( char * ) a + action_length );
      action = action->next;
    }
  }

  ret = append_to_tail( &instructions->list, ( void * ) instruction_actions );
  if ( ret ) {
    instructions->n_instructions++;
  }

  return ret;
}


bool
append_instructions_apply_actions( openflow_instructions *instructions, openflow_actions *actions ) {
  bool ret;
  void *a;
  uint16_t action_length = 0;
  uint16_t actions_length = 0;
  struct ofp_instruction_actions *instruction_actions;
  struct ofp_action_header *action_header;
  list_element *action;

  debug( "Appending a apply action instruction." );
  if ( actions != NULL ) {
    debug( "# of actions = %d.", actions->n_actions );
    actions_length = get_actions_length( actions );
  }

  assert( instructions != NULL );

  instruction_actions = ( struct ofp_instruction_actions * ) xcalloc( 1, sizeof( struct ofp_instruction_actions ) + actions_length );
  instruction_actions->type = OFPIT_APPLY_ACTIONS;
  instruction_actions->len = ( uint16_t ) ( sizeof( struct ofp_instruction_actions ) + actions_length );
  memset( instruction_actions->pad, 0, sizeof( instruction_actions->pad ) );
  if ( actions_length > 0 ) {
    a = ( void * ) ( ( char * ) instruction_actions + offsetof( struct ofp_instruction_actions, actions ) );

    action = actions->list;
    while ( action != NULL ) {
      action_header = ( struct ofp_action_header * ) action->data;
      action_length = action_header->len;
      memcpy( a, action_header, action_length );
      a = ( void * ) ( ( char * ) a + action_length );
      action = action->next;
    }
  }

  ret = append_to_tail( &instructions->list, ( void * ) instruction_actions );
  if ( ret ) {
    instructions->n_instructions++;
  }

  return ret;
}


bool
append_instructions_clear_actions( openflow_instructions *instructions ) {
  bool ret;
  struct ofp_instruction_actions *instruction_actions;

  debug( "Appending a clear action instruction." );

  assert( instructions != NULL );

  instruction_actions = ( struct ofp_instruction_actions * ) xcalloc( 1, sizeof( struct ofp_instruction_actions ) );
  instruction_actions->type = OFPIT_CLEAR_ACTIONS;
  instruction_actions->len = sizeof( struct ofp_instruction_actions );
  memset( instruction_actions->pad, 0, sizeof( instruction_actions->pad ) );

  ret = append_to_tail( &instructions->list, ( void * ) instruction_actions );
  if ( ret ) {
    instructions->n_instructions++;
  }

  return ret;
}


bool
append_instructions_meter( openflow_instructions *instructions, uint32_t meter_id ) {
  bool ret;
  struct ofp_instruction_meter *instruction_meter;

  debug( "Appending a meta instruction ( meter_id = %#x ).", meter_id );

  assert( instructions != NULL );

  instruction_meter = ( struct ofp_instruction_meter * ) xcalloc( 1, sizeof( struct ofp_instruction_meter ) );
  instruction_meter->type = OFPIT_METER;
  instruction_meter->len = sizeof( struct ofp_instruction_meter );
  instruction_meter->meter_id = meter_id;

  ret = append_to_tail( &instructions->list, ( void * ) instruction_meter );
  if ( ret ) {
    instructions->n_instructions++;
  }

  return ret;
}


bool
append_instructions_experimenter( openflow_instructions *instructions, uint32_t experimenter, const buffer *data  ) {
  bool ret;
  uint16_t data_length = 0;
  uint16_t offset;
  void *d;
  struct ofp_instruction_experimenter *instruction_experimenter;

  if ( ( data != NULL ) && ( data->length > 0 ) ) {
    data_length = ( uint16_t ) data->length;
  }

  debug( "Appending a experimenter instruction( experimenter = %#x, data length = %u ).",
          experimenter, data_length );

  assert( instructions != NULL );

  offset = sizeof( struct ofp_instruction_experimenter );
  instruction_experimenter = ( struct ofp_instruction_experimenter * ) xcalloc( 1, ( uint16_t ) ( offset + data_length ) );
  instruction_experimenter->type = OFPIT_EXPERIMENTER;
  instruction_experimenter->len = ( uint16_t ) ( offset + data_length );
  instruction_experimenter->experimenter = experimenter;

  if ( data_length > 0 ) {
    d = ( void * ) ( ( char * ) instruction_experimenter + offset );
    memcpy( d, data->data, data_length );
  }

  ret = append_to_tail( &instructions->list, ( void * ) instruction_experimenter );
  if ( ret ) {
    instructions->n_instructions++;
  }

  return ret;
}


openflow_buckets *
create_buckets( void ) {
  openflow_buckets *buckets;

  debug( "Creating an empty buckets list." );

  buckets = ( openflow_buckets * ) xmalloc( sizeof( openflow_buckets ) );

  if ( create_list( &buckets->list ) == false ) {
    assert( 0 );
  }

  buckets->n_buckets = 0;

  return buckets;
}


bool
delete_buckets( openflow_buckets *buckets ) {
  list_element *element;

  debug( "Deleting an buckets list." );

  assert( buckets != NULL );

  debug( "# of buckets = %d.", buckets->n_buckets );

  element = buckets->list;
  while ( element != NULL ) {
    xfree( element->data );
    element = element->next;
  }

  delete_list( buckets->list );
  xfree( buckets );

  return true;
}


uint16_t
get_buckets_length( const openflow_buckets *buckets ) {
  int buckets_length = 0;
  struct ofp_bucket *bucket;

  debug( "Calculating the total length of buckets." );

  assert( buckets != NULL );

  list_element *e = buckets->list;
  while ( e != NULL ) {
    bucket = ( struct ofp_bucket * ) e->data;
    buckets_length += bucket->len;
    e = e->next;
  }

  debug( "Total length of buckets = %u.", buckets_length );

  if ( buckets_length > UINT16_MAX ) {
    critical( "Too many buckets ( # of buckets = %d, buckets length = %u ).",
              buckets->n_buckets, buckets_length );
    assert( 0 );
  }

  return ( uint16_t ) buckets_length;
}


bool
append_bucket( openflow_buckets *buckets, uint16_t weight, uint32_t watch_port, uint32_t watch_group, openflow_actions *actions ) {
  bool ret;
  void *a;
  uint16_t action_length = 0;
  uint16_t actions_length = 0;
  struct ofp_bucket *bucket;
  struct ofp_action_header *action_header;
  list_element *action;

  debug( "Appending an bucket ( weight = %#x, watch_port = %#x, watch_group = %#x ).", weight, watch_port, watch_group );
  if ( actions != NULL ) {
    debug( "# of actions = %d.", actions->n_actions );
    actions_length = get_actions_length( actions );
  }

  assert( buckets != NULL );

  bucket = ( struct ofp_bucket * ) xcalloc( 1, sizeof( struct ofp_bucket ) + actions_length );
  bucket->len = ( uint16_t ) ( sizeof( struct ofp_bucket ) + actions_length );
  bucket->weight = weight;
  bucket->watch_port = watch_port;
  bucket->watch_group = watch_group;
  memset( bucket->pad, 0, sizeof( bucket->pad ) );
  if ( actions_length > 0 ) {
    a = ( void * ) ( ( char * ) bucket + offsetof( struct ofp_bucket, actions ) );

    action = actions->list;
    while ( action != NULL ) {
      action_header = ( struct ofp_action_header * ) action->data;
      action_length = action_header->len;
      memcpy( a, action_header, action_length );
      a = ( void * ) ( ( char * ) a + action_length );
      action = action->next;
    }
  }

  ret = append_to_tail( &buckets->list, ( void * ) bucket );
  if ( ret ) {
    buckets->n_buckets++;
  }

  return ret;
}


static int
validate_header( const buffer *message, const uint8_t type,
                 const uint16_t min_length, const uint16_t max_length ) {
  struct ofp_header *header;

  assert( message != NULL );
  if ( message->length < sizeof( struct ofp_header ) ) {
    return ERROR_TOO_SHORT_MESSAGE;
  }

  header = ( struct ofp_header * ) message->data;
  if ( header->version != OFP_VERSION ) {
    return ERROR_UNSUPPORTED_VERSION;
  }
  if ( header->type > OFPT_METER_MOD ) {
    return ERROR_UNDEFINED_TYPE;
  }
  if ( header->type != type ) {
    return ERROR_INVALID_TYPE;
  }
  if ( ntohs( header->length ) > max_length ) {
    return ERROR_TOO_LONG_MESSAGE;
  }
  else if ( ntohs( header->length ) < min_length ) {
    return ERROR_TOO_SHORT_MESSAGE;
  }
  if ( ntohs( header->length ) < message->length ) {
    return ERROR_TOO_LONG_MESSAGE;
  }
  else if ( ntohs( header->length ) > message->length ) {
    return ERROR_TOO_SHORT_MESSAGE;
  }

  if ( message->length > max_length ) {
    return ERROR_TOO_LONG_MESSAGE;
  }

  return 0;
}


static int
validate_hello_elem_versionbitmap( struct ofp_hello_elem_versionbitmap *element ) {
  size_t bitmaps_length;

  assert( element != NULL );
  assert( ntohs( element->type ) == OFPHET_VERSIONBITMAP );

  if ( ntohs( element->length ) < offsetof( struct ofp_hello_elem_versionbitmap, bitmaps ) ) {
    return ERROR_TOO_SHORT_HELLO_ELEMENT;
  }

  bitmaps_length = ntohs( element->length ) - offsetof( struct ofp_hello_elem_versionbitmap, bitmaps );
  if ( bitmaps_length % sizeof( uint32_t ) != 0 ) {
    return ERROR_INVALID_HELLO_ELEMENT_LENGTH;
  }

  if ( bitmaps_length > 0 ) {
    // FIXME: Since version negotiation is not implemented yet, we check OFP_VERSION here.
    if ( ( ntohl( element->bitmaps[ 0 ] ) & ( ( uint32_t ) 1 << OFP_VERSION ) ) == 0 ) {
      return ERROR_UNSUPPORTED_VERSION;
    }
  }

  return 0;
}


static int
validate_hello_elements( struct ofp_hello_elem_header *elements_head, const uint16_t length, bool *version_bitmap_found ) {
  int ret;
  size_t offset;
  struct ofp_hello_elem_header *element;

  assert( elements_head != NULL );

  *version_bitmap_found = false;
  ret = 0;
  offset = 0;
  while ( offset < length ) {
    element = ( struct ofp_hello_elem_header * ) ( ( char * ) elements_head + offset );
    switch ( ntohs( element->type ) ) {
    case OFPHET_VERSIONBITMAP:
      ret = validate_hello_elem_versionbitmap( ( struct ofp_hello_elem_versionbitmap * ) element );
      *version_bitmap_found = true;
      break;
    default:
      ret = ERROR_UNDEFINED_HELLO_ELEMENT_TYPE;
      break;
    }

    if ( ret < 0 ) {
      break;
    }

    offset += ( size_t ) ( ntohs( element->length ) + PADLEN_TO_64( ntohs( element->length ) ) );
  }

  return ret;
}


int
validate_hello( const buffer *message ) {
  bool version_bitmap_found;
  int ret;
  size_t elements_length;
  struct ofp_hello *hello;

  assert( message != NULL );

  ret = validate_header( message, OFPT_HELLO, sizeof( struct ofp_header ), UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  hello = ( struct ofp_hello * ) message->data;
  if ( message->length != ntohs( hello->header.length ) ) {
    return ERROR_INVALID_LENGTH;
  }

  elements_length = ntohs( hello->header.length ) - offsetof( struct ofp_hello, elements );

  if ( elements_length > 0 && elements_length < sizeof( struct ofp_hello_elem_header ) ) {
    return ERROR_INVALID_LENGTH;
  }

  version_bitmap_found = false;
  if ( elements_length > 0 ) {
    ret = validate_hello_elements( hello->elements, ( uint16_t ) elements_length, &version_bitmap_found );
  }

  if ( !version_bitmap_found && hello->header.version != OFP_VERSION ) {
    ret = ERROR_UNSUPPORTED_VERSION;
  }

  return ret;
}


int
validate_error( const buffer *message ) {
  int ret;

  assert( message != NULL );

  ret = validate_header( message, OFPT_ERROR, sizeof( struct ofp_error_msg ), UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  return 0;
}


int
validate_echo_request( const buffer *message ) {
  int ret;
  struct ofp_header *header;

  assert( message != NULL );

  ret = validate_header( message, OFPT_ECHO_REQUEST, sizeof( struct ofp_header ), UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  header = ( struct ofp_header * ) message->data;
  if ( message->length != ntohs( header->length ) ) {
    return ERROR_INVALID_LENGTH;
  }

  return 0;
}


int
validate_echo_reply( const buffer *message ) {
  int ret;
  struct ofp_header *header;

  assert( message != NULL );

  ret = validate_header( message, OFPT_ECHO_REPLY, sizeof( struct ofp_header ), UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  header = ( struct ofp_header * ) message->data;
  if ( message->length != ntohs( header->length ) ) {
    return ERROR_INVALID_LENGTH;
  }

  return 0;
}


int
validate_experimenter( const buffer *message ) {
  int ret;
  struct ofp_experimenter_header *experimenter_header;

  assert( message != NULL );

  ret = validate_header( message, OFPT_EXPERIMENTER, sizeof( struct ofp_experimenter_header ), UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  experimenter_header = ( struct ofp_experimenter_header * ) message->data;
  if ( message->length != ntohs( experimenter_header->header.length ) ) {
    return ERROR_INVALID_LENGTH;
  }

  return 0;
}


int
validate_features_request( const buffer *message ) {
  assert( message != NULL );
  return validate_header( message, OFPT_FEATURES_REQUEST, sizeof( struct ofp_header ),
                          sizeof( struct ofp_header ) );
}


static int
validate_port_no( const uint32_t port_no ) {
  if ( ( port_no == 0 ) || ( ( port_no > OFPP_MAX ) && ( port_no < OFPP_IN_PORT ) ) ) {
    return ERROR_INVALID_PORT_NO;
  }

  return 0;
}


static int
validate_port( struct ofp_port *port ) {
  int ret;
  struct ofp_port port_h;

  assert( port != NULL );

  ntoh_port( &port_h, port );

  ret = validate_port_no( port_h.port_no );
  if ( ret < 0 ) {
    return ret;
  }

  if ( ( port_h.config & ( uint32_t ) ~PORT_CONFIG ) != 0 ) {
    return ERROR_INVALID_PORT_CONFIG;
  }
  if ( ( port_h.state & ( uint32_t ) ~PORT_STATE ) != 0 ) {
    return ERROR_INVALID_PORT_STATE;
  }
  if ( ( port_h.curr & ( uint32_t ) ~PORT_FEATURES ) != 0
       || ( port_h.advertised & ( uint32_t ) ~PORT_FEATURES ) != 0
       || ( port_h.supported & ( uint32_t ) ~PORT_FEATURES ) != 0
       || ( port_h.peer & ( uint32_t ) ~PORT_FEATURES ) != 0 ) {
    return ERROR_INVALID_PORT_FEATURES;
  }

  // port_h.curr_speed
  // port_h.max_speed

  return 0;
}


static int
validate_ports( struct ofp_port *ports, const int n_ports ) {
  int i;
  int ret;
  struct ofp_port *port;

  assert( ports != NULL );
  assert( n_ports );

  port = ports;
  for ( i = 0; i < n_ports; i++ ) {
    ret = validate_port( port );
    if ( ret < 0 ) {
      return ret;
    }
    port++;
  }

  return 0;
}


int
validate_features_reply( const buffer *message ) {
  int ret;
  struct ofp_switch_features *switch_features;

  assert( message != NULL );

  ret = validate_header( message, OFPT_FEATURES_REPLY, sizeof( struct ofp_switch_features ), UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  switch_features = ( struct ofp_switch_features * ) message->data;

  // switch_features->datapath_id
  // switch_features->n_buffers

  if ( switch_features->n_tables == 0 ) {
    return ERROR_NO_TABLE_AVAILABLE;
  }

  // switch_features->auxiliary_id
  // switch_features->capabilities
  // switch_features->reserved

  return 0;
}


int
validate_get_config_request( const buffer *message ) {
  assert( message != NULL );
  return validate_header( message, OFPT_GET_CONFIG_REQUEST, sizeof( struct ofp_header ),
                          sizeof( struct ofp_header ) );
}


static int
validate_switch_config( const buffer *message, const uint8_t type ) {
  int ret;
  struct ofp_switch_config *switch_config;

  assert( message != NULL );
  assert( ( type == OFPT_GET_CONFIG_REPLY ) || ( type == OFPT_SET_CONFIG ) );

  ret = validate_header( message, type, sizeof( struct ofp_switch_config ),
                         sizeof( struct ofp_switch_config ) );
  if ( ret < 0 ) {
    return ret;
  }

  switch_config = ( struct ofp_switch_config * ) message->data;
  if ( ntohs( switch_config->flags ) > OFPC_FRAG_MASK ) {
    return ERROR_INVALID_SWITCH_CONFIG;
  }

  // switch_config->miss_send_len

  return 0;
}


int
validate_get_config_reply( const buffer *message ) {
  assert( message != NULL );
  return validate_switch_config( message, OFPT_GET_CONFIG_REPLY );
}


int
validate_set_config( const buffer *message ) {
  assert( message != NULL );
  return validate_switch_config( message, OFPT_SET_CONFIG );
}


static int
validate_vlan_vid( const uint16_t vid ) {
  if ( ( vid & ~VLAN_VID_MASK ) != 0 ) {
    return ERROR_INVALID_VLAN_VID;
  }

  return 0;
}


static int
validate_vlan_pcp( const uint8_t pcp ) {
  if ( ( pcp & ~VLAN_PCP_MASK ) != 0 ) {
    return ERROR_INVALID_VLAN_PCP;
  }

  return 0;
}


static int
validate_ip_dscp( const uint8_t ip_dscp ) {
  if ( ( ip_dscp & ~IP_DSCP_MASK ) != 0 ) {
    return ERROR_INVALID_IP_DSCP;
  }

  return 0;
}


static int
validate_ip_ecn( const uint8_t ip_ecn ) {
  if ( ( ip_ecn & ~IP_ECN_MASK ) != 0 ) {
    return ERROR_INVALID_IP_ECN;
  }

  return 0;
}


static int
validate_ipv6_flabel( const uint32_t ipv6_flabel ) {
  if ( ( ipv6_flabel & ( ( uint32_t ) ~IPV6_FLABEL_MASK ) ) != 0 ) {
    return ERROR_INVALID_IPV6_FLABEL;
  }

  return 0;
}


static int
validate_mpls_label( const uint32_t mpls_label ) {
  if ( ( mpls_label & ( ( uint32_t ) ~MPLS_LABEL_MASK ) ) != 0 ) {
    return ERROR_INVALID_MPLS_LABEL;
  }

  return 0;
}


static int
validate_mpls_tc( const uint8_t mpls_tc ) {
  if ( ( mpls_tc & ~MPLS_TC_MASK ) != 0 ) {
    return ERROR_INVALID_MPLS_TC;
  }

  return 0;
}


static int
validate_mpls_bos( const uint8_t mpls_bos ) {
  if ( ( mpls_bos & ~MPLS_BOS_MASK ) != 0 ) {
    return ERROR_INVALID_MPLS_BOS;
  }

  return 0;
}


static int
validate_pbb_isid( const uint32_t pbb_isid ) {
  if ( ( pbb_isid & ( ( uint32_t ) ~PBB_ISID_MASK ) ) != 0 ) {
    return ERROR_INVALID_PBB_ISID;
  }

  return 0;
}


static int
validate_ipv6_exthdr( const uint16_t ipv6_exthdr ) {
  if ( ( ipv6_exthdr & ~IPV6_EXTHDR_MASK ) != 0 ) {
    return ERROR_INVALID_IPV6_EXTHDR;
  }

  return 0;
}


static int
validate_match( struct ofp_match *match ) {
  int ret = 0;
  bool in_port_present = false;
  bool vid_present = false;
  uint16_t eth_type_val = 0;
  uint8_t ip_proto_val = 0;
  uint8_t icmpv6_type_val = 0;

  uint16_t offset = offsetof( struct ofp_match, oxm_fields );
  if ( ntohs( match->length ) < offset ) {
    return ERROR_INVALID_LENGTH;
  }

  uint16_t oxm_len = ( uint16_t ) ( ntohs( match->length ) - offset );
  oxm_match_header *tl_p = ( oxm_match_header * ) ( ( char * ) match + offset );
  oxm_match_header tl_hb;

  while ( oxm_len > sizeof( oxm_match_header ) ) {
    tl_hb = ntohl( *tl_p );
    offset = ( uint16_t ) ( sizeof( oxm_match_header ) + OXM_LENGTH( tl_hb ) );

    if ( oxm_len < offset ) {
      return ERROR_INVALID_LENGTH;
    }

    if ( OXM_CLASS( tl_hb ) != OFPXMC_OPENFLOW_BASIC ) {
      return ERROR_INVALID_MATCH_TYPE;
    }

    switch ( OXM_FIELD( tl_hb ) ) {
    case OFPXMT_OFB_IN_PORT:
      in_port_present = true;
      break;
    case OFPXMT_OFB_IN_PHY_PORT:
      if ( in_port_present != true ) {
        debug( "OFPXMT_OFB_IN_PHY_PORT: in_port_present false" );
        return ERROR_BAD_MATCH_PREREQ;
      }
      break;
    case OFPXMT_OFB_METADATA:
      break;
    case OFPXMT_OFB_ETH_DST:
      break;
    case OFPXMT_OFB_ETH_SRC:
      break;
    case OFPXMT_OFB_ETH_TYPE:
      {
        uint16_t *v = ( uint16_t * ) ( ( char * ) tl_p + sizeof( oxm_match_header ) );
        eth_type_val = ntohs( *v );
       }
      break;
    case OFPXMT_OFB_VLAN_VID:
      {
        uint16_t *v = ( uint16_t * ) ( ( char * ) tl_p + sizeof( oxm_match_header ) );
        uint16_t dl_vlan = ntohs( *v );
        uint16_t mask = 0xffff;
        ret = validate_vlan_vid( dl_vlan );
        if ( ret < 0 ) {
          return ret;
        }
        if ( tl_hb == OXM_OF_VLAN_VID_W ) {
          v = ( uint16_t * ) ( ( char * ) tl_p + sizeof( oxm_match_header ) + sizeof( uint16_t ) );
          mask = *v;
        }
        // VLAN_VID != NONE case
        if ( ( mask & OFPVID_PRESENT ) && ( dl_vlan & OFPVID_PRESENT ) ) {
          vid_present = true;
        }
      }
      break;
    case OFPXMT_OFB_VLAN_PCP:
      {
        if ( vid_present != true ) {
          debug( "OFPXMT_OFB_VLAN_PCP: vid_present false" );
          return ERROR_BAD_MATCH_PREREQ;
        }
        uint8_t *v = ( uint8_t * ) ( ( char * ) tl_p + sizeof( oxm_match_header ) );
        uint8_t dl_vlan_pcp = *v;
        ret = validate_vlan_pcp( dl_vlan_pcp );
        if ( ret < 0 ) {
          return ret;
        }
      break;
      }
    case OFPXMT_OFB_IP_DSCP:
      {
        if ( ( eth_type_val != 0x0800 ) && ( eth_type_val != 0x86dd ) ) {
          debug( "OFPXMT_OFB_IP_DSCP: invalid eth_type_val ( eth_type_val = 0x%x )", eth_type_val );
          return ERROR_BAD_MATCH_PREREQ;
        }
        uint8_t *v = ( uint8_t * ) ( ( char * ) tl_p + sizeof( oxm_match_header ) );
        uint8_t ip_dscp = *v;
        ret = validate_ip_dscp( ip_dscp );
        if ( ret < 0 ) {
          return ret;
        }
      }
      break;
    case OFPXMT_OFB_IP_ECN:
      {
        if ( ( eth_type_val != 0x0800 ) && ( eth_type_val != 0x86dd ) ) {
          debug( "OFPXMT_OFB_IP_ECN: invalid eth_type_val ( eth_type_val = 0x%x )", eth_type_val );
          return ERROR_BAD_MATCH_PREREQ;
        }
        uint8_t *v = ( uint8_t * ) ( ( char * ) tl_p + sizeof( oxm_match_header ) );
        uint8_t ip_ecn = *v;
        ret = validate_ip_ecn( ip_ecn );
        if ( ret < 0 ) {
          return ret;
        }
      }
      break;
    case OFPXMT_OFB_IP_PROTO:
      {
        if ( ( eth_type_val != 0x0800 ) && ( eth_type_val != 0x86dd ) ) {
          debug( "OFPXMT_OFB_IP_PROTO: invalid eth_type_val ( eth_type_val = 0x%x )", eth_type_val );
          return ERROR_BAD_MATCH_PREREQ;
        }
        uint8_t *v = ( uint8_t * ) ( ( char * ) tl_p + sizeof( oxm_match_header ) );
        ip_proto_val = *v;
       }
      break;
    case OFPXMT_OFB_IPV4_SRC:
      if ( eth_type_val != 0x0800 ) {
        debug( "OFPXMT_OFB_IPV4_SRC: invalid eth_type_val ( eth_type_val = 0x%x )", eth_type_val );
        return ERROR_BAD_MATCH_PREREQ;
      }
      break;
    case OFPXMT_OFB_IPV4_DST:
      if ( eth_type_val != 0x0800 ) {
        debug( "OFPXMT_OFB_IPV4_DST: invalid eth_type_val ( eth_type_val = 0x%x )", eth_type_val );
        return ERROR_BAD_MATCH_PREREQ;
      }
      break;
    case OFPXMT_OFB_TCP_SRC:
      if ( ip_proto_val != 6 ) {
        debug( "OFPXMT_OFB_TCP_SRC: invalid ip_proto_val ( ip_proto_val = %d )", ip_proto_val );
        return ERROR_BAD_MATCH_PREREQ;
      }
      break;
    case OFPXMT_OFB_TCP_DST:
      if ( ip_proto_val != 6 ) {
        debug( "OFPXMT_OFB_TCP_DST: invalid ip_proto_val ( ip_proto_val = %d )", ip_proto_val );
        return ERROR_BAD_MATCH_PREREQ;
      }
      break;
    case OFPXMT_OFB_UDP_SRC:
      if ( ip_proto_val != 17 ) {
        debug( "OFPXMT_OFB_UDP_SRC: invalid ip_proto_val ( ip_proto_val = %d )", ip_proto_val );
        return ERROR_BAD_MATCH_PREREQ;
      }
      break;
    case OFPXMT_OFB_UDP_DST:
      if ( ip_proto_val != 17 ) {
        debug( "OFPXMT_OFB_UDP_DST: invalid ip_proto_val ( ip_proto_val = %d )", ip_proto_val );
        return ERROR_BAD_MATCH_PREREQ;
      }
      break;
    case OFPXMT_OFB_SCTP_SRC:
      if ( ip_proto_val != 132 ) {
        debug( "OFPXMT_OFB_SCTP_SRC: invalid ip_proto_val ( ip_proto_val = %d )", ip_proto_val );
        return ERROR_BAD_MATCH_PREREQ;
      }
      break;
    case OFPXMT_OFB_SCTP_DST:
      if ( ip_proto_val != 132 ) {
        debug( "OFPXMT_OFB_SCTP_DST: invalid ip_proto_val ( ip_proto_val = %d )", ip_proto_val );
        return ERROR_BAD_MATCH_PREREQ;
      }
      break;
    case OFPXMT_OFB_ICMPV4_TYPE:
      if ( ip_proto_val != 1 ) {
        debug( "OFPXMT_OFB_ICMPV4_TYPE: invalid ip_proto_val ( ip_proto_val = %d )", ip_proto_val );
        return ERROR_BAD_MATCH_PREREQ;
      }
      break;
    case OFPXMT_OFB_ICMPV4_CODE:
      if ( ip_proto_val != 1 ) {
        debug( "OFPXMT_OFB_ICMPV4_CODE: invalid ip_proto_val ( ip_proto_val = %d )", ip_proto_val );
        return ERROR_BAD_MATCH_PREREQ;
      }
      break;
    case OFPXMT_OFB_ARP_OP:
      if ( eth_type_val != 0x0806 ) {
        debug( "OFPXMT_OFB_ARP_OP: invalid eth_type_val ( eth_type_val = 0x%x )", eth_type_val );
        return ERROR_BAD_MATCH_PREREQ;
      }
      break;
    case OFPXMT_OFB_ARP_SPA:
      if ( eth_type_val != 0x0806 ) {
        debug( "OFPXMT_OFB_ARP_SPA: invalid eth_type_val ( eth_type_val = 0x%x )", eth_type_val );
        return ERROR_BAD_MATCH_PREREQ;
      }
      break;
    case OFPXMT_OFB_ARP_TPA:
      if ( eth_type_val != 0x0806 ) {
        debug( "OFPXMT_OFB_ARP_TPA: invalid eth_type_val ( eth_type_val = 0x%x )", eth_type_val );
        return ERROR_BAD_MATCH_PREREQ;
      }
      break;
    case OFPXMT_OFB_ARP_SHA:
      if ( eth_type_val != 0x0806 ) {
        debug( "OFPXMT_OFB_ARP_SHA: invalid eth_type_val ( eth_type_val = 0x%x )", eth_type_val );
        return ERROR_BAD_MATCH_PREREQ;
      }
      break;
    case OFPXMT_OFB_ARP_THA:
      if ( eth_type_val != 0x0806 ) {
        debug( "OFPXMT_OFB_ARP_THA: invalid eth_type_val ( eth_type_val = 0x%x )", eth_type_val );
        return ERROR_BAD_MATCH_PREREQ;
      }
      break;
    case OFPXMT_OFB_IPV6_SRC:
      if ( eth_type_val != 0x86dd ) {
        debug( "OFPXMT_OFB_IPV6_SRC: invalid eth_type_val ( eth_type_val = 0x%x )", eth_type_val );
        return ERROR_BAD_MATCH_PREREQ;
      }
      break;
    case OFPXMT_OFB_IPV6_DST:
      if ( eth_type_val != 0x86dd ) {
        debug( "OFPXMT_OFB_IPV6_DST: invalid eth_type_val ( eth_type_val = 0x%x )", eth_type_val );
        return ERROR_BAD_MATCH_PREREQ;
      }
      break;
    case OFPXMT_OFB_IPV6_FLABEL:
      {
        if ( eth_type_val != 0x86dd ) {
          debug( "OFPXMT_OFB_IPV6_FLABEL: invalid eth_type_val ( eth_type_val = 0x%x )", eth_type_val );
          return ERROR_BAD_MATCH_PREREQ;
        }
        uint32_t *v = ( uint32_t * ) ( ( char * ) tl_p + sizeof( oxm_match_header ) );
        uint32_t ipv6_flabel = ntohl( *v );
        ret = validate_ipv6_flabel( ipv6_flabel );
        if ( ret < 0 ) {
          return ret;
        }
      }
      break;
    case OFPXMT_OFB_ICMPV6_TYPE:
      {
        if ( ip_proto_val != 58 ) {
          debug( "OFPXMT_OFB_ICMPV6_TYPE: invalid ip_proto_val ( ip_proto_val = %d )", ip_proto_val );
          return ERROR_BAD_MATCH_PREREQ;
        }
        uint8_t *v = ( uint8_t * ) ( ( char * ) tl_p + sizeof( oxm_match_header ) );
        icmpv6_type_val = *v;
       }
      break;
    case OFPXMT_OFB_ICMPV6_CODE:
      if ( ip_proto_val != 58 ) {
        debug( "OFPXMT_OFB_ICMPV6_CODE: invalid ip_proto_val ( ip_proto_val = %d )", ip_proto_val );
        return ERROR_BAD_MATCH_PREREQ;
      }
      break;
    case OFPXMT_OFB_IPV6_ND_TARGET:
      if ( ( icmpv6_type_val != 135 ) && ( icmpv6_type_val != 136 ) ) {
        debug( "OFPXMT_OFB_IPV6_ND_TARGET: invalid icmpv6_type_val ( icmpv6_type_val = %d )", icmpv6_type_val );
        return ERROR_BAD_MATCH_PREREQ;
      }
      break;
    case OFPXMT_OFB_IPV6_ND_SLL:
      if ( icmpv6_type_val != 135 ) {
        debug( "OFPXMT_OFB_IPV6_ND_SLL: invalid icmpv6_type_val ( icmpv6_type_val = %d )", icmpv6_type_val );
        return ERROR_BAD_MATCH_PREREQ;
      }
      break;
    case OFPXMT_OFB_IPV6_ND_TLL:
      if ( icmpv6_type_val != 136 ) {
        debug( "OFPXMT_OFB_IPV6_ND_TLL: invalid icmpv6_type_val ( icmpv6_type_val = %d )", icmpv6_type_val );
        return ERROR_BAD_MATCH_PREREQ;
      }
      break;
    case OFPXMT_OFB_MPLS_LABEL:
      {
        if ( ( eth_type_val != 0x8847 ) && ( eth_type_val != 0x8848 ) ) {
          debug( "OFPXMT_OFB_MPLS_LABEL: invalid eth_type_val ( eth_type_val = 0x%x )", eth_type_val );
          return ERROR_BAD_MATCH_PREREQ;
        }
        uint32_t *v = ( uint32_t * ) ( ( char * ) tl_p + sizeof( oxm_match_header ) );
        uint32_t mpls_label = ntohl( *v );
        ret = validate_mpls_label( mpls_label );
        if ( ret < 0 ) {
          return ret;
        }
      }
      break;
    case OFPXMT_OFB_MPLS_TC:
      {
        if ( ( eth_type_val != 0x8847 ) && ( eth_type_val != 0x8848 ) ) {
          debug( "OFPXMT_OFB_MPLS_TC: invalid eth_type_val ( eth_type_val = 0x%x )", eth_type_val );
          return ERROR_BAD_MATCH_PREREQ;
        }
        uint8_t *v = ( uint8_t * ) ( ( char * ) tl_p + sizeof( oxm_match_header ) );
        uint8_t mpls_tc = *v;
        ret = validate_mpls_tc( mpls_tc );
        if ( ret < 0 ) {
          return ret;
        }
      }
      break;
    case OFPXMT_OFB_MPLS_BOS:
      {
        if ( ( eth_type_val != 0x8847 ) && ( eth_type_val != 0x8848 ) ) {
          debug( "OFPXMT_OFB_MPLS_BOS: invalid eth_type_val ( eth_type_val = 0x%x )", eth_type_val );
          return ERROR_BAD_MATCH_PREREQ;
        }
        uint8_t *v = ( uint8_t * ) ( ( char * ) tl_p + sizeof( oxm_match_header ) );
        uint8_t mpls_bos = *v;
        ret = validate_mpls_bos( mpls_bos );
        if ( ret < 0 ) {
          return ret;
        }
      }
      break;
    case OFPXMT_OFB_PBB_ISID:
      {
        if ( eth_type_val != 0x88e7 ) {
          debug( "OFPXMT_OFB_PBB_ISID: invalid eth_type_val ( eth_type_val = 0x%x )", eth_type_val );
          return ERROR_BAD_MATCH_PREREQ;
        }
        uint32_t *v = ( uint32_t * ) ( ( char * ) tl_p + sizeof( oxm_match_header ) );
        uint32_t pbb_isid = ntohl( *v );
        ret = validate_pbb_isid( pbb_isid );
        if ( ret < 0 ) {
          return ret;
        }
      }
      break;
    case OFPXMT_OFB_TUNNEL_ID:
      break;
    case OFPXMT_OFB_IPV6_EXTHDR:
      {
        if ( eth_type_val != 0x86dd ) {
          debug( "OFPXMT_OFB_IPV6_EXTHDR: invalid eth_type_val ( eth_type_val = 0x%x )", eth_type_val );
          return ERROR_BAD_MATCH_PREREQ;
        }
        uint16_t *v = ( uint16_t * ) ( ( char * ) tl_p + sizeof( oxm_match_header ) );
        uint16_t ipv6_exthdr = ntohs( *v );
        ret = validate_ipv6_exthdr( ipv6_exthdr );
        if ( ret < 0 ) {
          return ret;
        }
      }
      break;
    default:
      debug( "ERROR_INVALID_MATCH_TYPE: invalid oxm field ( oxm field = 0x%x )", OXM_FIELD( tl_hb ) );
      return ERROR_INVALID_MATCH_TYPE;
      break;
    }

    tl_p = ( oxm_match_header * ) ( ( char * ) tl_p + offset );
    oxm_len = ( uint16_t ) ( oxm_len - offset );
  }

  if ( oxm_len != 0 ) {
    return ERROR_INVALID_LENGTH;
  }

  return 0;
}


int
validate_packet_in( const buffer *message ) {
  int ret;
  uint16_t data_length;
  uint16_t match_len;
  struct ofp_packet_in *packet_in;

  assert( message != NULL );

  ret = validate_header( message, OFPT_PACKET_IN, sizeof( struct ofp_packet_in ), UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  packet_in = ( struct ofp_packet_in * ) message->data;

  // packet_in->buffer_id
  // packet_in->total_len

  if ( packet_in->reason > OFPR_INVALID_TTL ) {
    return ERROR_INVALID_PACKET_IN_REASON;
  }

  // packet_in->table_id
  // packet_in->cookie

  match_len = ntohs( packet_in->match.length );
  match_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );

  if ( ntohs( packet_in->header.length ) < ( offsetof( struct ofp_packet_in, match ) + match_len ) ) {
    return ERROR_INVALID_LENGTH;
  }

  ret = validate_match( &packet_in->match );
  if ( ret < 0 ) {
    return ret;
  }

  data_length = ( uint16_t ) ( ntohs( packet_in->header.length ) - offsetof( struct ofp_packet_in, match ) - match_len );
  if ( data_length > 0 ) {
    // FIXME: it may be better to check if this is a valid Ethernet frame or not.
  }

  return 0;
}


int
validate_flow_removed( const buffer *message ) {
  int ret;
  uint16_t match_len;
  struct ofp_flow_removed *flow_removed;

  assert( message != NULL );

  ret = validate_header( message, OFPT_FLOW_REMOVED, sizeof( struct ofp_flow_removed ),
                         UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  flow_removed = ( struct ofp_flow_removed * ) message->data;

  // flow_removed->cookie
  // flow_removed->priority

  if ( flow_removed->reason > OFPRR_GROUP_DELETE ) {
    return ERROR_INVALID_FLOW_REMOVED_REASON;
  }

  // flow_removed->table_id
  // flow_removed->duration_sec
  // flow_removed->duration_nsec
  // flow_removed->idle_timeout
  // flow_removed->hard_timeout
  // flow_removed->packet_count
  // flow_removed->byte_count

  match_len = ntohs( flow_removed->match.length );
  match_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );

  if ( ntohs( flow_removed->header.length ) < ( offsetof( struct ofp_flow_removed, match ) + match_len ) ) {
    return ERROR_INVALID_LENGTH;
  }

  ret = validate_match( &flow_removed->match );
  if ( ret < 0 ) {
    return ret;
  }

  return 0;
}


int
validate_port_status( const buffer *message ) {
  int ret;
  struct ofp_port_status *port_status;

  assert( message != NULL );

  ret = validate_header( message, OFPT_PORT_STATUS, sizeof( struct ofp_port_status ),
                         sizeof( struct ofp_port_status ) );
  if ( ret < 0 ) {
    return ret;
  }

  port_status = ( struct ofp_port_status * ) message->data;
  if ( port_status->reason > OFPPR_MODIFY ) {
    return ERROR_INVALID_PORT_STATUS_REASON;
  }

  ret = validate_port( &port_status->desc );
  if ( ret < 0 ) {
    return ret;
  }

  return 0;
}


int
validate_packet_out( const buffer *message ) {
  int ret;
  uint16_t data_length;
  struct ofp_packet_out *packet_out;

  assert( message != NULL );

  ret = validate_header( message, OFPT_PACKET_OUT, offsetof( struct ofp_packet_out, actions ),
                         UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  packet_out = ( struct ofp_packet_out * ) message->data;

  ret = validate_port_no( ntohl( packet_out->in_port ) );
  if ( ret < 0 ) {
    return ret;
  }

  if ( ntohs( packet_out->actions_len ) > 0 ) {
    ret = validate_actions( packet_out->actions, ntohs( packet_out->actions_len ) );
    if ( ret < 0 ) {
      return ret;
    }
  }

  if ( ntohs( packet_out->header.length ) >
      ( ( uint16_t ) offsetof( struct ofp_packet_out, actions ) + ntohs( packet_out->actions_len ) ) ) {
    data_length = ( uint16_t ) ( ntohs( packet_out->header.length )
                               - offsetof( struct ofp_packet_out, actions )
                               - ntohs( packet_out->actions_len ) );

    if ( data_length > 0 ) {
      // FIXME: it may be better to check if this is a valid Ethernet frame or not.
    }
  }

  return 0;
}


int
validate_flow_mod( const buffer *message ) {
  int ret;
  uint16_t match_len;
  uint16_t instruction_length;
  struct ofp_flow_mod *flow_mod;

  assert( message != NULL );

  ret = validate_header( message, OFPT_FLOW_MOD, sizeof( struct ofp_flow_mod ),
                         UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  flow_mod = ( struct ofp_flow_mod * ) message->data;

  // flow_mod->cookie
  // flow_mod->cookie_mask
  // flow_mod->table_id

  if ( flow_mod->command > OFPFC_DELETE_STRICT ) {
    return ERROR_UNDEFINED_FLOW_MOD_COMMAND;
  }

  // flow_mod->idle_timeout
  // flow_mod->hard_timeout
  // flow_mod->priority
  // flow_mod->buffer_id

  if ( ( flow_mod->command == OFPFC_DELETE )
       || ( flow_mod->command == OFPFC_DELETE_STRICT ) ) {
    if ( ntohl( flow_mod->out_port ) != OFPP_ANY ) {
      ret = validate_port_no( ntohl( flow_mod->out_port ) );
      if ( ret < 0 ) {
        return ret;
      }
    }
  }

  // flow_mod->out_group

  if ( ( ntohs( flow_mod->flags ) & ~FLOW_MOD_FLAGS ) != 0 ) {
    return ERROR_INVALID_FLOW_MOD_FLAGS;
  }

  match_len = ntohs( flow_mod->match.length );
  match_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );

  if ( ntohs( flow_mod->header.length ) < ( offsetof( struct ofp_flow_mod, match ) + match_len ) ) {
    return ERROR_INVALID_LENGTH;
  }

  ret = validate_match( &flow_mod->match );
  if ( ret < 0 ) {
    return ret;
  }

  instruction_length = ( uint16_t ) ( ntohs( flow_mod->header.length )
                                - offsetof( struct ofp_flow_mod, match ) - match_len );

  if ( instruction_length > 0 ) {
    struct ofp_instruction *instructions = ( struct ofp_instruction * ) ( ( char * ) &flow_mod->match + match_len );
    ret = validate_instructions( instructions, instruction_length );
    if ( ret < 0 ) {
      return ret;
    }
  }

  return 0;
}


static int
validate_bucket( struct ofp_bucket *bucket ) {
  int ret = 0;
  uint16_t length = ntohs( bucket->len );
  uint16_t action_length = 0;

  if ( length < sizeof( struct ofp_bucket ) ) {
    return ERROR_INVALID_LENGTH;
  }

  action_length = ( uint16_t ) ( length - offsetof( struct ofp_bucket, actions ) );
  if ( action_length > 0 ) {
    ret = validate_actions( bucket->actions, action_length );
    if ( ret < 0 ) {
      return ret;
    }
  }

  return 0;
}


int
validate_group_mod( const buffer *message ) {
  int ret;
  uint16_t bucket_len;
  struct ofp_group_mod *group_mod;

  assert( message != NULL );

  ret = validate_header( message, OFPT_GROUP_MOD, sizeof( struct ofp_group_mod ),
                         UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  group_mod = ( struct ofp_group_mod * ) message->data;

  if ( ntohs( group_mod->command ) > GROUP_COMMAND_MAX ) {
    return ERROR_INVALID_GROUP_COMMAND;
  }
  if ( group_mod->type > GROUP_TYPE_MAX ) {
    return ERROR_INVALID_GROUP_TYPE;
  }
  // group_mod->group_id

  bucket_len = ( uint16_t ) ( ntohs( group_mod->header.length )
                                - offsetof( struct ofp_group_mod, buckets ) );

  if ( bucket_len >= sizeof( struct ofp_bucket ) ) {
    struct ofp_bucket *bucket = ( struct ofp_bucket * ) &group_mod->buckets;
    while ( bucket_len >= sizeof( struct ofp_bucket ) ) {
      ret = validate_bucket( bucket );
      if ( ret < 0 ) {
        return ret;
      }
      bucket_len = ( uint16_t ) ( bucket_len - ntohs( bucket->len ) );
      bucket = ( struct ofp_bucket * ) ( ( char * ) bucket + ntohs( bucket->len ) );
    }
  }

  if ( bucket_len != 0 ) {
    return ERROR_INVALID_LENGTH;
  }

  return 0;
}


int
validate_port_mod( const buffer *message ) {
  int ret;
  struct ofp_port_mod *port_mod;

  assert( message != NULL );

  ret = validate_header( message, OFPT_PORT_MOD, sizeof( struct ofp_port_mod ),
                         sizeof( struct ofp_port_mod ) );
  if ( ret < 0 ) {
    return ret;
  }

  port_mod = ( struct ofp_port_mod * ) message->data;

  ret = validate_port_no( ntohl( port_mod->port_no ) );
  if ( ret < 0 ) {
    return ret;
  }
  if ( ( ntohl( port_mod->port_no ) > OFPP_MAX ) && ( ntohl( port_mod->port_no ) != OFPP_LOCAL ) ) {
    return ERROR_INVALID_PORT_NO;
  }

  // port_mod->hw_addr

  if ( ( ntohl( port_mod->config ) & ( uint32_t ) ~PORT_CONFIG ) != 0 ) {
    return ERROR_INVALID_PORT_CONFIG;
  }
  if ( ( ntohl( port_mod->mask ) & ( uint32_t ) ~PORT_CONFIG ) != 0 ) {
    return ERROR_INVALID_PORT_MASK;
  }
  if ( ( ntohl( port_mod->advertise ) & ( uint32_t ) ~PORT_FEATURES ) != 0 ) {
    return ERROR_INVALID_PORT_FEATURES;
  }

  return 0;
}


int
validate_table_mod( const buffer *message ) {
  int ret;
  struct ofp_table_mod *table_mod;

  assert( message != NULL );

  ret = validate_header( message, OFPT_TABLE_MOD, sizeof( struct ofp_table_mod ),
                         sizeof( struct ofp_table_mod ) );
  if ( ret < 0 ) {
    return ret;
  }

  table_mod = ( struct ofp_table_mod * ) message->data;

  // table_mod->table_id
  // table_mod->config
  (void)table_mod;
  
  return 0;
}


int
validate_desc_multipart_request( const buffer *message ) {
  int ret;
  struct ofp_multipart_request *stats_request;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REQUEST, sizeof( struct ofp_multipart_request ),
                         sizeof( struct ofp_multipart_request ) );
  if ( ret < 0 ) {
    return ret;
  }

  stats_request = ( struct ofp_multipart_request * ) message->data;

  if ( ntohs( stats_request->type ) != OFPMP_DESC ) {
    return ERROR_INVALID_STATS_TYPE;
  }
  if ( ntohs( stats_request->flags ) != 0 ) {
    return ERROR_INVALID_STATS_REQUEST_FLAGS;
  }

  return 0;
}


int
validate_flow_multipart_request( const buffer *message ) {
  int ret;
  uint16_t match_len;
  struct ofp_multipart_request *stats_request;
  struct ofp_flow_stats_request *flow_stats_request;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REQUEST,
                         offsetof( struct ofp_multipart_request, body )
                         + sizeof( struct ofp_flow_stats_request ),
                         UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  stats_request = ( struct ofp_multipart_request * ) message->data;

  if ( ntohs( stats_request->type ) != OFPMP_FLOW ) {
    return ERROR_INVALID_STATS_TYPE;
  }

  if ( ( ntohs( stats_request->flags ) & ~OFPMPF_REQ_MORE ) != 0 ) {
    return ERROR_INVALID_STATS_REQUEST_FLAGS;
  }

  flow_stats_request = ( struct ofp_flow_stats_request * ) stats_request->body;

  // flow_stats_request->table_id

  ret = validate_port_no( ntohl( flow_stats_request->out_port ) );
  if ( ret < 0 ) {
    return ret;
  }

  // flow_stats_request->out_group
  // flow_stats_request->cookie
  // flow_stats_request->cookie_mask

  match_len = ntohs( flow_stats_request->match.length );
  match_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );

  if ( ntohs( stats_request->header.length ) < ( offsetof( struct ofp_multipart_request, body )
                                                + offsetof( struct ofp_flow_stats_request, match ) + match_len ) ) {
    return ERROR_INVALID_LENGTH;
  }

  ret = validate_match( &flow_stats_request->match );
  if ( ret < 0 ) {
    return ret;
  }

  return 0;
}


int
validate_aggregate_multipart_request( const buffer *message ) {
  int ret;
  uint16_t match_len;
  struct ofp_multipart_request *stats_request;
  struct ofp_aggregate_stats_request *aggregate_stats_request;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REQUEST,
                         offsetof( struct ofp_multipart_request, body )
                         + sizeof( struct ofp_aggregate_stats_request ),
                         UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  stats_request = ( struct ofp_multipart_request * ) message->data;

  if ( ntohs( stats_request->type ) != OFPMP_AGGREGATE ) {
    return ERROR_INVALID_STATS_TYPE;
  }
  if ( ( ntohs( stats_request->flags ) & ~OFPMPF_REQ_MORE ) != 0 ) {
    return ERROR_INVALID_STATS_REQUEST_FLAGS;
  }

  aggregate_stats_request = ( struct ofp_aggregate_stats_request * ) stats_request->body;

  // aggregate_stats_request->table_id

  ret = validate_port_no( ntohl( aggregate_stats_request->out_port ) );
  if ( ret < 0 ) {
    return ret;
  }

  // aggregate_stats_request->out_group
  // aggregate_stats_request->cookie
  // aggregate_stats_request->cookie_mask

  match_len = ntohs( aggregate_stats_request->match.length );
  match_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );

  if ( ntohs( stats_request->header.length ) < ( offsetof( struct ofp_multipart_request, body )
                                                + offsetof( struct ofp_aggregate_stats_request, match ) + match_len ) ) {
    return ERROR_INVALID_LENGTH;
  }

  ret = validate_match( &aggregate_stats_request->match );
  if ( ret < 0 ) {
    return ret;
  }

  return 0;
}


int
validate_table_multipart_request( const buffer *message ) {
  int ret;
  struct ofp_multipart_request *stats_request;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REQUEST, offsetof( struct ofp_multipart_request, body ),
                         offsetof( struct ofp_multipart_request, body ) );
  if ( ret < 0 ) {
    return ret;
  }

  stats_request = ( struct ofp_multipart_request * ) message->data;

  if ( ntohs( stats_request->type ) != OFPMP_TABLE ) {
    return ERROR_INVALID_STATS_TYPE;
  }
  if ( ntohs( stats_request->flags ) != 0 ) {
    return ERROR_INVALID_STATS_REQUEST_FLAGS;
  }

  return 0;
}


int
validate_port_multipart_request( const buffer *message ) {
  int ret;
  struct ofp_multipart_request *stats_request;
  struct ofp_port_stats_request *port_stats_request;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REQUEST,
                         offsetof( struct ofp_multipart_request, body )
                         + sizeof( struct ofp_port_stats_request ),
                         offsetof( struct ofp_multipart_request, body )
                         + sizeof( struct ofp_port_stats_request ) );
  if ( ret < 0 ) {
    return ret;
  }

  stats_request = ( struct ofp_multipart_request * ) message->data;

  if ( ntohs( stats_request->type ) != OFPMP_PORT_STATS ) {
    return ERROR_INVALID_STATS_TYPE;
  }
  if ( ntohs( stats_request->flags ) != 0 ) {
    return ERROR_INVALID_STATS_REQUEST_FLAGS;
  }

  port_stats_request = ( struct ofp_port_stats_request * ) stats_request->body;

  ret = validate_port_no( ntohl( port_stats_request->port_no ) );
  if ( ret < 0 ) {
    return ret;
  }

  if ( ntohl( port_stats_request->port_no ) > OFPP_MAX
       && ntohl( port_stats_request->port_no ) != OFPP_ANY
       && ntohl( port_stats_request->port_no ) != OFPP_LOCAL ) {
    return ERROR_INVALID_PORT_NO;
  }

  return 0;
}


int
validate_queue_multipart_request( const buffer *message ) {
  int ret;
  struct ofp_multipart_request *stats_request;
  struct ofp_queue_stats_request *queue_stats_request;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REQUEST,
                         offsetof( struct ofp_multipart_request, body )
                         + sizeof( struct ofp_queue_stats_request ),
                         offsetof( struct ofp_multipart_request, body )
                         + sizeof( struct ofp_queue_stats_request ) );
  if ( ret < 0 ) {
    return ret;
  }

  stats_request = ( struct ofp_multipart_request * ) message->data;

  if ( ntohs( stats_request->type ) != OFPMP_QUEUE ) {
    return ERROR_INVALID_STATS_TYPE;
  }
  if ( ntohs( stats_request->flags ) != 0 ) {
    return ERROR_INVALID_STATS_REQUEST_FLAGS;
  }

  queue_stats_request = ( struct ofp_queue_stats_request * ) stats_request->body;

  ret = validate_port_no( ntohl( queue_stats_request->port_no ) );
  if ( ret < 0 ) {
    return ret;
  }

  return 0;
}


int
validate_group_multipart_request( const buffer *message ) {
  int ret;
  struct ofp_multipart_request *stats_request;
  //struct ofp_group_stats_request *group_stats_request;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REQUEST,
                         offsetof( struct ofp_multipart_request, body )
                         + sizeof( struct ofp_group_stats_request ),
                         offsetof( struct ofp_multipart_request, body )
                         + sizeof( struct ofp_group_stats_request ) );
  if ( ret < 0 ) {
    return ret;
  }

  stats_request = ( struct ofp_multipart_request * ) message->data;

  if ( ntohs( stats_request->type ) != OFPMP_GROUP ) {
    return ERROR_INVALID_STATS_TYPE;
  }
  if ( ntohs( stats_request->flags ) != 0 ) {
    return ERROR_INVALID_STATS_REQUEST_FLAGS;
  }

  //group_stats_request = ( struct ofp_group_stats_request * ) stats_request->body;

  return 0;
}


int
validate_group_desc_multipart_request( const buffer *message ) {
  int ret;
  struct ofp_multipart_request *stats_request;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REQUEST,
                         offsetof( struct ofp_multipart_request, body ),
                         offsetof( struct ofp_multipart_request, body ) );
  if ( ret < 0 ) {
    return ret;
  }

  stats_request = ( struct ofp_multipart_request * ) message->data;

  if ( ntohs( stats_request->type ) != OFPMP_GROUP_DESC ) {
    return ERROR_INVALID_STATS_TYPE;
  }
  if ( ntohs( stats_request->flags ) != 0 ) {
    return ERROR_INVALID_STATS_REQUEST_FLAGS;
  }

  return 0;
}


int
validate_group_features_multipart_request( const buffer *message ) {
  int ret;
  struct ofp_multipart_request *stats_request;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REQUEST,
                         offsetof( struct ofp_multipart_request, body ),
                         offsetof( struct ofp_multipart_request, body ) );
  if ( ret < 0 ) {
    return ret;
  }

  stats_request = ( struct ofp_multipart_request * ) message->data;

  if ( ntohs( stats_request->type ) != OFPMP_GROUP_FEATURES ) {
    return ERROR_INVALID_STATS_TYPE;
  }
  if ( ntohs( stats_request->flags ) != 0 ) {
    return ERROR_INVALID_STATS_REQUEST_FLAGS;
  }

  return 0;
}


int
validate_meter_multipart_request( const buffer *message ) {
  int ret;
  struct ofp_multipart_request *stats_request;
  //struct ofp_meter_multipart_request *meter_stats_request;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REQUEST,
                         offsetof( struct ofp_multipart_request, body )
                         + sizeof( struct ofp_meter_multipart_request ),
                         offsetof( struct ofp_multipart_request, body )
                         + sizeof( struct ofp_meter_multipart_request ) );
  if ( ret < 0 ) {
    return ret;
  }

  stats_request = ( struct ofp_multipart_request * ) message->data;

  if ( ntohs( stats_request->type ) != OFPMP_METER ) {
    return ERROR_INVALID_STATS_TYPE;
  }
  if ( ntohs( stats_request->flags ) != 0 ) {
    return ERROR_INVALID_STATS_REQUEST_FLAGS;
  }

  //meter_stats_request = ( struct ofp_meter_multipart_request * ) stats_request->body;

  return 0;
}


int
validate_meter_config_multipart_request( const buffer *message ) {
  int ret;
  struct ofp_multipart_request *stats_request;
  //struct ofp_meter_multipart_request *meter_stats_request;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REQUEST,
                         offsetof( struct ofp_multipart_request, body )
                         + sizeof( struct ofp_meter_multipart_request ),
                         offsetof( struct ofp_multipart_request, body )
                         + sizeof( struct ofp_meter_multipart_request ) );
  if ( ret < 0 ) {
    return ret;
  }

  stats_request = ( struct ofp_multipart_request * ) message->data;

  if ( ntohs( stats_request->type ) != OFPMP_METER_CONFIG ) {
    return ERROR_INVALID_STATS_TYPE;
  }
  if ( ntohs( stats_request->flags ) != 0 ) {
    return ERROR_INVALID_STATS_REQUEST_FLAGS;
  }

  //meter_stats_request = ( struct ofp_meter_multipart_request * ) stats_request->body;

  return 0;
}


int
validate_meter_features_multipart_request( const buffer *message ) {
  int ret;
  struct ofp_multipart_request *stats_request;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REQUEST,
                         offsetof( struct ofp_multipart_request, body ),
                         offsetof( struct ofp_multipart_request, body ) );
  if ( ret < 0 ) {
    return ret;
  }

  stats_request = ( struct ofp_multipart_request * ) message->data;

  if ( ntohs( stats_request->type ) != OFPMP_METER_FEATURES ) {
    return ERROR_INVALID_STATS_TYPE;
  }
  if ( ntohs( stats_request->flags ) != 0 ) {
    return ERROR_INVALID_STATS_REQUEST_FLAGS;
  }

  return 0;
}


int
validate_table_features_multipart_request( const buffer *message ) {
  int ret;
  uint16_t table_length;
  uint16_t offset;
  struct ofp_multipart_request *stats_request;
  struct ofp_table_features *table_features;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REQUEST,
                         offsetof( struct ofp_multipart_request, body ),
                         UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  stats_request = ( struct ofp_multipart_request * ) message->data;

  if ( ntohs( stats_request->type ) != OFPMP_TABLE_FEATURES ) {
    return ERROR_INVALID_STATS_TYPE;
  }
  if ( ( ntohs( stats_request->flags ) & ~OFPMPF_REQ_MORE ) != 0 ) {
    return ERROR_INVALID_STATS_REPLY_FLAGS;
  }

  table_length = ( uint16_t ) ( ntohs( stats_request->header.length )
                                - offsetof( struct ofp_multipart_reply, body ) );

  offset = offsetof( struct ofp_multipart_request, body );
  table_features = ( struct ofp_table_features * ) ( ( char * ) message->data + offset );

  while ( table_length > 0 ) {
    if ( table_length < ntohs( table_features->length ) ) {
      return ERROR_INVALID_LENGTH;
    }

    // table_features->table_id
    // table_features->name
    // table_features->metadata_match
    // table_features->metadata_write
    // table_features->config
    // table_features->max_entries

    table_length = ( uint16_t ) ( table_length - ntohs( table_features->length ) );
    table_features = ( struct ofp_table_features * ) ( ( char * ) table_features + ntohs( table_features->length ) );
  }

  return 0;
}


int
validate_port_desc_multipart_request( const buffer *message ) {
  int ret;
  struct ofp_multipart_request *stats_request;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REQUEST,
                         offsetof( struct ofp_multipart_request, body ),
                         offsetof( struct ofp_multipart_request, body ) );
  if ( ret < 0 ) {
    return ret;
  }

  stats_request = ( struct ofp_multipart_request * ) message->data;

  if ( ntohs( stats_request->type ) != OFPMP_PORT_DESC ) {
    return ERROR_INVALID_STATS_TYPE;
  }
  if ( ntohs( stats_request->flags ) != 0 ) {
    return ERROR_INVALID_STATS_REQUEST_FLAGS;
  }

  return 0;
}


int
validate_experimenter_multipart_request( const buffer *message ) {
  int ret;
  struct ofp_multipart_request *stats_request;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REQUEST,
                         offsetof( struct ofp_multipart_request, body )
                        + sizeof( struct ofp_experimenter_multipart_header ),
                         UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  stats_request = ( struct ofp_multipart_request * ) message->data;

  if ( ntohs( stats_request->type ) != OFPMP_EXPERIMENTER ) {
    return ERROR_INVALID_STATS_TYPE;
  }
  if ( ( ntohs( stats_request->flags ) & ~OFPMPF_REQ_MORE ) != 0 ) {
    return ERROR_INVALID_STATS_REQUEST_FLAGS;
  }

  // experimenter
  // exp_type

  return 0;
}


int
validate_multipart_request( const buffer *message ) {
  struct ofp_multipart_request *request;

  assert( message != NULL );

  request = ( struct ofp_multipart_request * ) message->data;

  // TODO: if ( request->header.type != OFPT_MULTIPART_REQUEST ) { ... }

  switch ( ntohs( request->type ) ) {
  case OFPMP_DESC:
    return validate_desc_multipart_request( message );
  case OFPMP_FLOW:
    return validate_flow_multipart_request( message );
  case OFPMP_AGGREGATE:
    return validate_aggregate_multipart_request( message );
  case OFPMP_TABLE:
    return validate_table_multipart_request( message );
  case OFPMP_PORT_STATS:
    return validate_port_multipart_request( message );
  case OFPMP_QUEUE:
    return validate_queue_multipart_request( message );
  case OFPMP_GROUP:
    return validate_group_multipart_request( message );
  case OFPMP_GROUP_DESC:
    return validate_group_desc_multipart_request( message );
  case OFPMP_GROUP_FEATURES:
    return validate_group_features_multipart_request( message );
  case OFPMP_METER:
    return validate_meter_multipart_request( message );
  case OFPMP_METER_CONFIG:
    return validate_meter_config_multipart_request( message );
  case OFPMP_METER_FEATURES:
    return validate_meter_features_multipart_request( message );
  case OFPMP_TABLE_FEATURES:
    return validate_table_features_multipart_request( message );
  case OFPMP_PORT_DESC:
    return validate_port_desc_multipart_request( message );
  case OFPMP_EXPERIMENTER:
    return validate_experimenter_multipart_request( message );
  default:
    break;
  }

  return ERROR_UNSUPPORTED_STATS_TYPE;
}


int
validate_desc_multipart_reply( const buffer *message ) {
  int ret;
  struct ofp_multipart_reply *stats_reply;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REPLY,
                         offsetof( struct ofp_multipart_reply, body ) + sizeof( struct ofp_desc ),
                         offsetof( struct ofp_multipart_reply, body ) + sizeof( struct ofp_desc ) );
  if ( ret < 0 ) {
    return ret;
  }

  stats_reply = ( struct ofp_multipart_reply * ) message->data;
  if ( ntohs( stats_reply->flags ) != 0 ) {
    return ERROR_INVALID_STATS_REPLY_FLAGS;
  }

  return 0;
}


int
validate_flow_multipart_reply( const buffer *message ) {
  int ret;
  uint16_t offset;
  uint16_t match_len;
  uint16_t flow_length;
  uint16_t instructions_length;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_flow_stats *flow_stats;
  struct ofp_instruction *instructions_head;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REPLY, offsetof( struct ofp_multipart_reply, body ),
                         UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  stats_reply = ( struct ofp_multipart_reply * ) message->data;
  if ( ( ntohs( stats_reply->flags ) & ~OFPMPF_REPLY_MORE ) != 0 ) {
    return ERROR_INVALID_STATS_REPLY_FLAGS;
  }

  flow_length = ( uint16_t ) ( ntohs( stats_reply->header.length )
                              - offsetof( struct ofp_multipart_reply, body ) );

  offset = offsetof( struct ofp_multipart_reply, body );
  flow_stats = ( struct ofp_flow_stats * ) ( ( char * ) message->data + offset );

  while ( flow_length > 0 ) {
    if ( flow_length < ntohs( flow_stats->length ) ) {
      return ERROR_INVALID_LENGTH;
    }

    // flow_stats->table_id
    // flow_stats->duration_sec
    // flow_stats->duration_nsec
    // flow_stats->priority
    // flow_stats->idle_timeout
    // flow_stats->hard_timeout

    if ( ( ntohs( flow_stats->flags ) & ( uint16_t ) ~FLOW_MOD_FLAGS ) != 0 ) {
      return ERROR_INVALID_FLOW_MOD_FLAGS;
    }

    // flow_stats->cookie
    // flow_stats->packet_count
    // flow_stats->byte_count

    match_len = ntohs( flow_stats->match.length );
    match_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );

    if ( flow_length < ( offsetof( struct ofp_flow_stats, match ) + match_len ) ) {
      return ERROR_INVALID_LENGTH;
    }

    ret = validate_match( &flow_stats->match );
    if ( ret < 0 ) {
      return ret;
    }

    if ( ntohs( flow_stats->length ) < offsetof( struct ofp_flow_stats, match ) + match_len ) {
      return ERROR_INVALID_LENGTH;
    }

    instructions_length = ( uint16_t ) ( ntohs( flow_stats->length )
                                        - offsetof( struct ofp_flow_stats, match ) - match_len );
    if ( instructions_length > 0 ) {
      instructions_head = ( struct ofp_instruction * ) ( ( char * ) flow_stats
                                                       + offsetof( struct ofp_flow_stats, match )
                                                       + match_len );

      ret = validate_instructions( instructions_head, instructions_length );
      if ( ret < 0 ) {
        return ret;
      }
    }

    flow_length = ( uint16_t ) ( flow_length - ntohs( flow_stats->length ) );
    flow_stats = ( struct ofp_flow_stats * ) ( ( char * ) flow_stats + ntohs( flow_stats->length ) );

  }

  return 0;
}


int
validate_aggregate_multipart_reply( const buffer *message ) {
  int ret;
  struct ofp_multipart_reply *stats_reply;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REPLY,
                         offsetof( struct ofp_multipart_reply, body ) + sizeof( struct ofp_aggregate_stats_reply ),
                         offsetof( struct ofp_multipart_reply, body ) + sizeof( struct ofp_aggregate_stats_reply ) );
  if ( ret < 0 ) {
    return ret;
  }

  stats_reply = ( struct ofp_multipart_reply * ) message->data;
  if ( ntohs( stats_reply->flags ) != 0 ) {
    return ERROR_INVALID_STATS_REPLY_FLAGS;
  }

  // uint16_t offset = offsetof( struct ofp_multipart_reply, body );
  // struct ofp_aggregate_stats_reply *aggregate_stats = ( struct ofp_aggregate_stats_reply * ) ( ( char * ) message->data + offset );

  // aggregate_stats->packet_count
  // aggregate_stats->byte_count
  // aggregate_stats->flow_count

  return 0;
}


int
validate_table_multipart_reply( const buffer *message ) {
  int i;
  int ret;
  uint16_t tables_length;
  uint16_t n_tables;
  uint16_t offset;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_table_stats *table_stats;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REPLY,
                         offsetof( struct ofp_multipart_reply, body ) + sizeof( struct ofp_table_stats ),
                         UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  stats_reply = ( struct ofp_multipart_reply * ) message->data;
  if ( ( ntohs( stats_reply->flags ) & ~OFPMPF_REPLY_MORE ) != 0 ) {
    return ERROR_INVALID_STATS_REPLY_FLAGS;
  }

  tables_length = ( uint16_t ) ( ntohs( stats_reply->header.length )
                                - offsetof( struct ofp_multipart_reply, body ) );
  if ( tables_length % sizeof( struct ofp_table_stats ) != 0 ) {
    return ERROR_INVALID_LENGTH;
  }

  offset = offsetof( struct ofp_multipart_reply, body );
  table_stats = ( struct ofp_table_stats * ) ( ( char * ) message->data + offset );

  n_tables = tables_length / sizeof( struct ofp_table_stats );

  for ( i = 0; i < n_tables; i++ ) {
    // table_stats->table_id
    // table_stats->active_count
    // table_stats->lookup_count
    // table_stats->matched_count

    table_stats++;
  }

  return 0;
}


int
validate_port_multipart_reply( const buffer *message ) {
  int i;
  int ret;
  uint16_t ports_length;
  uint16_t n_ports;
  uint16_t offset;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_port_stats *port_stats;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REPLY,
                         offsetof( struct ofp_multipart_reply, body ) + sizeof( struct ofp_port_stats ),
                         UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  stats_reply = ( struct ofp_multipart_reply * ) message->data;
  if ( ( ntohs( stats_reply->flags ) & ~OFPMPF_REPLY_MORE ) != 0 ) {
    return ERROR_INVALID_STATS_REPLY_FLAGS;
  }

  ports_length = ( uint16_t ) ( ntohs( stats_reply->header.length )
                              - offsetof( struct ofp_multipart_reply, body ) );
  if ( ports_length % sizeof( struct ofp_port_stats ) != 0 ) {
    return ERROR_INVALID_LENGTH;
  }

  offset = offsetof( struct ofp_multipart_reply, body );
  port_stats = ( struct ofp_port_stats * ) ( ( char * ) message->data + offset );

  n_ports = ports_length / sizeof( struct ofp_port_stats );
  for ( i = 0; i < n_ports; i++ ) {
    ret = validate_port_no( ntohl( port_stats->port_no ) );

    if ( ret < 0 ) {
      return ret;
    }

    // port_stats->rx_packets
    // port_stats->tx_packets
    // port_stats->rx_bytes
    // port_stats->tx_bytes
    // port_stats->rx_dropped
    // port_stats->tx_dropped
    // port_stats->rx_errors
    // port_stats->tx_errors
    // port_stats->rx_frame_err
    // port_stats->rx_over_err
    // port_stats->rx_crc_err
    // port_stats->collisions
    // port_stats->duration_sec
    // port_stats->duration_nsec

    port_stats++;
  }

  return 0;
}


int
validate_queue_multipart_reply( const buffer *message ) {
  int i;
  int ret;
  uint16_t queues_length;
  uint16_t n_queues;
  uint16_t offset;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_queue_stats *queue_stats;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REPLY,
                         offsetof( struct ofp_multipart_reply, body ),
                         UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  stats_reply = ( struct ofp_multipart_reply * ) message->data;
  if ( ( ntohs( stats_reply->flags ) & ~OFPMPF_REPLY_MORE ) != 0 ) {
    return ERROR_INVALID_STATS_REPLY_FLAGS;
  }

  queues_length = ( uint16_t ) ( ntohs( stats_reply->header.length )
                                 - offsetof( struct ofp_multipart_reply, body ) );
  if ( queues_length % sizeof( struct ofp_queue_stats ) != 0 ) {
    return ERROR_INVALID_LENGTH;
  }

  offset = offsetof( struct ofp_multipart_reply, body );
  queue_stats = ( struct ofp_queue_stats * ) ( ( char * ) message->data + offset );

  n_queues = queues_length / sizeof( struct ofp_queue_stats );
  for ( i = 0; i < n_queues; i++ ) {
    ret = validate_port_no( ntohl( queue_stats->port_no ) );
    if ( ret < 0 ) {
      return ret;
    }

    // queue_stats->queue_id
    // queue_stats->tx_bytes
    // queue_stats->tx_packets
    // queue_stats->tx_errors
    // queue_stats->duration_sec
    // queue_stats->duration_nsec

    queue_stats++;
  }

  return 0;
}


int
validate_group_multipart_reply( const buffer *message ) {
  int ret;
  uint16_t group_length;
  uint16_t offset;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_group_stats *group_stats;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REPLY,
                         offsetof( struct ofp_multipart_reply, body ),
                         UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  stats_reply = ( struct ofp_multipart_reply * ) message->data;
  if ( ( ntohs( stats_reply->flags ) & ~OFPMPF_REPLY_MORE ) != 0 ) {
    return ERROR_INVALID_STATS_REPLY_FLAGS;
  }

  group_length = ( uint16_t ) ( ntohs( stats_reply->header.length )
                                - offsetof( struct ofp_multipart_reply, body ) );

  offset = offsetof( struct ofp_multipart_reply, body );
  group_stats = ( struct ofp_group_stats * ) ( ( char * ) message->data + offset );

  while ( group_length > 0 ) {
    if ( group_length < ntohs( group_stats->length ) ) {
      return ERROR_INVALID_LENGTH;
    }

    // group_stats->group_id
    // group_stats->ref_count
    // group_stats->packet_count
    // group_stats->byte_count
    // group_stats->duration_sec
    // group_stats->duration_nsec
    // group_stats->bucket_stats.packet_count
    // group_stats->bucket_stats.byte_count

    group_length = ( uint16_t ) ( group_length - ntohs( group_stats->length ) );
    group_stats = ( struct ofp_group_stats * ) ( ( char * ) group_stats + ntohs( group_stats->length ) );
  }

  return 0;
}


int
validate_group_desc_multipart_reply( const buffer *message ) {
  int ret;
  uint16_t group_length;
  uint16_t offset;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_group_desc *group_desc;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REPLY,
                         offsetof( struct ofp_multipart_reply, body ),
                         UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  stats_reply = ( struct ofp_multipart_reply * ) message->data;
  if ( ( ntohs( stats_reply->flags ) & ~OFPMPF_REPLY_MORE ) != 0 ) {
    return ERROR_INVALID_STATS_REPLY_FLAGS;
  }

  group_length = ( uint16_t ) ( ntohs( stats_reply->header.length )
                                - offsetof( struct ofp_multipart_reply, body ) );

  offset = offsetof( struct ofp_multipart_reply, body );
  group_desc = ( struct ofp_group_desc * ) ( ( char * ) message->data + offset );

  while ( group_length > 0 ) {
    if ( group_length < ntohs( group_desc->length ) ) {
      return ERROR_INVALID_LENGTH;
    }

    if ( group_desc->type > GROUP_TYPE_MAX ) {
      return ERROR_INVALID_GROUP_TYPE;
    }
    // group_desc->group_id

    if ( ntohs( group_desc->length ) > offsetof( struct ofp_group_desc, buckets ) ) {
      uint16_t bucket_len = ( uint16_t ) ( ntohs( group_desc->length ) - offsetof( struct ofp_group_desc, buckets ) );
      if ( bucket_len >= sizeof( struct ofp_bucket ) ) {
        struct ofp_bucket *bucket = ( struct ofp_bucket * ) &group_desc->buckets;
        while ( bucket_len >= sizeof( struct ofp_bucket ) ) {
          ret = validate_bucket( bucket );
          if ( ret < 0 ) {
            return ret;
          }
          bucket_len = ( uint16_t ) ( bucket_len - ntohs( bucket->len ) );
          bucket = ( struct ofp_bucket * ) ( ( char * ) bucket + ntohs( bucket->len ) );
        }
      }
    }

    group_length = ( uint16_t ) ( group_length - ntohs( group_desc->length ) );
    group_desc = ( struct ofp_group_desc * ) ( ( char * ) group_desc + ntohs( group_desc->length ) );
  }

  return 0;
}


int
validate_group_features_multipart_reply( const buffer *message ) {
  int ret;
  uint16_t offset;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_group_features *group_features;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REPLY,
                         offsetof( struct ofp_multipart_reply, body ) + sizeof( struct ofp_group_features ),
                         offsetof( struct ofp_multipart_reply, body ) + sizeof( struct ofp_group_features ) );
  if ( ret < 0 ) {
    return ret;
  }

  stats_reply = ( struct ofp_multipart_reply * ) message->data;
  if ( ( ntohs( stats_reply->flags ) & ~OFPMPF_REPLY_MORE ) != 0 ) {
    return ERROR_INVALID_STATS_REPLY_FLAGS;
  }

  offset = offsetof( struct ofp_multipart_reply, body );
  group_features = ( struct ofp_group_features * ) ( ( char * ) message->data + offset );

  if ( ( ntohl( group_features->types ) & ( uint32_t ) ~GROUP_TYPE ) != 0 ) {
    return ERROR_INVALID_GROUP_TYPE;
  }

  // group_features->capabilities
  // group_features->max_groups[ 0 ]
  // group_features->max_groups[ 1 ]
  // group_features->max_groups[ 2 ]
  // group_features->max_groups[ 3 ]
  // group_features->actions[ 0 ]
  // group_features->actions[ 1 ]
  // group_features->actions[ 2 ]
  // group_features->actions[ 3 ]

  return 0;
}


int
validate_meter_multipart_reply( const buffer *message ) {
  int ret;
  uint16_t meter_length;
  uint16_t offset;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_meter_stats *meter_stats;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REPLY,
                         offsetof( struct ofp_multipart_reply, body ),
                         UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  stats_reply = ( struct ofp_multipart_reply * ) message->data;
  if ( ( ntohs( stats_reply->flags ) & ~OFPMPF_REPLY_MORE ) != 0 ) {
    return ERROR_INVALID_STATS_REPLY_FLAGS;
  }

  meter_length = ( uint16_t ) ( ntohs( stats_reply->header.length )
                                - offsetof( struct ofp_multipart_reply, body ) );

  offset = offsetof( struct ofp_multipart_reply, body );
  meter_stats = ( struct ofp_meter_stats * ) ( ( char * ) message->data + offset );

  while ( meter_length > 0 ) {
    // meter_stats->meter_id

    if ( meter_length < ntohs( meter_stats->len ) ) {
      return ERROR_INVALID_LENGTH;
    }

    // meter_stats->flow_count
    // meter_stats->packet_in_count
    // meter_stats->byte_in_count
    // meter_stats->duration_sec
    // meter_stats->duration_nsec
    // meter_stats->band_stats.packet_band_count
    // meter_stats->band_stats.byte_band_count

    meter_length = ( uint16_t ) ( meter_length - ntohs( meter_stats->len ) );
    meter_stats = ( struct ofp_meter_stats * ) ( ( char * ) meter_stats + ntohs( meter_stats->len ) );
  }

  return 0;
}


int
validate_meter_config_multipart_reply( const buffer *message ) {
  int ret;
  uint16_t meter_length;
  uint16_t offset;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_meter_config *meter_config;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REPLY,
                         offsetof( struct ofp_multipart_reply, body ),
                         UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  stats_reply = ( struct ofp_multipart_reply * ) message->data;
  if ( ( ntohs( stats_reply->flags ) & ~OFPMPF_REPLY_MORE ) != 0 ) {
    return ERROR_INVALID_STATS_REPLY_FLAGS;
  }

  meter_length = ( uint16_t ) ( ntohs( stats_reply->header.length )
                                - offsetof( struct ofp_multipart_reply, body ) );

  offset = offsetof( struct ofp_multipart_reply, body );
  meter_config = ( struct ofp_meter_config * ) ( ( char * ) message->data + offset );

  while ( meter_length > 0 ) {
    if ( meter_length < ntohs( meter_config->length ) ) {
      return ERROR_INVALID_LENGTH;
    }

    if ( ( ntohs( meter_config->flags ) & ~METER_FLAGS ) != 0 ) {
      return ERROR_INVALID_METER_FLAGS;
    }
    // meter_config->meter_id
    // meter_config->bands.type
    // meter_config->bands.len
    // meter_config->bands.rate
    // meter_config->bands.burst_size

    meter_length = ( uint16_t ) ( meter_length - ntohs( meter_config->length ) );
    meter_config = ( struct ofp_meter_config * ) ( ( char * ) meter_config + ntohs( meter_config->length ) );
  }

  return 0;
}


int
validate_meter_features_multipart_reply( const buffer *message ) {
  int ret;
  uint16_t offset;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_meter_features *meter_features;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REPLY,
                         offsetof( struct ofp_multipart_reply, body ) + sizeof( struct ofp_meter_features ),
                         offsetof( struct ofp_multipart_reply, body ) + sizeof( struct ofp_meter_features ) );
  if ( ret < 0 ) {
    return ret;
  }

  stats_reply = ( struct ofp_multipart_reply * ) message->data;
  if ( ( ntohs( stats_reply->flags ) & ~OFPMPF_REPLY_MORE ) != 0 ) {
    return ERROR_INVALID_STATS_REPLY_FLAGS;
  }

  offset = offsetof( struct ofp_multipart_reply, body );
  meter_features = ( struct ofp_meter_features * ) ( ( char * ) message->data + offset );

  // meter_features->max_meter

  if ( ( ntohl( meter_features->band_types ) & ( uint32_t ) ~METER_BAND_TYPE ) != 0 ) {
    return ERROR_INVALID_METER_BAND_TYPE;
  }
  if ( ( ntohl( meter_features->capabilities ) & ( uint32_t ) ~METER_FLAGS ) != 0 ) {
    return ERROR_INVALID_METER_FLAGS;
  }
  // meter_features->max_bands
  // meter_features->max_color

  return 0;
}


int
validate_table_features_multipart_reply( const buffer *message ) {
  int ret;
  uint16_t table_length;
  uint16_t offset;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_table_features *table_features;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REPLY,
                         offsetof( struct ofp_multipart_reply, body ),
                         UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  stats_reply = ( struct ofp_multipart_reply * ) message->data;
  if ( ( ntohs( stats_reply->flags ) & ~OFPMPF_REPLY_MORE ) != 0 ) {
    return ERROR_INVALID_STATS_REPLY_FLAGS;
  }

  table_length = ( uint16_t ) ( ntohs( stats_reply->header.length )
                                - offsetof( struct ofp_multipart_reply, body ) );

  offset = offsetof( struct ofp_multipart_reply, body );
  table_features = ( struct ofp_table_features * ) ( ( char * ) message->data + offset );

  while ( table_length > 0 ) {
    if ( table_length < ntohs( table_features->length ) ) {
      return ERROR_INVALID_LENGTH;
    }

    // table_features->table_id
    // table_features->name
    // table_features->metadata_match
    // table_features->metadata_write
    // table_features->config
    // table_features->max_entries

    table_length = ( uint16_t ) ( table_length - ntohs( table_features->length ) );
    table_features = ( struct ofp_table_features * ) ( ( char * ) table_features + ntohs( table_features->length ) );
  }

  return 0;
}


int
validate_port_desc_multipart_reply( const buffer *message ) {
  int ret;
  uint16_t port_length;
  uint16_t n_tables;
  uint16_t offset;
  struct ofp_multipart_reply *stats_reply;
  struct ofp_port *port_desc;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REPLY,
                         offsetof( struct ofp_multipart_reply, body ),
                         UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  stats_reply = ( struct ofp_multipart_reply * ) message->data;
  if ( ( ntohs( stats_reply->flags ) & ~OFPMPF_REPLY_MORE ) != 0 ) {
    return ERROR_INVALID_STATS_REPLY_FLAGS;
  }

  port_length = ( uint16_t ) ( ntohs( stats_reply->header.length )
                                - offsetof( struct ofp_multipart_reply, body ) );
  if ( port_length % sizeof( struct ofp_port ) != 0 ) {
    return ERROR_INVALID_LENGTH;
  }

  offset = offsetof( struct ofp_multipart_reply, body );
  port_desc = ( struct ofp_port * ) ( ( char * ) message->data + offset );

  n_tables = port_length / sizeof( struct ofp_port );
  if ( n_tables > 0 ) {
    ret = validate_ports( port_desc, n_tables );
    if ( ret < 0 ) {
      return ret;
    }
  }

  return 0;
}


int
validate_experimenter_multipart_reply( const buffer *message ) {
  void *body;
  int ret;
  uint16_t body_length;
  uint16_t offset;
  struct ofp_multipart_reply *stats_reply;

  assert( message != NULL );

  ret = validate_header( message, OFPT_MULTIPART_REPLY,
                         offsetof( struct ofp_multipart_reply, body ) + sizeof( struct ofp_experimenter_multipart_header ),
                         UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  stats_reply = ( struct ofp_multipart_reply * ) message->data;

  if ( ( ntohs( stats_reply->flags ) & ~OFPMPF_REPLY_MORE ) != 0 ) {
    return ERROR_INVALID_STATS_REPLY_FLAGS;
  }

  body_length = ( uint16_t ) ( ntohs( stats_reply->header.length )
                             - offsetof( struct ofp_multipart_reply, body ) );

  offset = ( uint16_t ) ( offsetof( struct ofp_multipart_reply, body ) + sizeof( struct ofp_experimenter_multipart_header ) );
  body = ( void * ) ( ( char * ) message->data + offset );
  if ( ( body_length > 0 ) && ( body != NULL ) ) {
    // FIXME: validate body here
  }

  return 0;
}


int
validate_multipart_reply( const buffer *message ) {
  struct ofp_multipart_reply *reply;

  assert( message != NULL );
  assert( message->data != NULL );

  reply = ( struct ofp_multipart_reply * ) message->data;

  // TODO: if ( reply->header.type != OFPT_MULTIPART_REPLY ) { ... }

  switch ( ntohs( reply->type ) ) {
  case OFPMP_DESC:
    return validate_desc_multipart_reply( message );
  case OFPMP_FLOW:
    return validate_flow_multipart_reply( message );
  case OFPMP_AGGREGATE:
    return validate_aggregate_multipart_reply( message );
  case OFPMP_TABLE:
    return validate_table_multipart_reply( message );
  case OFPMP_PORT_STATS:
    return validate_port_multipart_reply( message );
  case OFPMP_QUEUE:
    return validate_queue_multipart_reply( message );
  case OFPMP_GROUP:
    return validate_group_multipart_reply( message );
  case OFPMP_GROUP_DESC:
    return validate_group_desc_multipart_reply( message );
  case OFPMP_GROUP_FEATURES:
    return validate_group_features_multipart_reply( message );
  case OFPMP_METER:
    return validate_meter_multipart_reply( message );
  case OFPMP_METER_CONFIG:
    return validate_meter_config_multipart_reply( message );
  case OFPMP_METER_FEATURES:
    return validate_meter_features_multipart_reply( message );
  case OFPMP_TABLE_FEATURES:
    return validate_table_features_multipart_reply( message );
  case OFPMP_PORT_DESC:
    return validate_port_desc_multipart_reply( message );
  case OFPMP_EXPERIMENTER:
    return validate_experimenter_multipart_reply( message );
  default:
    break;
  }

  return ERROR_UNSUPPORTED_STATS_TYPE;
}


int
validate_barrier_request( const buffer *message ) {
  return validate_header( message, OFPT_BARRIER_REQUEST, sizeof( struct ofp_header ),
                          sizeof( struct ofp_header ) );
}


int
validate_barrier_reply( const buffer *message ) {
  return validate_header( message, OFPT_BARRIER_REPLY, sizeof( struct ofp_header ),
                          sizeof( struct ofp_header ) );
}


int
validate_queue_get_config_request( const buffer *message ) {
  int ret;
  struct ofp_queue_get_config_request *queue_get_config_request;

  ret = validate_header( message, OFPT_QUEUE_GET_CONFIG_REQUEST,
                         sizeof( struct ofp_queue_get_config_request ),
                         sizeof( struct ofp_queue_get_config_request ) );
  if ( ret < 0 ) {
    return ret;
  }

  queue_get_config_request = ( struct ofp_queue_get_config_request * ) message->data;

  ret = validate_port_no( ntohl( queue_get_config_request->port ) );
  if ( ret < 0 ) {
    return ret;
  }

  return 0;
}


static int
validate_queue_property( const struct ofp_queue_prop_header *property ) {
  uint16_t property_length = ntohs( property->len );

  if ( property_length < sizeof( struct ofp_queue_prop_header ) ) {
    return ERROR_TOO_SHORT_QUEUE_PROPERTY;
  }

  switch ( ntohs( property->property ) ) {
  case OFPQT_MIN_RATE:
    if ( property_length < sizeof( struct ofp_queue_prop_min_rate ) ) {
      return ERROR_TOO_SHORT_QUEUE_PROPERTY;
    }
    else if ( property_length > sizeof( struct ofp_queue_prop_min_rate ) ) {
      return ERROR_TOO_LONG_QUEUE_PROPERTY;
    }
    break;
  case OFPQT_MAX_RATE:
    if ( property_length < sizeof( struct ofp_queue_prop_max_rate ) ) {
      return ERROR_TOO_SHORT_QUEUE_PROPERTY;
    }
    else if ( property_length > sizeof( struct ofp_queue_prop_max_rate ) ) {
      return ERROR_TOO_LONG_QUEUE_PROPERTY;
    }
    break;
  case OFPQT_EXPERIMENTER:
    break;
  default:
    return ERROR_UNDEFINED_QUEUE_PROPERTY;
  }

  return 0;
}


static int
validate_queue_properties( struct ofp_queue_prop_header *prop_head,
                           const uint16_t properties_length ) {
  int ret;
  uint16_t offset = 0;
  struct ofp_queue_prop_header *property;

  property = prop_head;
  while ( offset < properties_length ) {
    ret = validate_queue_property( property );
    if ( ret < 0 ) {
      return ret;
    }

    offset = ( uint16_t ) ( offset + ntohs( property->len ) );
    property = ( struct ofp_queue_prop_header * ) ( ( char * ) prop_head + offset );
  }

  return 0;
}


static int
validate_packet_queue( struct ofp_packet_queue *queue ) {
  int ret;
  uint16_t properties_length;
  struct ofp_queue_prop_header *prop_head;

  assert( queue != NULL );

  // queue->queue_id

  if ( ntohs( queue->len ) < ( offsetof( struct ofp_packet_queue, properties )
                             + sizeof( struct ofp_queue_prop_header ) ) ) {
    return ERROR_TOO_SHORT_QUEUE_DESCRIPTION;
  }

  prop_head =  ( struct ofp_queue_prop_header * ) ( ( char * ) queue
               + offsetof( struct ofp_packet_queue, properties ) );
  properties_length = ( uint16_t ) ( ntohs( queue->len )
                                   - offsetof( struct ofp_packet_queue, properties ) );

  ret = validate_queue_properties( prop_head, properties_length );
  if ( ret < 0 ) {
    return ret;
  }

  return 0;
}


static int
validate_packet_queues( struct ofp_packet_queue *queue_head, const int n_queues ) {
  int i;
  int ret;
  struct ofp_packet_queue *queue;

  assert( queue_head != NULL );

  queue = queue_head;
  for ( i = 0; i < n_queues; i++ ) {
    ret = validate_packet_queue( queue );
    if ( ret < 0 ) {
      return ret;
    }
    queue = ( struct ofp_packet_queue * ) ( ( char * ) queue + ntohs( queue->len ) );
  }

  return 0;
}


int
validate_queue_get_config_reply( const buffer *message ) {
  int ret;
  int n_queues = 0;
  uint16_t queues_length;
  struct ofp_queue_get_config_reply *queue_get_config_reply;
  struct ofp_packet_queue *queue_head, *queue;

  assert( message != NULL );

  ret = validate_header( message, OFPT_QUEUE_GET_CONFIG_REPLY,
                         sizeof( struct ofp_queue_get_config_reply ) + sizeof( struct ofp_packet_queue ),
                         UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  queue_get_config_reply = ( struct ofp_queue_get_config_reply * ) message->data;

  ret = validate_port_no( ntohl( queue_get_config_reply->port ) );
  if ( ret < 0 ) {
    return ret;
  }

  queues_length = ( uint16_t ) ( ntohs( queue_get_config_reply->header.length )
                 - offsetof( struct ofp_queue_get_config_reply, queues ) );

  queue_head = ( struct ofp_packet_queue * ) ( ( char * ) message->data
               + offsetof( struct ofp_queue_get_config_reply, queues ) );

  queue = queue_head;
  while ( queues_length >= offsetof( struct ofp_packet_queue, properties ) ) {
    if ( queues_length < ntohs( queue->len ) ) {
      break;
    }
    queues_length = ( uint16_t ) ( queues_length - ntohs( queue->len ) );
    queue = ( struct ofp_packet_queue * ) ( ( char * ) queue + ntohs( queue->len ) );
    n_queues++;
  }

  if ( queues_length != 0 ) {
    return ERROR_INVALID_LENGTH;
  }

  if ( n_queues > 0 ) {
    ret = validate_packet_queues( queue_head, n_queues );
    if ( ret < 0 ) {
      return ret;
    }
  }

  return 0;
}


int
validate_role_request( const buffer *message ) {
  int ret;
  struct ofp_role_request *role_request;

  assert( message != NULL );

  ret = validate_header( message, OFPT_ROLE_REQUEST, sizeof( struct ofp_role_request ),
                         sizeof( struct ofp_role_request ) );
  if ( ret < 0 ) {
    return ret;
  }

  role_request = ( struct ofp_role_request * ) message->data;

  if ( ntohl( role_request->role ) > CONTROLLER_ROLE_MAX ) {
    return ERROR_INVALID_CONTROLLER_ROLE;
  }
  // role_request->generation_id

  return 0;
}


int
validate_role_reply( const buffer *message ) {
  int ret;
  struct ofp_role_request *role_reply;

  assert( message != NULL );

  ret = validate_header( message, OFPT_ROLE_REPLY, sizeof( struct ofp_role_request ),
                         sizeof( struct ofp_role_request ) );
  if ( ret < 0 ) {
    return ret;
  }

  role_reply = ( struct ofp_role_request * ) message->data;

  if ( ntohl( role_reply->role ) > CONTROLLER_ROLE_MAX ) {
    return ERROR_INVALID_CONTROLLER_ROLE;
  }
  // role_reply->generation_id

  return 0;
}


int
validate_get_async_request( const buffer *message ) {
  return validate_header( message, OFPT_GET_ASYNC_REQUEST, sizeof( struct ofp_header ),
                          sizeof( struct ofp_header ) );
}


int
validate_get_async_reply( const buffer *message ) {
  int ret;
  struct ofp_async_config *async_reply;

  assert( message != NULL );

  ret = validate_header( message, OFPT_GET_ASYNC_REPLY, sizeof( struct ofp_async_config ),
                         sizeof( struct ofp_async_config ) );
  if ( ret < 0 ) {
    return ret;
  }

  async_reply = ( struct ofp_async_config * ) message->data;

  if ( ( ntohl( async_reply->packet_in_mask[ 0 ] ) & ( uint32_t ) ~PACKET_IN_MASK ) != 0 ) {
    return ERROR_INVALID_PACKET_IN_MASK;
  }
  if ( ( ntohl( async_reply->packet_in_mask[ 1 ] ) & ( uint32_t ) ~PACKET_IN_MASK ) != 0 ) {
    return ERROR_INVALID_PACKET_IN_MASK;
  }
  if ( ( ntohl( async_reply->port_status_mask[ 0 ] ) & ( uint32_t ) ~PORT_STATUS_MASK ) != 0 ) {
    return ERROR_INVALID_PORT_STATUS_MASK;
  }
  if ( ( ntohl( async_reply->port_status_mask[ 1 ] ) & ( uint32_t ) ~PORT_STATUS_MASK ) != 0 ) {
    return ERROR_INVALID_PORT_STATUS_MASK;
  }
  if ( ( ntohl( async_reply->flow_removed_mask[ 0 ] ) & ( uint32_t ) ~FLOW_REMOVED_MASK ) != 0 ) {
    return ERROR_INVALID_FLOW_REMOVED_MASK;
  }
  if ( ( ntohl( async_reply->flow_removed_mask[ 1 ] ) & ( uint32_t ) ~FLOW_REMOVED_MASK ) != 0 ) {
    return ERROR_INVALID_FLOW_REMOVED_MASK;
  }

  return 0;
}


int
validate_set_async( const buffer *message ) {
  int ret;
  struct ofp_async_config *async_config;

  assert( message != NULL );

  ret = validate_header( message, OFPT_SET_ASYNC, sizeof( struct ofp_async_config ),
                         sizeof( struct ofp_async_config ) );
  if ( ret < 0 ) {
    return ret;
  }

  async_config = ( struct ofp_async_config * ) message->data;
  
  if ( ( ntohl( async_config->packet_in_mask[ 0 ] ) & ( uint32_t ) ~PACKET_IN_MASK ) != 0 ) {
    return ERROR_INVALID_PACKET_IN_MASK;
  }
  if ( ( ntohl( async_config->packet_in_mask[ 1 ] ) & ( uint32_t ) ~PACKET_IN_MASK ) != 0 ) {
    return ERROR_INVALID_PACKET_IN_MASK;
  }
  if ( ( ntohl( async_config->port_status_mask[ 0 ] ) & ( uint32_t ) ~PORT_STATUS_MASK ) != 0 ) {
    return ERROR_INVALID_PORT_STATUS_MASK;
  }
  if ( ( ntohl( async_config->port_status_mask[ 1 ] ) & ( uint32_t ) ~PORT_STATUS_MASK ) != 0 ) {
    return ERROR_INVALID_PORT_STATUS_MASK;
  }
  if ( ( ntohl( async_config->flow_removed_mask[ 0 ] ) & ( uint32_t ) ~FLOW_REMOVED_MASK ) != 0 ) {
    return ERROR_INVALID_FLOW_REMOVED_MASK;
  }
  if ( ( ntohl( async_config->flow_removed_mask[ 1 ] ) & ( uint32_t ) ~FLOW_REMOVED_MASK ) != 0 ) {
    return ERROR_INVALID_FLOW_REMOVED_MASK;
  }
  
  return 0;
}


int
validate_meter_mod( const buffer *message ) {
  int ret;
  uint16_t bands_length;
  struct ofp_meter_mod *meter_mod;
  struct ofp_meter_band_header *mtbnd;

  assert( message != NULL );

  ret = validate_header( message, OFPT_METER_MOD, sizeof( struct ofp_meter_mod ),
                         UINT16_MAX );
  if ( ret < 0 ) {
    return ret;
  }

  meter_mod = ( struct ofp_meter_mod * ) message->data;
  
  if ( ntohs( meter_mod->command ) > METER_COMMAND_MAX ) {
    return ERROR_INVALID_METER_COMMAND;
  }
  if ( ( ntohs( meter_mod->flags ) & ( uint16_t ) ~METER_FLAGS ) != 0 ) {
    return ERROR_INVALID_METER_FLAGS;
  }

  bands_length = ( uint16_t ) ( ntohs( meter_mod->header.length ) - offsetof( struct ofp_meter_mod, bands ) );
  mtbnd = meter_mod->bands;

  while ( bands_length > sizeof( struct ofp_meter_band_header ) ) {
    if ( bands_length < ntohs( mtbnd->len ) ) {
      return ERROR_TOO_SHORT_MESSAGE;
    }
    if ( ( ntohs( mtbnd->type ) > METER_BAND_MAX ) && ( ntohs( mtbnd->type ) != OFPMBT_EXPERIMENTER ) ) {
       return ERROR_INVALID_METER_BAND_TYPE;
    }
    // meter_mod->meter_mod->bands->rate
    // meter_mod->meter_mod->bands->burst_size

    bands_length = ( uint16_t ) ( bands_length - ntohs( mtbnd->len ) );
    mtbnd = ( struct ofp_meter_band_header * ) ( ( char * ) mtbnd + ntohs( mtbnd->len ) );
  }

  if ( bands_length > 0 ) {
    return ERROR_TOO_LONG_MESSAGE;
  }

  return 0;
}


static int
validate_action( struct ofp_action_header *action ) {
  if ( ntohs( action->len ) < sizeof( struct ofp_action_header ) ) {
    return ERROR_TOO_SHORT_ACTION;
  }

  switch ( ntohs( action->type ) ) {
  case OFPAT_OUTPUT:
    return validate_action_output( ( struct ofp_action_output * ) action );
  case OFPAT_COPY_TTL_OUT:
    return validate_action_copy_ttl_out( ( struct ofp_action_header * ) action );
  case OFPAT_COPY_TTL_IN:
    return validate_action_copy_ttl_in( ( struct ofp_action_header * ) action );
  case OFPAT_SET_MPLS_TTL:
    return validate_action_set_mpls_ttl( ( struct ofp_action_mpls_ttl * ) action );
  case OFPAT_DEC_MPLS_TTL:
    return validate_action_dec_mpls_ttl( ( struct ofp_action_header * ) action );
  case OFPAT_PUSH_VLAN:
    return validate_action_push_vlan( ( struct ofp_action_push * ) action );
  case OFPAT_POP_VLAN:
    return validate_action_pop_vlan( ( struct ofp_action_header * ) action );
  case OFPAT_PUSH_MPLS:
    return validate_action_push_mpls( ( struct ofp_action_push * ) action );
  case OFPAT_POP_MPLS:
    return validate_action_pop_mpls( ( struct ofp_action_pop_mpls * ) action );
  case OFPAT_SET_QUEUE:
    return validate_action_set_queue( ( struct ofp_action_set_queue * ) action );
  case OFPAT_GROUP:
    return validate_action_group( ( struct ofp_action_group * ) action );
  case OFPAT_SET_NW_TTL:
    return validate_action_set_nw_ttl( ( struct ofp_action_nw_ttl * ) action );
  case OFPAT_DEC_NW_TTL:
    return validate_action_dec_nw_ttl( ( struct ofp_action_header * ) action );
  case OFPAT_SET_FIELD:
    return validate_action_set_field( ( struct ofp_action_set_field * ) action );
  case OFPAT_PUSH_PBB:
    return validate_action_push_pbb( ( struct ofp_action_push * ) action );
  case OFPAT_POP_PBB:
    return validate_action_pop_pbb( ( struct ofp_action_header * ) action );
  case OFPAT_EXPERIMENTER:
    return validate_action_experimenter( ( struct ofp_action_experimenter_header * ) action );
  default:
    break;
  }

  return ERROR_UNDEFINED_ACTION_TYPE;
}


int
validate_actions( struct ofp_action_header *actions_head, const uint16_t length ) {
  int ret;
  uint16_t offset = 0;
  struct ofp_action_header *action;

  action = actions_head;
  while ( offset < length ) {
    ret = validate_action( action );
    if ( ret < 0 ) {
      return ret;
    }

    offset = ( uint16_t ) ( offset + ntohs( action->len ) );
    action = ( struct ofp_action_header * ) ( ( char * ) actions_head + offset );
  }

  return 0;
}


int
validate_action_output( const struct ofp_action_output *action ) {
  int ret;
  struct ofp_action_output output;

  ntoh_action_output( &output, action );
  if ( output.type != OFPAT_OUTPUT ) {
    return ERROR_INVALID_ACTION_TYPE;
  }
  if ( output.len < sizeof( struct ofp_action_output ) ) {
    return ERROR_TOO_SHORT_ACTION_OUTPUT;
  }
  else if ( output.len > sizeof( struct ofp_action_output ) ) {
    return ERROR_TOO_LONG_ACTION_OUTPUT;
  }

  ret = validate_port_no( output.port );
  if ( ret < 0 ) {
    return ret;
  }

  // output.max_len

  return 0;
}


int
validate_action_copy_ttl_out( const struct ofp_action_header *action ) {
  struct ofp_action_header copy_ttl_out;

  ntoh_action_header( &copy_ttl_out, action );

  if ( copy_ttl_out.type != OFPAT_COPY_TTL_OUT ) {
    return ERROR_INVALID_ACTION_TYPE;
  }
  if ( copy_ttl_out.len < sizeof( struct ofp_action_header ) ) {
    return ERROR_TOO_SHORT_ACTION_COPY_TTL_OUT;
  }
  else if ( copy_ttl_out.len > sizeof( struct ofp_action_header ) ) {
    return ERROR_TOO_LONG_ACTION_COPY_TTL_OUT;
  }

  return 0;
}


int
validate_action_copy_ttl_in( const struct ofp_action_header *action ) {
  struct ofp_action_header copy_ttl_in;

  ntoh_action_header( &copy_ttl_in, action );

  if ( copy_ttl_in.type != OFPAT_COPY_TTL_IN ) {
    return ERROR_INVALID_ACTION_TYPE;
  }
  if ( copy_ttl_in.len < sizeof( struct ofp_action_header ) ) {
    return ERROR_TOO_SHORT_ACTION_COPY_TTL_IN;
  }
  else if ( copy_ttl_in.len > sizeof( struct ofp_action_header ) ) {
    return ERROR_TOO_LONG_ACTION_COPY_TTL_IN;
  }

  return 0;
}


int
validate_action_set_mpls_ttl( const struct ofp_action_mpls_ttl *action ) {
  struct ofp_action_mpls_ttl mblp_ttl;

  ntoh_action_mpls_ttl( &mblp_ttl, action );
  if ( mblp_ttl.type != OFPAT_SET_MPLS_TTL ) {
    return ERROR_INVALID_ACTION_TYPE;
  }
  if ( mblp_ttl.len < sizeof( struct ofp_action_mpls_ttl ) ) {
    return ERROR_TOO_SHORT_ACTION_SET_MPLS_TTL;
  }
  else if ( mblp_ttl.len > sizeof( struct ofp_action_mpls_ttl ) ) {
    return ERROR_TOO_LONG_ACTION_SET_MPLS_TTL;
  }

  // mblp_ttl.mpls_ttl

  return 0;
}


int
validate_action_dec_mpls_ttl( const struct ofp_action_header *action ) {
  struct ofp_action_header dec_mpls_ttl;

  ntoh_action_header( &dec_mpls_ttl, action );

  if ( dec_mpls_ttl.type != OFPAT_DEC_MPLS_TTL ) {
    return ERROR_INVALID_ACTION_TYPE;
  }
  if ( dec_mpls_ttl.len < sizeof( struct ofp_action_header ) ) {
    return ERROR_TOO_SHORT_ACTION_DEC_MPLS_TTL;
  }
  else if ( dec_mpls_ttl.len > sizeof( struct ofp_action_header ) ) {
    return ERROR_TOO_LONG_ACTION_DEC_MPLS_TTL;
  }

  return 0;
}


int
validate_action_push_vlan( const struct ofp_action_push *action ) {
  struct ofp_action_push push_vlan;

  ntoh_action_push( &push_vlan, action );
  if ( push_vlan.type != OFPAT_PUSH_VLAN ) {
    return ERROR_INVALID_ACTION_TYPE;
  }
  if ( push_vlan.len < sizeof( struct ofp_action_push ) ) {
    return ERROR_TOO_SHORT_ACTION_PUSH_VLAN;
  }
  else if ( push_vlan.len > sizeof( struct ofp_action_push ) ) {
    return ERROR_TOO_LONG_ACTION_PUSH_VLAN;
  }

  // push_vlan.ethertype

  return 0;
}


int
validate_action_pop_vlan( const struct ofp_action_header *action ) {
  struct ofp_action_header pop_vlan;

  ntoh_action_header( &pop_vlan, action );

  if ( pop_vlan.type != OFPAT_POP_VLAN ) {
    return ERROR_INVALID_ACTION_TYPE;
  }
  if ( pop_vlan.len < sizeof( struct ofp_action_header ) ) {
    return ERROR_TOO_SHORT_ACTION_POP_VLAN;
  }
  else if ( pop_vlan.len > sizeof( struct ofp_action_header ) ) {
    return ERROR_TOO_LONG_ACTION_POP_VLAN;
  }

  return 0;
}


int
validate_action_push_mpls( const struct ofp_action_push *action ) {
  struct ofp_action_push push_mpls;

  ntoh_action_push( &push_mpls, action );
  if ( push_mpls.type != OFPAT_PUSH_MPLS ) {
    return ERROR_INVALID_ACTION_TYPE;
  }
  if ( push_mpls.len < sizeof( struct ofp_action_push ) ) {
    return ERROR_TOO_SHORT_ACTION_PUSH_MPLS;
  }
  else if ( push_mpls.len > sizeof( struct ofp_action_push ) ) {
    return ERROR_TOO_LONG_ACTION_PUSH_MPLS;
  }

  // push_mpls.ethertype

  return 0;
}


int
validate_action_pop_mpls( const struct ofp_action_pop_mpls *action ) {
  struct ofp_action_pop_mpls pop_mpls;

  ntoh_action_pop_mpls( &pop_mpls, action );
  if ( pop_mpls.type != OFPAT_POP_MPLS ) {
    return ERROR_INVALID_ACTION_TYPE;
  }
  if ( pop_mpls.len < sizeof( struct ofp_action_pop_mpls ) ) {
    return ERROR_TOO_SHORT_ACTION_POP_MPLS;
  }
  else if ( pop_mpls.len > sizeof( struct ofp_action_pop_mpls ) ) {
    return ERROR_TOO_LONG_ACTION_POP_MPLS;
  }

  // pop_mpls.ethertype

  return 0;
}


int
validate_action_set_queue( const struct ofp_action_set_queue *action ) {
  struct ofp_action_set_queue set_queue;

  ntoh_action_set_queue( &set_queue, action );

  if ( set_queue.type != OFPAT_SET_QUEUE ) {
    return ERROR_INVALID_ACTION_TYPE;
  }
  if ( set_queue.len < sizeof( struct ofp_action_set_queue ) ) {
    return ERROR_TOO_SHORT_ACTION_SET_QUEUE;
  }
  else if ( set_queue.len > sizeof( struct ofp_action_set_queue ) ) {
    return ERROR_TOO_LONG_ACTION_SET_QUEUE;
  }

  // set_queue.queue_id

  return 0;
}


int
validate_action_group( const struct ofp_action_group *action ) {
  struct ofp_action_group group;

  ntoh_action_group( &group, action );

  if ( group.type != OFPAT_GROUP ) {
    return ERROR_INVALID_ACTION_TYPE;
  }
  if ( group.len < sizeof( struct ofp_action_group ) ) {
    return ERROR_TOO_SHORT_ACTION_GROUP;
  }
  else if ( group.len > sizeof( struct ofp_action_group ) ) {
    return ERROR_TOO_LONG_ACTION_GROUP;
  }

  // group.group_id

  return 0;
}


int
validate_action_set_nw_ttl( const struct ofp_action_nw_ttl *action ) {
  struct ofp_action_nw_ttl nw_ttl;

  ntoh_action_nw_ttl( &nw_ttl, action );

  if ( nw_ttl.type != OFPAT_SET_NW_TTL ) {
    return ERROR_INVALID_ACTION_TYPE;
  }
  if ( nw_ttl.len < sizeof( struct ofp_action_nw_ttl ) ) {
    return ERROR_TOO_SHORT_ACTION_SET_NW_TTL;
  }
  else if ( nw_ttl.len > sizeof( struct ofp_action_nw_ttl ) ) {
    return ERROR_TOO_LONG_ACTION_SET_NW_TTL;
  }

  // nw_ttl.nw_ttl

  return 0;
}


int
validate_action_dec_nw_ttl( const struct ofp_action_header *action ) {
  struct ofp_action_header dec_nw_ttl;

  ntoh_action_header( &dec_nw_ttl, action );

  if ( dec_nw_ttl.type != OFPAT_DEC_NW_TTL ) {
    return ERROR_INVALID_ACTION_TYPE;
  }
  if ( dec_nw_ttl.len < sizeof( struct ofp_action_header ) ) {
    return ERROR_TOO_SHORT_ACTION_DEC_NW_TTL;
  }
  else if ( dec_nw_ttl.len > sizeof( struct ofp_action_header ) ) {
    return ERROR_TOO_LONG_ACTION_DEC_NW_TTL;
  }

  return 0;
}


int
validate_action_set_field( const struct ofp_action_set_field *action ) {
  int ret = 0;
  struct ofp_action_set_field *set_field = NULL;
  oxm_match_header *oxm_tlv;
  uint16_t length = ntohs( action->len );

  if ( length < sizeof( struct ofp_action_set_field ) ) {
    return ERROR_TOO_SHORT_ACTION_SET_FIELD;
  }
  else if ( length % 8 != 0 ) {
    return ERROR_TOO_LONG_ACTION_SET_FIELD;
  }

  set_field = ( struct ofp_action_set_field * ) xcalloc( 1, length );
  ntoh_action_set_field( set_field, action );

  if ( set_field->type != OFPAT_SET_FIELD ) {
    ret = ERROR_INVALID_ACTION_TYPE;
    goto END;
  }

  length = ( uint16_t ) ( length - offsetof( struct ofp_action_set_field, field ) );
  oxm_tlv = ( oxm_match_header * ) set_field->field;
  if ( length < ( sizeof( oxm_match_header ) + OXM_LENGTH( *oxm_tlv ) ) ) {
    ret = ERROR_TOO_SHORT_ACTION_SET_FIELD;
    goto END;
  }

END:
  if ( set_field != NULL ) {
    xfree( set_field );
  }
  return ret;
}


int
validate_action_push_pbb( const struct ofp_action_push *action ) {
  struct ofp_action_push push_pbb;

  ntoh_action_push( &push_pbb, action );

  if ( push_pbb.type != OFPAT_PUSH_PBB ) {
    return ERROR_INVALID_ACTION_TYPE;
  }
  if ( push_pbb.len < sizeof( struct ofp_action_push ) ) {
    return ERROR_TOO_SHORT_ACTION_PUSH_PBB;
  }
  else if ( push_pbb.len > sizeof( struct ofp_action_push ) ) {
    return ERROR_TOO_LONG_ACTION_PUSH_PBB;
  }

  // push_pbb.ethertype

  return 0;
}


int
validate_action_pop_pbb( const struct ofp_action_header *action ) {
  struct ofp_action_header pop_pbb;

  ntoh_action_header( &pop_pbb, action );

  if ( pop_pbb.type != OFPAT_POP_PBB ) {
    return ERROR_INVALID_ACTION_TYPE;
  }
  if ( pop_pbb.len < sizeof( struct ofp_action_header ) ) {
    return ERROR_TOO_SHORT_ACTION_POP_PBB;
  }
  else if ( pop_pbb.len > sizeof( struct ofp_action_header ) ) {
    return ERROR_TOO_LONG_ACTION_POP_PBB;
  }

  return 0;
}


int
validate_action_experimenter( const struct ofp_action_experimenter_header *action ) {
  int ret = 0;
  struct ofp_action_experimenter_header *experimenter = xcalloc( 1, ntohs( action->len ) );

  ntoh_action_experimenter( experimenter, action );

  if ( experimenter->type != OFPAT_EXPERIMENTER ) {
    ret = ERROR_INVALID_ACTION_TYPE;
    goto END;
  }
  if ( experimenter->len < sizeof( struct ofp_action_experimenter_header ) ) {
    ret = ERROR_TOO_SHORT_ACTION_EXPERIMENTER;
    goto END;
  }

  // experimenter.experimenter

END:
  xfree( experimenter );
  return ret;
}


static int
validate_instruction( struct ofp_instruction *instruction ) {
  if ( ntohs( instruction->len ) < sizeof( struct ofp_instruction ) ) {
    return ERROR_TOO_SHORT_INSTRUCTION;
  }

  switch ( ntohs( instruction->type ) ) {
  case OFPIT_GOTO_TABLE:
    return validate_instructions_goto_table( ( struct ofp_instruction_goto_table * ) instruction );
  case OFPIT_WRITE_METADATA:
    return validate_instructions_write_metadata( ( struct ofp_instruction_write_metadata * ) instruction );
  case OFPIT_WRITE_ACTIONS:
    return validate_instructions_write_actions( ( struct ofp_instruction_actions * ) instruction );
  case OFPIT_APPLY_ACTIONS:
    return validate_instructions_apply_actions( ( struct ofp_instruction_actions * ) instruction );
  case OFPIT_CLEAR_ACTIONS:
    return validate_instructions_clear_actions( ( struct ofp_instruction_actions * ) instruction );
  case OFPIT_METER:
    return validate_instructions_meter( ( struct ofp_instruction_meter * ) instruction );
  case OFPIT_EXPERIMENTER:
    return validate_instructions_experimenter( ( struct ofp_instruction_experimenter * ) instruction );
  default:
    break;
  }

  return ERROR_UNDEFINED_INSTRUCTION_TYPE;
}


int
validate_instructions( struct ofp_instruction *instructions_head, const uint16_t length ) {
  int ret;
  uint16_t offset = 0;
  struct ofp_instruction *instruction;

  instruction = instructions_head;
  while ( offset < length ) {
    ret = validate_instruction( instruction );
    if ( ret < 0 ) {
      return ret;
    }

    offset = ( uint16_t ) ( offset + ntohs( instruction->len ) );
    instruction = ( struct ofp_instruction * ) ( ( char * ) instructions_head + offset );
  }

  return 0;
}


int
validate_instructions_goto_table( const struct ofp_instruction_goto_table *instruction ) {
  struct ofp_instruction_goto_table goto_table;

  ntoh_instruction_goto_table( &goto_table, instruction );

  if ( goto_table.type != OFPIT_GOTO_TABLE ) {
    return ERROR_INVALID_INSTRUCTION_TYPE;
  }
  if ( goto_table.len < sizeof( struct ofp_instruction_goto_table ) ) {
    return ERROR_TOO_SHORT_INSTRUCTION_GOTO_TABLE;
  }
  else if ( goto_table.len > sizeof( struct ofp_instruction_goto_table ) ) {
    return ERROR_TOO_LONG_INSTRUCTION_GOTO_TABLE;
  }

  return 0;
}


int
validate_instructions_write_metadata( const struct ofp_instruction_write_metadata *instruction ) {
  struct ofp_instruction_write_metadata write_metadata;

  ntoh_instruction_write_metadata( &write_metadata, instruction );

  if ( write_metadata.type != OFPIT_WRITE_METADATA ) {
    return ERROR_INVALID_INSTRUCTION_TYPE;
  }
  if ( write_metadata.len < sizeof( struct ofp_instruction_write_metadata ) ) {
    return ERROR_TOO_SHORT_INSTRUCTION_WRITE_METADATA;
  }
  else if ( write_metadata.len > sizeof( struct ofp_instruction_write_metadata ) ) {
    return ERROR_TOO_LONG_INSTRUCTION_WRITE_METADATA;
  }

  return 0;
}


int
validate_instructions_write_actions( struct ofp_instruction_actions *instruction ) {
  int ret = 0;
  uint16_t length = ntohs( instruction->len );
  uint16_t action_length = 0;

  if ( length < sizeof( struct ofp_instruction_actions ) ) {
    return ERROR_TOO_SHORT_INSTRUCTION_WRITE_ACTIONS;
  }

  if ( ntohs( instruction->type ) != OFPIT_WRITE_ACTIONS ) {
    return ERROR_INVALID_INSTRUCTION_TYPE;
  }

  action_length = ( uint16_t ) ( length - offsetof( struct ofp_instruction_actions, actions ) );
  if ( action_length > 0 ) {
    struct ofp_action_header *action;
    
    action = instruction->actions;
    while ( action_length >= sizeof( struct ofp_action_header ) ) {
      if ( action_length < ntohs( action->len ) ) {
        break;
      }

      ret = validate_action( action );
      if ( ret < 0 ) {
        return ret;
      }

      action_length = ( uint16_t ) ( action_length - ntohs( action->len ) );
      action = ( struct ofp_action_header * ) ( ( char * ) action + ntohs( action->len ) );
    }
  }

  if ( action_length > 0 ) {
    return ERROR_TOO_LONG_INSTRUCTION_WRITE_ACTIONS;
  }

  return 0;
}


int
validate_instructions_apply_actions( struct ofp_instruction_actions *instruction ) {
  int ret = 0;
  uint16_t length = ntohs( instruction->len );
  uint16_t action_length = 0;

  if ( length < sizeof( struct ofp_instruction_actions ) ) {
    return ERROR_TOO_SHORT_INSTRUCTION_APPLY_ACTIONS;
  }

  if ( ntohs( instruction->type ) != OFPIT_APPLY_ACTIONS ) {
    return ERROR_INVALID_INSTRUCTION_TYPE;
  }

  action_length = ( uint16_t ) ( length - offsetof( struct ofp_instruction_actions, actions ) );
  if ( action_length > 0 ) {
    struct ofp_action_header *action;
    
    action = instruction->actions;
    while ( action_length >= sizeof( struct ofp_action_header ) ) {
      if ( action_length < ntohs( action->len ) ) {
        break;
      }

      ret = validate_action( action );
      if ( ret < 0 ) {
        return ret;
      }

      action_length = ( uint16_t ) ( action_length - ntohs( action->len ) );
      action = ( struct ofp_action_header * ) ( ( char * ) action + ntohs( action->len ) );
    }
  }

  if ( action_length > 0 ) {
    return ERROR_TOO_LONG_INSTRUCTION_APPLY_ACTIONS;
  }

  return 0;
}


int
validate_instructions_clear_actions( const struct ofp_instruction_actions *instruction ) {
  struct ofp_instruction_actions clear_actions;

  ntoh_instruction_actions( &clear_actions, instruction );

  if ( clear_actions.type != OFPIT_CLEAR_ACTIONS ) {
    return ERROR_INVALID_INSTRUCTION_TYPE;
  }
  if ( clear_actions.len < sizeof( struct ofp_instruction_actions ) ) {
    return ERROR_TOO_SHORT_INSTRUCTION_CLEAR_ACTIONS;
  }
  else if ( clear_actions.len > sizeof( struct ofp_instruction_actions ) ) {
    return ERROR_TOO_LONG_INSTRUCTION_CLEAR_ACTIONS;
  }

  return 0;
}


int
validate_instructions_meter( const struct ofp_instruction_meter *instruction ) {
  struct ofp_instruction_meter meter;

  ntoh_instruction_meter( &meter, instruction );

  if ( meter.type != OFPIT_METER ) {
    return ERROR_INVALID_INSTRUCTION_TYPE;
  }
  if ( meter.len < sizeof( struct ofp_instruction_meter ) ) {
    return ERROR_TOO_SHORT_INSTRUCTION_METER;
  }
  else if ( meter.len > sizeof( struct ofp_instruction_meter ) ) {
    return ERROR_TOO_LONG_INSTRUCTION_METER;
  }

  return 0;
}


int
validate_instructions_experimenter( const struct ofp_instruction_experimenter *instruction ) {
  int ret = 0;
  struct ofp_instruction_experimenter *experimenter = xcalloc( 1, ntohs( instruction->len ) );

  ntoh_instruction_experimenter( experimenter, instruction );

  if ( experimenter->type != OFPIT_EXPERIMENTER ) {
    ret = ERROR_INVALID_INSTRUCTION_TYPE;
    goto END;
  }
  if ( experimenter->len < sizeof( struct ofp_instruction_experimenter ) ) {
    ret = ERROR_TOO_SHORT_INSTRUCTION_EXPERIMENTER;
    goto END;
  }

END:
  xfree( experimenter );
  return ret;
}


int
validate_openflow_message( const buffer *message ) {
  int ret;

  assert( message != NULL );
  assert( message->data != NULL );

  struct ofp_header *header = ( struct ofp_header * ) message->data;

  debug( "Validating an OpenFlow message ( version = %#x, type = %#x, length = %u, xid = %#x ).",
         header->version, header->type, ntohs( header->length ), ntohl( header->xid ) );

  switch ( header->type ) {
  case OFPT_HELLO:
    ret = validate_hello( message );
    break;
  case OFPT_ERROR:
    ret = validate_error( message );
    break;
  case OFPT_ECHO_REQUEST:
    ret = validate_echo_request( message );
    break;
  case OFPT_ECHO_REPLY:
    ret = validate_echo_reply( message );
    break;
  case OFPT_EXPERIMENTER:
    ret = validate_experimenter( message );
    break;
  case OFPT_FEATURES_REQUEST:
    ret = validate_features_request( message );
    break;
  case OFPT_FEATURES_REPLY:
    ret = validate_features_reply( message );
    break;
  case OFPT_GET_CONFIG_REQUEST:
    ret = validate_get_config_request( message );
    break;
  case OFPT_GET_CONFIG_REPLY:
    ret = validate_get_config_reply( message );
    break;
  case OFPT_SET_CONFIG:
    ret = validate_set_config( message );
    break;
  case OFPT_PACKET_IN:
    ret = validate_packet_in( message );
    break;
  case OFPT_FLOW_REMOVED:
    ret = validate_flow_removed( message );
    break;
  case OFPT_PORT_STATUS:
    ret = validate_port_status( message );
    break;
  case OFPT_PACKET_OUT:
    ret = validate_packet_out( message );
    break;
  case OFPT_FLOW_MOD:
    ret = validate_flow_mod( message );
    break;
  case OFPT_GROUP_MOD:
    ret = validate_group_mod( message );
    break;
  case OFPT_PORT_MOD:
    ret = validate_port_mod( message );
    break;
  case OFPT_TABLE_MOD:
    ret = validate_table_mod( message );
    break;
  case OFPT_MULTIPART_REQUEST:
    ret = validate_multipart_request( message );
    break;
  case OFPT_MULTIPART_REPLY:
    ret = validate_multipart_reply( message );
    break;
  case OFPT_BARRIER_REQUEST:
    ret = validate_barrier_request( message );
    break;
  case OFPT_BARRIER_REPLY:
    ret = validate_barrier_reply( message );
    break;
  case OFPT_QUEUE_GET_CONFIG_REQUEST:
    ret = validate_queue_get_config_request( message );
    break;
  case OFPT_QUEUE_GET_CONFIG_REPLY:
    ret = validate_queue_get_config_reply( message );
    break;
  case OFPT_ROLE_REQUEST:
    ret = validate_role_request( message );
    break;
  case OFPT_ROLE_REPLY:
    ret = validate_role_reply( message );
    break;
  case OFPT_GET_ASYNC_REQUEST:
    ret = validate_get_async_request( message );
    break;
  case OFPT_GET_ASYNC_REPLY:
    ret = validate_get_async_reply( message );
    break;
  case OFPT_SET_ASYNC:
    ret = validate_set_async( message );
    break;
  case OFPT_METER_MOD:
    ret = validate_meter_mod( message );
    break;
  default:
    ret = ERROR_UNDEFINED_TYPE;
    break;
  }

  debug( "Validation completed ( ret = %d ).", ret );

  return ret;
}


bool
valid_openflow_message( const buffer *message ) {
  if ( validate_openflow_message( message ) < 0 ) {
    return false;
  }

  return true;
}


static struct error_map {
  uint8_t type; // One of the OFPT_ constants.
  struct map {
    int error_no; // Internal error number.
    uint16_t error_type; // OpenFlow error type.
    uint16_t error_code; // OpenFlow error code.
  } maps[ 128 ];
} error_maps[] = {
  {
    OFPT_HELLO,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_HELLO_FAILED, OFPHFC_INCOMPATIBLE },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_TOO_SHORT_HELLO_ELEMENT, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_HELLO_ELEMENT_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_HELLO_ELEMENT_TYPE, OFPET_HELLO_FAILED, OFPHFC_INCOMPATIBLE }, // FIXME
      { 0, 0, 0 },
    }
  },
  {
    OFPT_ERROR,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { 0, 0, 0 },
    }
  },
  {
    OFPT_ECHO_REQUEST,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { 0, 0, 0 },
    }
  },
  {
    OFPT_ECHO_REPLY,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { 0, 0, 0 },
    }
  },
  {
    OFPT_EXPERIMENTER,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { 0, 0, 0 },
    }
  },
  {
    OFPT_FEATURES_REQUEST,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { 0, 0, 0 },
    }
  },
  {
    OFPT_FEATURES_REPLY,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_NO_TABLE_AVAILABLE, OFPET_BAD_REQUEST, OFPBRC_BAD_TABLE_ID },
      { 0, 0, 0 },
    }
  },
  {
    OFPT_GET_CONFIG_REQUEST,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { 0, 0, 0 },
    }
  },
  {
    OFPT_GET_CONFIG_REPLY,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_SWITCH_CONFIG, OFPET_BAD_REQUEST, OFPBRC_EPERM }, // FIXME
      { 0, 0, 0 },
    }
  },
  {
    OFPT_SET_CONFIG,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_SWITCH_CONFIG, OFPET_BAD_REQUEST, OFPBRC_EPERM }, // FIXME
      { 0, 0, 0 },
    }
  },
  {
    OFPT_PACKET_IN, // FIXME: Should we return an error for packet_in ?
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_PACKET_IN_REASON, OFPET_BAD_REQUEST, OFPBRC_EPERM }, // FIXME
      { ERROR_INVALID_VLAN_VID, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_VLAN_PCP, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_IP_DSCP, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_IP_ECN, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_IPV6_FLABEL, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_MPLS_LABEL, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_MPLS_TC, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_MPLS_BOS, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_PBB_ISID, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_IPV6_EXTHDR, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_MATCH_TYPE, OFPET_BAD_MATCH, OFPBMC_BAD_TYPE },
      { ERROR_BAD_MATCH_PREREQ, OFPET_BAD_MATCH, OFPBMC_BAD_PREREQ },
      { 0, 0, 0 },
    }
  },
  {
    OFPT_FLOW_REMOVED,  // FIXME: Should we return an error for flow_removed ?
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_FLOW_PRIORITY, OFPET_BAD_REQUEST, OFPBRC_EPERM }, // FIXME
      { ERROR_INVALID_FLOW_REMOVED_REASON, OFPET_BAD_REQUEST, OFPBRC_EPERM },
      { ERROR_INVALID_VLAN_VID, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_VLAN_PCP, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_IP_DSCP, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_IP_ECN, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_IPV6_FLABEL, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_MPLS_LABEL, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_MPLS_TC, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_MPLS_BOS, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_PBB_ISID, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_IPV6_EXTHDR, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_MATCH_TYPE, OFPET_BAD_MATCH, OFPBMC_BAD_TYPE },
      { ERROR_BAD_MATCH_PREREQ, OFPET_BAD_MATCH, OFPBMC_BAD_PREREQ },
      { 0, 0, 0 },
    }
  },
  {
    OFPT_PORT_STATUS,  // FIXME: Should we return an error for port_status ?
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_PORT_STATUS_REASON, OFPET_BAD_REQUEST, OFPBRC_EPERM }, // FIXME
      { ERROR_INVALID_PORT_NO, OFPET_BAD_REQUEST, OFPBRC_EPERM }, // FIXME
      { ERROR_INVALID_PORT_CONFIG, OFPET_BAD_REQUEST, OFPBRC_EPERM }, // FIXME
      { ERROR_INVALID_PORT_STATE, OFPET_BAD_REQUEST, OFPBRC_EPERM }, // FIXME
      { ERROR_INVALID_PORT_FEATURES, OFPET_BAD_REQUEST, OFPBRC_EPERM }, // FIXME
      { 0, 0, 0 },
    }
  },
  {
    OFPT_PACKET_OUT,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_ACTION_TYPE, OFPET_BAD_ACTION, OFPBAC_BAD_TYPE },
      { ERROR_TOO_SHORT_ACTION_OUTPUT, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_OUTPUT, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_INVALID_PORT_NO, OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT },
      { ERROR_TOO_SHORT_ACTION_COPY_TTL_OUT, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_COPY_TTL_OUT, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_COPY_TTL_IN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_COPY_TTL_IN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_SET_MPLS_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_SET_MPLS_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_DEC_MPLS_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_DEC_MPLS_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_PUSH_VLAN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_PUSH_VLAN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_POP_VLAN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_POP_VLAN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_PUSH_MPLS, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_PUSH_MPLS, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_POP_MPLS, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_POP_MPLS, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_SET_QUEUE, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_SET_QUEUE, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_GROUP, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_GROUP, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_SET_NW_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_SET_NW_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_DEC_NW_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_DEC_NW_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_SET_FIELD, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_SET_FIELD, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_PUSH_PBB, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_PUSH_PBB, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_POP_PBB, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_POP_PBB, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_EXPERIMENTER, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_UNDEFINED_ACTION_TYPE, OFPET_BAD_ACTION, OFPBAC_BAD_TYPE },
      { 0, 0, 0 },
    }
  },
  {
    OFPT_FLOW_MOD,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_UNDEFINED_FLOW_MOD_COMMAND, OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_COMMAND },
      { ERROR_INVALID_FLOW_PRIORITY, OFPET_FLOW_MOD_FAILED, OFPFMFC_EPERM }, // FIXME
      { ERROR_INVALID_FLOW_MOD_FLAGS, OFPET_FLOW_MOD_FAILED, OFPFMFC_EPERM }, // FIXME
      { ERROR_INVALID_VLAN_VID, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_VLAN_PCP, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_IP_DSCP, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_IP_ECN, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_IPV6_FLABEL, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_MPLS_LABEL, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_MPLS_TC, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_MPLS_BOS, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_PBB_ISID, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_IPV6_EXTHDR, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_MATCH_TYPE, OFPET_BAD_MATCH, OFPBMC_BAD_TYPE },
      { ERROR_BAD_MATCH_PREREQ, OFPET_BAD_MATCH, OFPBMC_BAD_PREREQ },
      { ERROR_TOO_SHORT_INSTRUCTION, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_UNDEFINED_INSTRUCTION_TYPE, OFPET_BAD_INSTRUCTION, OFPBIC_UNKNOWN_INST },
      { ERROR_INVALID_INSTRUCTION_TYPE, OFPET_BAD_INSTRUCTION, OFPBIC_UNKNOWN_INST },
      { ERROR_TOO_SHORT_INSTRUCTION_GOTO_TABLE, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_LONG_INSTRUCTION_GOTO_TABLE, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_SHORT_INSTRUCTION_WRITE_METADATA, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_LONG_INSTRUCTION_WRITE_METADATA, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_SHORT_INSTRUCTION_WRITE_ACTIONS, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_LONG_INSTRUCTION_WRITE_ACTIONS, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_SHORT_INSTRUCTION_APPLY_ACTIONS, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_LONG_INSTRUCTION_APPLY_ACTIONS, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_SHORT_INSTRUCTION_CLEAR_ACTIONS, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_LONG_INSTRUCTION_CLEAR_ACTIONS, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_SHORT_INSTRUCTION_METER, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_LONG_INSTRUCTION_METER, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_SHORT_INSTRUCTION_EXPERIMENTER, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_LONG_INSTRUCTION_EXPERIMENTER, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_INVALID_ACTION_TYPE, OFPET_BAD_ACTION, OFPBAC_BAD_TYPE },
      { ERROR_TOO_SHORT_ACTION_OUTPUT, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_OUTPUT, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_INVALID_PORT_NO, OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT },
      { ERROR_TOO_SHORT_ACTION_COPY_TTL_OUT, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_COPY_TTL_OUT, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_COPY_TTL_IN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_COPY_TTL_IN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_SET_MPLS_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_SET_MPLS_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_DEC_MPLS_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_DEC_MPLS_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_PUSH_VLAN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_PUSH_VLAN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_POP_VLAN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_POP_VLAN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_PUSH_MPLS, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_PUSH_MPLS, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_POP_MPLS, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_POP_MPLS, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_SET_QUEUE, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_SET_QUEUE, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_GROUP, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_GROUP, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_SET_NW_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_SET_NW_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_DEC_NW_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_DEC_NW_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_SET_FIELD, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_SET_FIELD, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_PUSH_PBB, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_PUSH_PBB, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_POP_PBB, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_POP_PBB, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_EXPERIMENTER, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_UNDEFINED_ACTION_TYPE, OFPET_BAD_ACTION, OFPBAC_BAD_TYPE },
      { 0, 0, 0 },
    }
  },
  {
    OFPT_GROUP_MOD,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_GROUP_COMMAND, OFPET_GROUP_MOD_FAILED, OFPGMFC_BAD_COMMAND },
      { ERROR_INVALID_GROUP_TYPE, OFPET_GROUP_MOD_FAILED, OFPGMFC_BAD_TYPE },
      { ERROR_INVALID_ACTION_TYPE, OFPET_BAD_ACTION, OFPBAC_BAD_TYPE },
      { ERROR_TOO_SHORT_ACTION_OUTPUT, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_OUTPUT, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_INVALID_PORT_NO, OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT },
      { ERROR_TOO_SHORT_ACTION_COPY_TTL_OUT, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_COPY_TTL_OUT, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_COPY_TTL_IN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_COPY_TTL_IN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_SET_MPLS_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_SET_MPLS_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_DEC_MPLS_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_DEC_MPLS_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_PUSH_VLAN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_PUSH_VLAN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_POP_VLAN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_POP_VLAN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_PUSH_MPLS, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_PUSH_MPLS, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_POP_MPLS, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_POP_MPLS, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_SET_QUEUE, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_SET_QUEUE, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_GROUP, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_GROUP, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_SET_NW_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_SET_NW_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_DEC_NW_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_DEC_NW_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_SET_FIELD, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_SET_FIELD, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_PUSH_PBB, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_PUSH_PBB, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_POP_PBB, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_POP_PBB, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_EXPERIMENTER, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_UNDEFINED_ACTION_TYPE, OFPET_BAD_ACTION, OFPBAC_BAD_TYPE },
      { 0, 0, 0 },
    }
  },
  {
    OFPT_PORT_MOD,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_PORT_NO, OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_PORT },
      { ERROR_INVALID_PORT_CONFIG, OFPET_BAD_REQUEST, OFPBRC_EPERM }, // FIXME
      { ERROR_INVALID_PORT_MASK, OFPET_BAD_REQUEST, OFPBRC_EPERM }, // FIXME
      { ERROR_INVALID_PORT_FEATURES, OFPET_BAD_REQUEST, OFPBRC_EPERM }, // FIXME
      { 0, 0, 0 },
    }
  },
  {
    OFPT_TABLE_MOD,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { 0, 0, 0 },
    }
  },
  {
    OFPT_MULTIPART_REQUEST,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_UNSUPPORTED_STATS_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_MULTIPART },
      { ERROR_INVALID_STATS_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_MULTIPART },
      { ERROR_INVALID_STATS_REQUEST_FLAGS, OFPET_BAD_REQUEST, OFPBRC_EPERM }, // FIXME
      { ERROR_INVALID_PORT_NO, OFPET_BAD_REQUEST, OFPBRC_EPERM }, // FIXME
      { ERROR_INVALID_VLAN_VID, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_VLAN_PCP, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_IP_DSCP, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_IP_ECN, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_IPV6_FLABEL, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_MPLS_LABEL, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_MPLS_TC, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_MPLS_BOS, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_PBB_ISID, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_IPV6_EXTHDR, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_MATCH_TYPE, OFPET_BAD_MATCH, OFPBMC_BAD_TYPE },
      { ERROR_BAD_MATCH_PREREQ, OFPET_BAD_MATCH, OFPBMC_BAD_PREREQ },
      { 0, 0, 0 },
    }
  },
  {
    OFPT_MULTIPART_REPLY,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_UNSUPPORTED_STATS_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_MULTIPART },
      { ERROR_INVALID_STATS_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_MULTIPART },
      { ERROR_INVALID_STATS_REPLY_FLAGS, OFPET_BAD_REQUEST, OFPBRC_EPERM }, // FIXME
      { ERROR_INVALID_PORT_NO, OFPET_BAD_REQUEST, OFPBRC_EPERM }, // FIXME
      { ERROR_INVALID_VLAN_VID, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_VLAN_PCP, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_IP_DSCP, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_IP_ECN, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_IPV6_FLABEL, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_MPLS_LABEL, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_MPLS_TC, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_MPLS_BOS, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_PBB_ISID, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_IPV6_EXTHDR, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
      { ERROR_INVALID_MATCH_TYPE, OFPET_BAD_MATCH, OFPBMC_BAD_TYPE },
      { ERROR_BAD_MATCH_PREREQ, OFPET_BAD_MATCH, OFPBMC_BAD_PREREQ },
      { ERROR_TOO_SHORT_INSTRUCTION, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_UNDEFINED_INSTRUCTION_TYPE, OFPET_BAD_INSTRUCTION, OFPBIC_UNKNOWN_INST },
      { ERROR_INVALID_INSTRUCTION_TYPE, OFPET_BAD_INSTRUCTION, OFPBIC_UNKNOWN_INST },
      { ERROR_TOO_SHORT_INSTRUCTION_GOTO_TABLE, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_LONG_INSTRUCTION_GOTO_TABLE, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_SHORT_INSTRUCTION_WRITE_METADATA, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_LONG_INSTRUCTION_WRITE_METADATA, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_SHORT_INSTRUCTION_WRITE_ACTIONS, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_LONG_INSTRUCTION_WRITE_ACTIONS, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_SHORT_INSTRUCTION_APPLY_ACTIONS, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_LONG_INSTRUCTION_APPLY_ACTIONS, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_SHORT_INSTRUCTION_CLEAR_ACTIONS, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_LONG_INSTRUCTION_CLEAR_ACTIONS, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_SHORT_INSTRUCTION_METER, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_LONG_INSTRUCTION_METER, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_SHORT_INSTRUCTION_EXPERIMENTER, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_TOO_LONG_INSTRUCTION_EXPERIMENTER, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
      { ERROR_INVALID_ACTION_TYPE, OFPET_BAD_ACTION, OFPBAC_BAD_TYPE },
      { ERROR_TOO_SHORT_ACTION_OUTPUT, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_OUTPUT, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_INVALID_PORT_NO, OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT },
      { ERROR_TOO_SHORT_ACTION_COPY_TTL_OUT, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_COPY_TTL_OUT, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_COPY_TTL_IN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_COPY_TTL_IN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_SET_MPLS_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_SET_MPLS_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_DEC_MPLS_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_DEC_MPLS_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_PUSH_VLAN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_PUSH_VLAN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_POP_VLAN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_POP_VLAN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_PUSH_MPLS, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_PUSH_MPLS, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_POP_MPLS, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_POP_MPLS, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_SET_QUEUE, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_SET_QUEUE, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_GROUP, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_GROUP, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_SET_NW_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_SET_NW_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_DEC_NW_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_DEC_NW_TTL, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_SET_FIELD, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_SET_FIELD, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_PUSH_PBB, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_PUSH_PBB, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_POP_PBB, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_LONG_ACTION_POP_PBB, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_TOO_SHORT_ACTION_EXPERIMENTER, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
      { ERROR_UNDEFINED_ACTION_TYPE, OFPET_BAD_ACTION, OFPBAC_BAD_TYPE },
      { 0, 0, 0 },
    }
  },
  {
    OFPT_BARRIER_REQUEST,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { 0, 0, 0 },
    }
  },
  {
    OFPT_BARRIER_REPLY,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { 0, 0, 0 },
    }
  },
  {
    OFPT_QUEUE_GET_CONFIG_REQUEST,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_PORT_NO, OFPET_QUEUE_OP_FAILED, OFPQOFC_BAD_PORT },
      { 0, 0, 0 },
    }
  },
  {
    OFPT_QUEUE_GET_CONFIG_REPLY,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_PORT_NO, OFPET_BAD_REQUEST, OFPBRC_EPERM }, // FIXME
      { ERROR_TOO_SHORT_QUEUE_DESCRIPTION, OFPET_BAD_REQUEST, OFPBRC_EPERM }, // FIXME
      { ERROR_TOO_SHORT_QUEUE_PROPERTY, OFPET_BAD_REQUEST, OFPBRC_EPERM }, // FIXME
      { ERROR_TOO_LONG_QUEUE_PROPERTY, OFPET_BAD_REQUEST, OFPBRC_EPERM }, // FIXME
      { ERROR_UNDEFINED_QUEUE_PROPERTY, OFPET_BAD_REQUEST, OFPBRC_EPERM }, // FIXME
      { 0, 0, 0 },
    }
  },
  {
    OFPT_ROLE_REQUEST,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_CONTROLLER_ROLE, OFPET_ROLE_REQUEST_FAILED, OFPRRFC_BAD_ROLE },
      { 0, 0, 0 },
    }
  },
  {
    OFPT_ROLE_REPLY,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_CONTROLLER_ROLE, OFPET_ROLE_REQUEST_FAILED, OFPRRFC_BAD_ROLE },
      { 0, 0, 0 },
    }
  },
  {
    OFPT_GET_ASYNC_REQUEST,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { 0, 0, 0 },
    }
  },
  {
    OFPT_GET_ASYNC_REPLY,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_PORT_STATUS_MASK, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE }, // FIXME
      { ERROR_INVALID_PORT_MASK, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE }, // FIXME
      { ERROR_INVALID_FLOW_REMOVED_MASK, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE }, // FIXME
      { 0, 0, 0 },
    }
  },
  {
    OFPT_SET_ASYNC,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_PORT_STATUS_MASK, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE }, // FIXME
      { ERROR_INVALID_PORT_MASK, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE }, // FIXME
      { ERROR_INVALID_FLOW_REMOVED_MASK, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE }, // FIXME
      { 0, 0, 0 },
    }
  },
  {
    OFPT_METER_MOD,
    {
      { ERROR_UNSUPPORTED_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
      { ERROR_TOO_SHORT_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_TOO_LONG_MESSAGE, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_INVALID_LENGTH, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
      { ERROR_UNDEFINED_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
      { ERROR_INVALID_METER_COMMAND, OFPET_METER_MOD_FAILED, OFPMMFC_BAD_COMMAND },
      { ERROR_INVALID_METER_FLAGS, OFPET_METER_MOD_FAILED, OFPMMFC_BAD_FLAGS },
      { ERROR_INVALID_METER_BAND_TYPE, OFPET_METER_MOD_FAILED, OFPMMFC_BAD_BAND },
      { 0, 0, 0 },
    }
  },
};


bool
get_error_type_and_code( const uint8_t type, const int error_no,
                         uint16_t *error_type, uint16_t *error_code ) {
  if ( type > OFPT_METER_MOD ) {
    *error_type = OFPET_BAD_REQUEST;
    *error_code = OFPBRC_BAD_TYPE;
    debug( "Undefined OpenFlow message type ( type = %u ).", type );
    return true;
  }

  int i = 0;
  for ( i = 0; error_maps[ type ].maps[ i ].error_no != 0; i++ ) {
    if ( error_no == error_maps[ type ].maps[ i ].error_no ) {
      *error_type = error_maps[ type ].maps[ i ].error_type;
      *error_code = error_maps[ type ].maps[ i ].error_code;
      return true;
    }
  }

  return false;
}


void
set_match_from_packet( oxm_matches *match, const uint32_t in_port,
                       const mask_fields *mask, const buffer *packet ) {
  // Note that mask must be filled before calling this function.

  assert( packet != NULL );
  assert( packet->user_data != NULL );
  assert( match != NULL );

  bool no_mask = ( mask == NULL ) ? true : false;
  uint16_t eth_type = 0;
  uint8_t ip_proto = 0;
  uint8_t icmpv6_type = 0;
  uint8_t tmp_mac_mask[ OFP_ETH_ALEN ];
  uint8_t no_mac_mask[ OFP_ETH_ALEN ];
  struct in6_addr tmp_ipv6_mask;
  struct in6_addr no_ipv6_mask;

  memset( no_mac_mask, 0xff, sizeof( no_mac_mask ) );
  memset( &no_ipv6_mask, 0xff, sizeof( no_ipv6_mask ) );

  if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_IN_PORT ) ) ) {
    append_oxm_match_in_port( match, in_port );
  }

  // Layer 2
  if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_ETH_SRC ) ) ) {
    if ( no_mask ) {
      memcpy( tmp_mac_mask, no_mac_mask, sizeof( tmp_mac_mask ) );
    }
    else {
      memcpy( tmp_mac_mask, mask->mask_eth_src, sizeof( tmp_mac_mask ) );
    }
    append_oxm_match_eth_src( match, ( ( packet_info * ) packet->user_data )->eth_macsa, tmp_mac_mask );
  }
  if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_ETH_DST ) ) ) {
    if ( no_mask ) {
      memcpy( tmp_mac_mask, no_mac_mask, sizeof( tmp_mac_mask ) );
    }
    else {
      memcpy( tmp_mac_mask, mask->mask_eth_dst, sizeof( tmp_mac_mask ) );
    }
    append_oxm_match_eth_dst( match, ( ( packet_info * ) packet->user_data )->eth_macda, tmp_mac_mask );
  }
  if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_PBB_ISID ) ) ) {
    uint32_t pbb_isid = 0;
    if ( packet_type_eth_pbb( packet ) ) {
      pbb_isid = ( ( packet_info * ) packet->user_data )->pbb_isid;
      if ( ( pbb_isid & ( uint32_t ) ~PBB_ISID_MASK ) != 0 ) {
        warn( "Invalid pbb_isid ( change %#x to %#x )", pbb_isid, pbb_isid & PBB_ISID_MASK );
        pbb_isid = ( uint32_t ) ( pbb_isid & PBB_ISID_MASK );
      }
      append_oxm_match_pbb_isid( match, pbb_isid, ( uint32_t ) ( no_mask ? UINT32_MAX : mask->mask_pbb_isid ) );
    }
  }
  if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_VLAN_VID ) ) ) {
    uint16_t vlan_vid;
    if ( packet_type_eth_vtag( packet ) ) {
      vlan_vid = ( ( packet_info * ) packet->user_data )->vlan_vid;
      vlan_vid = ( uint16_t ) ( vlan_vid | OFPVID_PRESENT );
      if ( ( vlan_vid & ~VLAN_VID_MASK ) != 0 ) {
        warn( "Invalid vlan id ( change %#x to %#x )", vlan_vid, vlan_vid & VLAN_VID_MASK );
        vlan_vid = ( uint16_t ) ( vlan_vid & VLAN_VID_MASK );
      }
    }
    else {
      vlan_vid = OFPVID_NONE;
    }
    append_oxm_match_vlan_vid( match, vlan_vid, ( uint16_t ) ( no_mask ? UINT16_MAX : mask->mask_vlan_vid ) );
  }
  if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_VLAN_PCP ) ) ) {
    if ( packet_type_eth_vtag( packet ) ) {
      uint8_t dl_vlan_pcp = ( ( packet_info * ) packet->user_data )->vlan_prio;
      if ( ( dl_vlan_pcp & ~VLAN_PCP_MASK ) != 0 ) {
        warn( "Invalid vlan pcp ( change %#x to %#x )", dl_vlan_pcp, dl_vlan_pcp & VLAN_PCP_MASK );
        dl_vlan_pcp = ( uint8_t ) ( dl_vlan_pcp & VLAN_PCP_MASK );
      }
      append_oxm_match_vlan_pcp( match, dl_vlan_pcp );
    }
  }
  if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_ETH_TYPE ) ) ) {
    eth_type = ( ( packet_info * ) packet->user_data )->eth_type;
    append_oxm_match_eth_type( match, eth_type );
  }

  // Layer 3
  if ( eth_type == ETH_ETHTYPE_IPV4 ) {
    if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_IP_DSCP ) ) ) {
      append_oxm_match_ip_dscp( match, ( uint8_t ) ( ( ( ( packet_info * ) packet->user_data )->ipv4_tos >> 2 & 0x3f ) ) );
    }
    if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_IP_ECN ) ) ) {
      append_oxm_match_ip_ecn( match, ( uint8_t ) ( ( ( packet_info * ) packet->user_data )->ipv4_tos & 0x3 ) );
    }
    if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_IP_PROTO ) ) ) {
      ip_proto = ( ( packet_info * ) packet->user_data )->ipv4_protocol;
      append_oxm_match_ip_proto( match, ip_proto );
    }
    if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_IPV4_SRC ) ) ) {
      append_oxm_match_ipv4_src( match, ( ( packet_info * ) packet->user_data )->ipv4_saddr, ( uint32_t ) ( no_mask ? UINT32_MAX : mask->mask_ipv4_src ) );
    }
    if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_IPV4_DST ) ) ) {
      append_oxm_match_ipv4_dst( match, ( ( packet_info * ) packet->user_data )->ipv4_daddr, ( uint32_t ) ( no_mask ? UINT32_MAX : mask->mask_ipv4_dst ) );
    }
  }
  else if ( eth_type == ETH_ETHTYPE_IPV6 ) {
    if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_IP_DSCP ) ) ) {
      append_oxm_match_ip_dscp( match, ( uint8_t ) ( ( ( ( packet_info * ) packet->user_data )->ipv6_tc >> 2 & 0x3f ) ) );
    }
    if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_IP_ECN ) ) ) {
      append_oxm_match_ip_ecn( match, ( uint8_t ) ( ( ( packet_info * ) packet->user_data )->ipv6_tc & 0x3 ) );
    }
    if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_IP_PROTO ) ) ) {
      ip_proto = ( ( packet_info * ) packet->user_data )->ipv6_protocol;
      append_oxm_match_ip_proto( match, ip_proto );
    }
    if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_IPV6_SRC ) ) ) {
      if ( no_mask ) {
        memcpy( &tmp_ipv6_mask, &no_ipv6_mask, sizeof( tmp_ipv6_mask ) );
      }
      else {
        memcpy( &tmp_ipv6_mask, &mask->mask_ipv6_src, sizeof( tmp_ipv6_mask ) );
      }
      append_oxm_match_ipv6_src( match, ( ( packet_info * ) packet->user_data )->ipv6_saddr, tmp_ipv6_mask );
    }
    if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_IPV6_DST ) ) ) {
      if ( no_mask ) {
        memcpy( &tmp_ipv6_mask, &no_ipv6_mask, sizeof( tmp_ipv6_mask ) );
      }
      else {
        memcpy( &tmp_ipv6_mask, &mask->mask_ipv6_dst, sizeof( tmp_ipv6_mask ) );
      }
      append_oxm_match_ipv6_dst( match, ( ( packet_info * ) packet->user_data )->ipv6_daddr, tmp_ipv6_mask );
    }
    if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_IPV6_FLABEL ) ) ) {
      append_oxm_match_ipv6_flabel( match, ( ( packet_info * ) packet->user_data )->ipv6_flowlabel, ( uint32_t ) ( no_mask ? UINT32_MAX : mask->mask_flabel ) );
    }
    if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_IPV6_EXTHDR ) ) ) {
      append_oxm_match_ipv6_exthdr( match, ( ( packet_info * ) packet->user_data )->ipv6_exthdr, ( uint16_t ) ( no_mask ? UINT32_MAX : mask->mask_ipv6_exthdr ) );
    }
  }
  else if ( eth_type == ETH_ETHTYPE_ARP ) {
    if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_ARP_OP ) ) ) {
      append_oxm_match_arp_op( match, ( ( packet_info * ) packet->user_data )->arp_ar_op );
    }
    if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_ARP_SPA ) ) ) {
      append_oxm_match_arp_spa( match, ( ( packet_info * ) packet->user_data )->arp_spa, ( uint32_t ) ( no_mask ? UINT32_MAX : mask->mask_arp_spa ) );
    }
    if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_ARP_TPA ) ) ) {
      append_oxm_match_arp_tpa( match, ( ( packet_info * ) packet->user_data )->arp_tpa, ( uint32_t ) ( no_mask ? UINT32_MAX : mask->mask_arp_tpa ) );
    }
    if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_ARP_SHA ) ) ) {
      if ( no_mask ) {
        memcpy( tmp_mac_mask, no_mac_mask, sizeof( tmp_mac_mask ) );
      }
      else {
        memcpy( tmp_mac_mask, mask->mask_arp_sha, sizeof( tmp_mac_mask ) );
      }
      append_oxm_match_arp_sha( match, ( ( packet_info * ) packet->user_data )->arp_sha, tmp_mac_mask );
    }
    if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_ARP_THA ) ) ) {
      if ( no_mask ) {
        memcpy( tmp_mac_mask, no_mac_mask, sizeof( tmp_mac_mask ) );
      }
      else {
        memcpy( tmp_mac_mask, mask->mask_arp_tha, sizeof( tmp_mac_mask ) );
      }
      append_oxm_match_arp_tha( match, ( ( packet_info * ) packet->user_data )->arp_tha, tmp_mac_mask );
    }
  }
  else if ( ( eth_type == ETH_ETHTYPE_MPLS_UNI ) || ( eth_type == ETH_ETHTYPE_MPLS_MLT ) ) {
    if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_MPLS_LABEL ) ) ) {
      append_oxm_match_mpls_label( match, ( ( ( packet_info * ) packet->user_data )->mpls_label >> 12 & 0xfffff ) );
    }
    if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_MPLS_TC ) ) ) {
      append_oxm_match_mpls_tc( match, ( uint8_t ) ( ( ( packet_info * ) packet->user_data )->mpls_label >> 9 & 0x7 ) );
    }
    if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_MPLS_BOS ) ) ) {
      append_oxm_match_mpls_bos( match, ( uint8_t ) ( ( ( packet_info * ) packet->user_data )->mpls_label >> 8 & 0x1 ) );
    }
  }

  // Layer 4
  if ( ( eth_type == ETH_ETHTYPE_IPV4 ) || ( eth_type == ETH_ETHTYPE_IPV6 ) ) {
    switch ( ip_proto ) {
    case IPPROTO_ICMP:
      if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_ICMPV4_TYPE ) ) ) {
        append_oxm_match_icmpv4_type( match, ( ( packet_info * ) packet->user_data )->icmpv4_type );
      }
      if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_ICMPV4_CODE ) ) ) {
        append_oxm_match_icmpv4_code( match, ( ( packet_info * ) packet->user_data )->icmpv4_code );
      }
      break;
    case IPPROTO_TCP:
      if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_TCP_SRC ) ) ) {
        append_oxm_match_tcp_src( match, ( ( packet_info * ) packet->user_data )->tcp_src_port );
      }
      if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_TCP_DST ) ) ) {
        append_oxm_match_tcp_dst( match, ( ( packet_info * ) packet->user_data )->tcp_dst_port );
      }
      break;
    case IPPROTO_UDP:
      if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_UDP_SRC ) ) ) {
        append_oxm_match_udp_src( match, ( ( packet_info * ) packet->user_data )->udp_src_port );
      }
      if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_UDP_DST ) ) ) {
        append_oxm_match_udp_dst( match, ( ( packet_info * ) packet->user_data )->udp_dst_port );
      }
      break;
    case IPPROTO_SCTP:
      if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_SCTP_SRC ) ) ) {
        append_oxm_match_sctp_src( match, ( ( packet_info * ) packet->user_data )->sctp_src_port );
      }
      if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_SCTP_DST ) ) ) {
        append_oxm_match_sctp_dst( match, ( ( packet_info * ) packet->user_data )->sctp_dst_port );
      }
      break;
    case IPPROTO_ICMPV6:
      if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_ICMPV6_TYPE ) ) ) {
        icmpv6_type = ( ( packet_info * ) packet->user_data )->icmpv6_type;
        append_oxm_match_icmpv6_type( match, icmpv6_type );
      }
      if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_ICMPV6_CODE ) ) ) {
        append_oxm_match_icmpv6_code( match, ( ( packet_info * ) packet->user_data )->icmpv6_code );
      }
      if ( icmpv6_type == 135 ) {
        if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_IPV6_ND_TARGET ) ) ) {
          append_oxm_match_ipv6_nd_target( match, ( ( packet_info * ) packet->user_data )->icmpv6_nd_target );
        }
        // ICMPv6 option(Source link-layer address)
        if ( ( ( ( packet_info * ) packet->user_data )->icmpv6_nd_ll_type == 1 ) && ( ( ( packet_info * ) packet->user_data )->icmpv6_nd_ll_length == 1 ) ) {
          if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_IPV6_ND_SLL ) ) ) {
            append_oxm_match_ipv6_nd_sll( match, ( ( packet_info * ) packet->user_data )->icmpv6_nd_sll );
          }
        }
      }
      else if ( icmpv6_type == 136 ) {
        if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_IPV6_ND_TARGET ) ) ) {
          append_oxm_match_ipv6_nd_target( match, ( ( packet_info * ) packet->user_data )->icmpv6_nd_target );
        }
        // ICMPv6 option(Target link-layer address)
        if ( ( ( ( packet_info * ) packet->user_data )->icmpv6_nd_ll_type == 2 ) && ( ( ( packet_info * ) packet->user_data )->icmpv6_nd_ll_length == 1 ) ) {
          if ( no_mask || !( mask->wildcards & WILDCARD_OFB_BIT( OFPXMT_OFB_IPV6_ND_TLL ) ) ) {
            append_oxm_match_ipv6_nd_tll( match, ( ( packet_info * ) packet->user_data )->icmpv6_nd_tll );
          }
        }
      }
      break;

    default:
      break;
    }
  }
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
