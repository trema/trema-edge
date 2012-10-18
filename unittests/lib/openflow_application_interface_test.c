/*
 * Unit tests for OpenFlow Application Interface.
 *
 * Author: Yasunobu Chiba
 *
 * Copyright (C) 2008-2012 NEC Corporation
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


#include <openflow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bool.h"
#include "checks.h"
#include "cmockery_trema.h"
#include "hash_table.h"
#include "linked_list.h"
#include "log.h"
#include "messenger.h"
#include "openflow_application_interface.h"
#include "openflow_message.h"
#include "stat.h"
#include "wrapper.h"


/********************************************************************************
 * Helpers.
 ********************************************************************************/

typedef struct {
  char key[ STAT_KEY_LENGTH ];
  uint64_t value;
} stat_entry;


extern bool openflow_application_interface_initialized;
extern openflow_event_handlers_t event_handlers;
extern char service_name[ MESSENGER_SERVICE_NAME_LENGTH ];
extern hash_table *stats;

extern void assert_if_not_initialized();
extern void handle_error( const uint64_t datapath_id, buffer *data );
extern void handle_experimenter_error( const uint64_t datapath_id, buffer *data );
extern void handle_echo_reply( const uint64_t datapath_id, buffer *data );
extern void handle_experimenter( const uint64_t datapath_id, buffer *data );
extern void handle_features_reply( const uint64_t datapath_id, buffer *data );
extern void handle_get_config_reply( const uint64_t datapath_id, buffer *data );
extern void handle_packet_in( const uint64_t datapath_id, buffer *data );
extern void handle_flow_removed( const uint64_t datapath_id, buffer *data );
extern void handle_port_status( const uint64_t datapath_id, buffer *data );
extern void handle_multipart_reply( const uint64_t datapath_id, buffer *data );
extern void handle_stats_reply( const uint64_t datapath_id, buffer *data );
extern void handle_barrier_reply( const uint64_t datapath_id, buffer *data );
extern void handle_queue_get_config_reply( const uint64_t datapath_id, buffer *data );
extern void handle_role_reply( const uint64_t datapath_id, buffer *data );
extern void handle_get_async_reply( const uint64_t datapath_id, buffer *data );
extern void dump_buf( const buffer *data );
extern void handle_switch_events( uint16_t type, void *data, size_t length );
extern void handle_openflow_message( void *data, size_t length );
extern void handle_message( uint16_t type, void *data, size_t length );
extern void insert_dpid( list_element **head, uint64_t *dpid );
extern void handle_list_switches_reply( uint16_t message_type, void *data, size_t length, void *user_data );


#define SWITCH_READY_HANDLER ( ( void * ) 0x00020001 )
#define SWITCH_READY_USER_DATA ( ( void * ) 0x00020011 )
#define SWITCH_DISCONNECTED_HANDLER ( ( void * ) 0x00020002 )
#define SWITCH_DISCONNECTED_USER_DATA ( ( void * ) 0x00020021 )
#define ERROR_HANDLER ( ( void * ) 0x00010001 )
#define ERROR_USER_DATA ( ( void * ) 0x00010011 )
#define EXPERIMENTER_ERROR_HANDLER ( ( void * ) 0x00010002 )
#define EXPERIMENTER_ERROR_USER_DATA ( ( void * ) 0x00010021 )
#define ECHO_REPLY_HANDLER ( ( void * ) 0x00010003 )
#define ECHO_REPLY_USER_DATA ( ( void * ) 0x00010031 )
#define EXPERIMENTER_HANDLER ( ( void * ) 0x00010004 )
#define EXPERIMENTER_USER_DATA ( ( void * ) 0x00010041 )
#define FEATURES_REPLY_HANDLER ( ( void * ) 0x00010005 )
#define FEATURES_REPLY_USER_DATA ( ( void * ) 0x00010051 )
#define GET_CONFIG_REPLY_HANDLER ( ( void * ) 0x00010006 )
#define GET_CONFIG_REPLY_USER_DATA ( ( void * ) 0x00010061 )
#define PACKET_IN_HANDLER ( ( void * ) 0x00010007 )
#define PACKET_IN_USER_DATA ( ( void * ) 0x00010071 )
#define FLOW_REMOVED_HANDLER ( ( void * ) 0x00010008 )
#define FLOW_REMOVED_USER_DATA ( ( void * ) 0x00010081 )
#define PORT_STATUS_HANDLER ( ( void * ) 0x00010009 )
#define PORT_STATUS_USER_DATA ( ( void * ) 0x00010091 )
#define MULTIPART_REPLY_HANDLER ( ( void * ) 0x0001000a )
#define MULTIPART_REPLY_USER_DATA ( ( void * ) 0x000100a1 )
#define BARRIER_REPLY_HANDLER ( ( void * ) 0x0001000b )
#define BARRIER_REPLY_USER_DATA ( ( void * ) 0x000100b1 )
#define QUEUE_GET_CONFIG_REPLY_HANDLER ( ( void * ) 0x0001000c )
#define QUEUE_GET_CONFIG_REPLY_USER_DATA ( ( void * ) 0x000100c1 )
#define ROLE_REPLY_HANDLER ( ( void * ) 0x0001000d )
#define ROLE_REPLY_USER_DATA ( ( void * ) 0x000100d1 )
#define GET_ASYNC_REPLY_HANDLER ( ( void * ) 0x0001000e )
#define GET_ASYNC_REPLY_USER_DATA ( ( void * ) 0x000100e1 )
#define LIST_SWITCHES_REPLY_HANDLER ( ( void * ) 0x0001000f )
#define LIST_SWITCHES_REPLY_USER_DATA ( ( void * ) 0x000100f1 )


static const pid_t PID = 12345;
static char SERVICE_NAME[] = "learning switch application 0";

static openflow_event_handlers_t NULL_EVENT_HANDLERS = { false, ( void * ) 0, ( void * ) 0,
                                                         ( void * ) 0, ( void * ) 0,
                                                         ( void * ) 0, ( void * ) 0,
                                                         ( void * ) 0, ( void * ) 0,
                                                         ( void * ) 0, ( void * ) 0,
                                                         ( void * ) 0, ( void * ) 0,
                                                         ( void * ) 0, ( void * ) 0,
                                                         ( void * ) 0, ( void * ) 0,
                                                         false, ( void * ) 0, ( void * ) 0,
                                                         false, ( void * ) 0, ( void * ) 0,
                                                         ( void * ) 0, ( void * ) 0,
                                                         ( void * ) 0, ( void * ) 0,
                                                         ( void * ) 0, ( void * ) 0,
                                                         ( void * ) 0, ( void * ) 0,
                                                         ( void * ) 0, ( void * ) 0,
                                                         ( void * ) 0, ( void * ) 0,
                                                         ( void * ) 0 };

static openflow_event_handlers_t EVENT_HANDLERS = {
  false, SWITCH_READY_HANDLER, SWITCH_READY_USER_DATA,
  SWITCH_DISCONNECTED_HANDLER, SWITCH_DISCONNECTED_USER_DATA,
  ERROR_HANDLER, ERROR_USER_DATA,
  EXPERIMENTER_ERROR_HANDLER, EXPERIMENTER_ERROR_USER_DATA,
  ECHO_REPLY_HANDLER, ECHO_REPLY_USER_DATA,
  EXPERIMENTER_HANDLER, EXPERIMENTER_USER_DATA,
  FEATURES_REPLY_HANDLER, FEATURES_REPLY_USER_DATA,
  GET_CONFIG_REPLY_HANDLER, GET_CONFIG_REPLY_USER_DATA,
  false, PACKET_IN_HANDLER, PACKET_IN_USER_DATA,
  false, FLOW_REMOVED_HANDLER, FLOW_REMOVED_USER_DATA,
  PORT_STATUS_HANDLER, PORT_STATUS_USER_DATA,
  MULTIPART_REPLY_HANDLER, MULTIPART_REPLY_USER_DATA,
  BARRIER_REPLY_HANDLER, BARRIER_REPLY_USER_DATA,
  QUEUE_GET_CONFIG_REPLY_HANDLER, QUEUE_GET_CONFIG_REPLY_USER_DATA,
  ROLE_REPLY_HANDLER, ROLE_REPLY_USER_DATA,
  GET_ASYNC_REPLY_HANDLER, GET_ASYNC_REPLY_USER_DATA,
  LIST_SWITCHES_REPLY_HANDLER
};
static uint64_t DATAPATH_ID = 0x0102030405060708ULL;
static char REMOTE_SERVICE_NAME[] = "switch.0x102030405060708";
static const uint32_t TRANSACTION_ID = 0x04030201;
static const uint32_t VENDOR_ID = 0xccddeeff;
static const uint8_t MAC_ADDR_X[ OFP_ETH_ALEN ] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
static const uint8_t MAC_ADDR_Y[ OFP_ETH_ALEN ] = { 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d };
static const char *PORT_NAME = "port 1";
static const uint32_t PORT_FEATURES = ( OFPPF_10MB_HD | OFPPF_10MB_FD | OFPPF_100MB_HD |
                                        OFPPF_100MB_FD | OFPPF_1GB_HD | OFPPF_1GB_FD |
                                        OFPPF_10GB_FD | OFPPF_40GB_FD | OFPPF_100GB_FD |
                                        OFPPF_1TB_FD | OFPPF_OTHER |  OFPPF_COPPER |
                                        OFPPF_FIBER | OFPPF_AUTONEG | OFPPF_PAUSE | OFPPF_PAUSE_ASYM );

#define USER_DATA_LEN 64
static uint8_t USER_DATA[ USER_DATA_LEN ];


static bool packet_in_handler_called = false;


/********************************************************************************
 * Mocks.
 ********************************************************************************/

const char*
mock_get_trema_name() {
  return "TEST_SERVICE_NAME";
}


pid_t
mock_getpid() {
  return PID;
}


bool
mock_init_openflow_message() {
  return ( bool ) mock();
}


bool
mock_add_message_received_callback( char *service_name,
                                    void ( *callback )( uint16_t tag, void *data, size_t len ) ) {
  check_expected( service_name );
  check_expected( callback );

  return ( bool ) mock();
}


bool
mock_add_message_replied_callback( char *service_name,
                                   void ( *callback )( uint16_t tag, void *data, size_t len, void *user_data ) ) {
  check_expected( service_name );
  check_expected( callback );

  return ( bool ) mock();
}


bool
mock_send_message( char *service_name, uint16_t tag, void *data, size_t len ) {
  uint32_t tag32 = tag;

  check_expected( service_name );
  check_expected( tag32 );
  check_expected( data );
  check_expected( len );

  return ( bool ) mock();
}


bool
mock_send_request_message( char *to_service_name, char *from_service_name, uint16_t tag,
                           void *data, size_t len, void *user_data ) {
  uint32_t tag32 = tag;

  check_expected( to_service_name );
  check_expected( from_service_name );
  check_expected( tag32 );
  check_expected( data );
  check_expected( len );
  check_expected( user_data );

  return ( bool ) mock();
}


bool
mock_delete_message_received_callback( char *service_name,
                                       void ( *callback )( uint16_t tag, void *data, size_t len ) ) {
  check_expected( service_name );
  check_expected( callback );

  return ( bool ) mock();
}


bool
mock_delete_message_replied_callback( char *service_name,
                                      void ( *callback )( uint16_t tag, void *data, size_t len, void *user_data ) ) {
  check_expected( service_name );
  check_expected( callback );

  return ( bool ) mock();
}


bool
mock_clear_send_queue( const char *service_name ) {
  check_expected( service_name );

  return ( bool ) mock();
}


bool
mock_parse_packet( buffer *buf ) {
  calloc_packet_info( buf );
  return ( bool ) mock();
}


static void
mock_switch_disconnected_handler( uint64_t datapath_id, void *user_data ) {
  check_expected( &datapath_id );
  check_expected( user_data );
}

static void
mock_error_handler( uint64_t datapath_id, uint32_t transaction_id, uint16_t type, uint16_t code,
                    const buffer *data, void *user_data ) {
  uint32_t type32 = type;
  uint32_t code32 = code;

  check_expected( &datapath_id );
  check_expected( transaction_id );
  check_expected( type32 );
  check_expected( code32 );
  check_expected( data->length );
  check_expected( data->data );
  check_expected( user_data );
}


static void
mock_experimenter_error_handler( uint64_t datapath_id, uint32_t transaction_id, uint16_t type,
                                 uint16_t exp_type, uint32_t experimenter,
                                 const buffer *data, void *user_data ) {
  uint32_t type32 = type;
  uint32_t exp_type32 = exp_type;

  check_expected( &datapath_id );
  check_expected( transaction_id );
  check_expected( type32 );
  check_expected( exp_type32 );
  check_expected( experimenter );
  check_expected( data->length );
  check_expected( data->data );
  check_expected( user_data );
}

static void
mock_echo_reply_handler( uint64_t datapath_id, uint32_t transaction_id, const buffer *data,
                         void *user_data ){
  void *data_uc;

  check_expected( &datapath_id );
  check_expected( transaction_id );
  if( data != NULL ) {
    check_expected( data->length );
    check_expected( data->data );
  }
  else {
    data_uc = ( void * ) ( unsigned long ) data;
    check_expected( data_uc );
  }
  check_expected( user_data );
}


static void
mock_experimenter_handler( uint64_t datapath_id, uint32_t transaction_id, uint32_t experimenter,
                           uint32_t exp_type, const buffer *data, void *user_data ){
  void *data_uc;

  check_expected( &datapath_id );
  check_expected( transaction_id );
  check_expected( experimenter );
  check_expected( exp_type );
  if( data != NULL ) {
    check_expected( data->length );
    check_expected( data->data );
  }
  else {
    data_uc = ( void * ) ( unsigned long ) data;
    check_expected( data_uc );
  }
  check_expected( user_data );
}


static void
mock_features_reply_handler( uint64_t datapath_id, uint32_t transaction_id,
                             uint32_t n_buffers, uint8_t n_tables, uint8_t auxiliary_id,
                             uint32_t capabilities, void *user_data ) {
  uint32_t n_tables32 = n_tables;
  uint32_t auxiliary_id32 = auxiliary_id;

  check_expected( &datapath_id );
  check_expected( transaction_id );
  check_expected( n_buffers );
  check_expected( n_tables32 );
  check_expected( auxiliary_id32 );
  check_expected( capabilities );
  check_expected( user_data );
}

static void
mock_get_config_reply_handler( uint64_t datapath_id, uint32_t transaction_id,
                               uint16_t flags, uint16_t miss_send_len, void *user_data ) {
  uint32_t flags32 = flags;
  uint32_t miss_send_len32 = miss_send_len;

  check_expected( &datapath_id );
  check_expected( transaction_id );
  check_expected( flags32 );
  check_expected( miss_send_len32 );
  check_expected( user_data );
}


static void
mock_packet_in_handler(
  uint64_t datapath_id,
  uint32_t transaction_id,
  uint32_t buffer_id,
  uint16_t total_len,
  uint8_t reason,
  uint8_t table_id,
  uint64_t cookie,
  const oxm_matches *match,
  const buffer *data,
  void *user_data
) {
  uint32_t total_len32 = total_len;
  uint32_t reason32 = reason;
  uint32_t table_id32 = table_id;
  oxm_match_header *match1, *match2;
  
  match1 = match->list->data;
  match2 = match->list->next->data;
  
  check_expected( &datapath_id );
  check_expected( transaction_id );
  check_expected( buffer_id );
  check_expected( total_len32 );
  check_expected( reason32 );
  check_expected( table_id32 );
  check_expected( &cookie );
  check_expected( match1 );
  check_expected( match2 );
  if ( data != NULL ) {
    check_expected( data->length );
    check_expected( data->data );
  }
  else {
    void *data_uc = ( void * ) ( unsigned long ) data;
    check_expected( data_uc );
  }
  check_expected( user_data );

  packet_in_handler_called = true;
}


static void
mock_simple_packet_in_handler( uint64_t dpid, packet_in event ) {
  uint64_t datapath_id = dpid;
  uint32_t transaction_id = event.transaction_id;
  uint32_t buffer_id = event.buffer_id;
  uint32_t total_len32 = event.total_len;
  uint32_t reason32 = event.reason;
  uint32_t table_id32 = event.table_id;
  uint64_t cookie = event.cookie;
  const oxm_matches *match = event.match;
  const buffer *data = event.data;
  void *user_data = event.user_data;
  oxm_match_header *match1, *match2;

  match1 = match->list->data;
  match2 = match->list->next->data;
  
  check_expected( &datapath_id );
  check_expected( transaction_id );
  check_expected( buffer_id );
  check_expected( total_len32 );
  check_expected( reason32 );
  check_expected( table_id32 );
  check_expected( &cookie );
  check_expected( match1 );
  check_expected( match2 );
  check_expected( data->length );
  check_expected( user_data );

  packet_in_handler_called = true;
}


static void
mock_flow_removed_handler( uint64_t datapath_id, uint32_t transaction_id, uint64_t cookie, uint16_t priority,
                           uint8_t reason, uint8_t table_id, uint32_t duration_sec, uint32_t duration_nsec,
                           uint16_t idle_timeout, uint16_t hard_timeout, uint64_t packet_count, uint64_t byte_count,
                           const oxm_matches *match, void *user_data ) {
  uint32_t priority32 = priority;
  uint32_t reason32 = reason;
  uint32_t table_id32 = table_id;
  uint32_t idle_timeout32 = idle_timeout;
  uint32_t hard_timeout32 = hard_timeout;
  oxm_match_header *match1, *match2;
  
  match1 = match->list->data;
  match2 = match->list->next->data;

  check_expected( &datapath_id );
  check_expected( transaction_id );
  check_expected( &cookie );
  check_expected( priority32 );
  check_expected( reason32 );
  check_expected( table_id32 );
  check_expected( duration_sec );
  check_expected( duration_nsec );
  check_expected( idle_timeout32 );
  check_expected( hard_timeout32 );
  check_expected( &packet_count );
  check_expected( &byte_count );
  check_expected( match1 );
  check_expected( match2 );
  check_expected( user_data );
}


static void
mock_simple_flow_removed_handler( uint64_t datapath_id, flow_removed message ) {
  uint32_t transaction_id = message.transaction_id;
  uint64_t cookie = message.cookie;
  uint32_t priority32 = message.priority;
  uint32_t reason32 = message.reason;
  uint32_t table_id32 = message.table_id;
  uint32_t duration_sec = message.duration_sec;
  uint32_t duration_nsec = message.duration_nsec;
  uint32_t idle_timeout32 = message.idle_timeout;
  uint32_t hard_timeout32 = message.hard_timeout;
  uint64_t packet_count = message.packet_count;
  uint64_t byte_count = message.byte_count;
  const oxm_matches *match = message.match;
  void *user_data = message.user_data;
  oxm_match_header *match1, *match2;

  match1 = match->list->data;
  match2 = match->list->next->data;

  check_expected( &datapath_id );
  check_expected( transaction_id );
  check_expected( &cookie );
  check_expected( priority32 );
  check_expected( reason32 );
  check_expected( table_id32 );
  check_expected( duration_sec );
  check_expected( duration_nsec );
  check_expected( idle_timeout32 );
  check_expected( hard_timeout32 );
  check_expected( &packet_count );
  check_expected( &byte_count );
  check_expected( match1 );
  check_expected( match2 );
  check_expected( user_data );
}


static void
mock_port_status_handler( uint64_t datapath_id, uint32_t transaction_id, uint8_t reason,
                          struct ofp_port desc, void *user_data ) {
  uint32_t reason32 = reason;

  check_expected( &datapath_id );
  check_expected( transaction_id );
  check_expected( reason32 );
  check_expected( &desc );
  check_expected( user_data );
}


static void
mock_multipart_reply_handler( uint64_t datapath_id, uint32_t transaction_id, uint16_t type,
                              uint16_t flags, const buffer *data, void *user_data ) {
  uint32_t type32 = type;
  uint32_t flags32 = flags;

  check_expected( &datapath_id );
  check_expected( transaction_id );
  check_expected( type32 );
  check_expected( flags32 );
  check_expected( data->length );
  check_expected( data->data );
  check_expected( user_data );
}


static void
mock_barrier_reply_handler( uint64_t datapath_id, uint32_t transaction_id, void *user_data ) {
  check_expected( &datapath_id );
  check_expected( transaction_id );
  check_expected( user_data );
}

static void
mock_queue_get_config_reply_handler( uint64_t datapath_id, uint32_t transaction_id,
                                     uint32_t port, const list_element *queues, void *user_data ) {
  struct ofp_packet_queue *queue1, *queue2;

  queue1 = queues->data;
  queue2 = queues->next->data;

  check_expected( &datapath_id );
  check_expected( transaction_id );
  check_expected( port );
  check_expected( queue1 );
  check_expected( queue2 );
  check_expected( user_data );
}

static void
mock_role_reply_handler( uint64_t datapath_id, uint32_t transaction_id, uint32_t role, uint64_t generation_id, void *user_data ) {
  check_expected( &datapath_id );
  check_expected( transaction_id );
  check_expected( role );
  check_expected( &generation_id );
  check_expected( user_data );
}


static void
mock_get_async_reply_handler( uint64_t datapath_id, uint32_t transaction_id, uint32_t packet_in_mask[2], uint32_t port_status_mask[2],
                              uint32_t flow_removed_mask[2], void *user_data ) {
  check_expected( &datapath_id );
  check_expected( transaction_id );
  check_expected( packet_in_mask );
  check_expected( port_status_mask );
  check_expected( flow_removed_mask );
  check_expected( user_data );
}

static void
mock_handle_list_switches_reply( const list_element *switches, void *user_data ) {
  uint64_t *dpid1, *dpid2, *dpid3;

  if ( switches != NULL ) {
    dpid1 = switches->data;
    check_expected( *dpid1 );
    if ( switches->next != NULL ) {
      dpid2 = switches->next->data;
      check_expected( *dpid2 );
      if ( switches->next->next != NULL ) {
        dpid3 = switches->next->next->data;
        check_expected( *dpid3 );
      }
    }
  }
  check_expected( user_data );
}


void
mock_die( char *format, ... ) {
  check_expected( format );
  mock_assert( false, "die", __FILE__, __LINE__ );
}


void
mock_debug( char *format, ... ) {
  UNUSED( format );
}


void
mock_info( char *format, ... ) {
  UNUSED( format );
}


void
mock_warn( char *format, ... ) {
  UNUSED( format );
}


void
mock_error( char *format, ... ) {
  UNUSED( format );
}


void
mock_critical( char *format, ... ) {
  UNUSED( format );
}


static int
mock_get_logging_level() {
  return LOG_DEBUG;
}


/********************************************************************************
 * Common function.
 ********************************************************************************/

static oxm_match_header *oxm_match_testdata[2] = { NULL, NULL };
static uint16_t oxm_match_testdata_len[2] = { 0, 0 };
struct ofp_match *expected_ofp_match = NULL;
static uint16_t expected_ofp_match_len = 0;


static void
delete_oxm_match_testdata( void ) {
  if ( oxm_match_testdata[0] != NULL ) {
    xfree( oxm_match_testdata[0] );
    oxm_match_testdata[0] = NULL;
  }
  if ( oxm_match_testdata[1] != NULL ) {
    xfree( oxm_match_testdata[1] );
    oxm_match_testdata[1] = NULL;
  }
  if ( expected_ofp_match != NULL ) {
    xfree( expected_ofp_match );
    expected_ofp_match = NULL;
  }
  memset( oxm_match_testdata_len, 0, sizeof( oxm_match_testdata_len ) );
  expected_ofp_match_len = 0;
}


static void
create_oxm_match_testdata( void ) {
  uint16_t offset = sizeof( oxm_match_header );
  uint32_t type;
  uint16_t match_len;
  uint32_t *val32;
  oxm_match_header *match;
  struct ofp_match *ofp_match;
  uint16_t ofp_match_len;
  uint16_t ofp_match_len_with_pad;
  void *v;

  delete_oxm_match_testdata();

  type = OXM_OF_IN_PORT;
  match_len = ( uint16_t ) ( offset + OXM_LENGTH( type ) );
  match = ( oxm_match_header * ) xcalloc( 1, match_len );
  *match = type;
  val32 = ( uint32_t * ) ( ( char * ) match + offset );
  *val32 = 0x01020304;

  oxm_match_testdata[0] = match;
  oxm_match_testdata_len[0] = match_len;


  type = OXM_OF_IN_PHY_PORT;
  match_len = ( uint16_t ) ( offset + OXM_LENGTH( type ) );
  match = ( oxm_match_header * ) xcalloc( 1, match_len );
  *match = type;
  val32 = ( uint32_t * ) ( ( char * ) match + offset );
  *val32 = 0x05060708;

  oxm_match_testdata[1] = match;
  oxm_match_testdata_len[1] = match_len;

  ofp_match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields )
                                + oxm_match_testdata_len[0]
                                + oxm_match_testdata_len[1] );
  ofp_match_len_with_pad = ( uint16_t ) ( ofp_match_len + PADLEN_TO_64( ofp_match_len ) );
  ofp_match = ( struct ofp_match * ) xcalloc( 1, ofp_match_len_with_pad );
  ofp_match->type = OFPMT_OXM;
  ofp_match->length = ofp_match_len;
  v = ( char * ) ofp_match + offsetof( struct ofp_match, oxm_fields );
  memcpy( v, oxm_match_testdata[0], oxm_match_testdata_len[0] );
  v = ( char * ) v + oxm_match_testdata_len[0];
  memcpy( v, oxm_match_testdata[1], oxm_match_testdata_len[1] );

  expected_ofp_match = ofp_match;
  expected_ofp_match_len = ofp_match_len_with_pad;
}


static struct ofp_instruction *instruction_testdata[2] = { NULL, NULL };
static uint16_t instruction_testdata_len[2] = { 0, 0 };
struct ofp_instruction *expected_ofp_instruction = NULL;
static uint16_t expected_ofp_instruction_len = 0;


static void
delete_instruction_testdata( void ) {
  if ( instruction_testdata[0] != NULL ) {
    xfree( instruction_testdata[0] );
    instruction_testdata[0] = NULL;
  }
  if ( instruction_testdata[1] != NULL ) {
    xfree( instruction_testdata[1] );
    instruction_testdata[1] = NULL;
  }
  if ( expected_ofp_instruction != NULL ) {
    xfree( expected_ofp_instruction );
    expected_ofp_instruction = NULL;
  }
  memset( instruction_testdata_len, 0, sizeof( instruction_testdata_len ) );
  expected_ofp_instruction_len = 0;
}


static void
create_instruction_testdata( void ) {
  uint16_t instruction_len;
  uint16_t ofp_instruction_len;
  struct ofp_instruction *inst;
  struct ofp_instruction_meter *instruction;
  void *d;

  delete_instruction_testdata();

  instruction_len = ( uint16_t ) ( sizeof( struct ofp_instruction_meter ) );
  instruction = ( struct ofp_instruction_meter * ) xcalloc( 1, instruction_len );
  instruction->type = OFPIT_METER;
  instruction->len = instruction_len;
  instruction->meter_id = 0x01020304;

  instruction_testdata[0] = ( struct ofp_instruction * ) instruction;
  instruction_testdata_len[0] = instruction_len;


  instruction_len = ( uint16_t ) ( sizeof( struct ofp_instruction_meter ) );
  instruction = ( struct ofp_instruction_meter * ) xcalloc( 1, instruction_len );
  instruction->type = OFPIT_METER;
  instruction->len = instruction_len;
  instruction->meter_id = 0x05060708;

  instruction_testdata[1] = ( struct ofp_instruction * ) instruction;
  instruction_testdata_len[1] = instruction_len;

  ofp_instruction_len = ( uint16_t ) ( instruction_testdata_len[0] + instruction_testdata_len[1] );
  inst = ( struct ofp_instruction * ) xcalloc( 1, ofp_instruction_len );
  memcpy( inst, instruction_testdata[0], instruction_testdata_len[0] );
  d = ( char * ) inst + instruction_testdata_len[0];
  memcpy( d, instruction_testdata[1], instruction_testdata_len[1] );

  expected_ofp_instruction = inst;
  expected_ofp_instruction_len = ofp_instruction_len;
}


static struct ofp_bucket *bucket_testdata[2] = { NULL, NULL };
static uint16_t bucket_testdata_len[2] = { 0, 0 };


static void
delete_bucket_testdata( void ) {
  if ( bucket_testdata[0] != NULL ) {
    xfree( bucket_testdata[0] );
    bucket_testdata[0] = NULL;
  }
  if ( bucket_testdata[1] != NULL ) {
    xfree( bucket_testdata[1] );
    bucket_testdata[1] = NULL;
  }
  memset( bucket_testdata_len, 0, sizeof( bucket_testdata_len ) );
}


static void
create_bucket_testdata( void ) {
  uint16_t action_len;
  uint16_t bucket_len;
  struct ofp_bucket *bucket;
  struct ofp_action_output *act;

  delete_bucket_testdata();

  action_len = sizeof( struct ofp_action_output );
  bucket_len = ( uint16_t ) ( offsetof( struct ofp_bucket, actions ) + action_len );
  bucket = ( struct ofp_bucket * ) xcalloc( 1, bucket_len );
  bucket->len = bucket_len;
  bucket->weight = 0x1234;
  bucket->watch_port = 0x11223344;
  bucket->watch_group = 0x55667788;
  act = ( struct ofp_action_output * ) bucket->actions;
  act->type = OFPAT_OUTPUT;
  act->len = action_len;
  act->port = 0x01020304;
  act->max_len = 0x0506;

  bucket_testdata[0] = ( struct ofp_bucket * ) bucket;
  bucket_testdata_len[0] = bucket_len;


  action_len = sizeof( struct ofp_action_output );
  bucket_len = ( uint16_t ) ( offsetof( struct ofp_bucket, actions ) + action_len );
  bucket = ( struct ofp_bucket * ) xcalloc( 1, bucket_len );
  bucket->len = bucket_len;
  bucket->weight = 0x5678;
  bucket->watch_port = 0x12233445;
  bucket->watch_group = 0x56677889;
  act = ( struct ofp_action_output * ) bucket->actions;
  act->type = OFPAT_OUTPUT;
  act->len = action_len;
  act->port = 0x0708090A;
  act->max_len = 0x0B0C;

  bucket_testdata[1] = ( struct ofp_bucket * ) bucket;
  bucket_testdata_len[1] = bucket_len;
}


/********************************************************************************
 * Setup and teardown function.
 ********************************************************************************/

static void
cleanup() {
  openflow_application_interface_initialized = false;
  packet_in_handler_called = false;

  memset( service_name, 0, sizeof( service_name ) );
  memset( &event_handlers, 0, sizeof( event_handlers ) );
  memset( USER_DATA, 'Z', sizeof( USER_DATA ) );
  if ( stats != NULL ) {
    delete_hash( stats );
    stats = NULL;
  }
}


static void
init() {
  bool ret;

  get_logging_level = mock_get_logging_level;

  cleanup();

  will_return( mock_init_openflow_message, true );

  expect_string( mock_add_message_received_callback, service_name, SERVICE_NAME );
  expect_value( mock_add_message_received_callback, callback, handle_message );
  will_return( mock_add_message_received_callback, true );

  expect_string( mock_add_message_replied_callback, service_name, SERVICE_NAME );
  expect_value( mock_add_message_replied_callback, callback, handle_list_switches_reply );
  will_return( mock_add_message_replied_callback, true );

  init_stat();

  ret = init_openflow_application_interface( SERVICE_NAME );

  assert_true( ret );
  assert_true( openflow_application_interface_initialized );
  assert_string_equal( service_name, SERVICE_NAME );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * init_openflow_application_interface() tests.
 ********************************************************************************/

static void
test_init_openflow_application_interface_with_valid_custom_service_name() {
  bool ret;

  will_return( mock_init_openflow_message, true );

  expect_string( mock_add_message_received_callback, service_name, SERVICE_NAME );
  expect_value( mock_add_message_received_callback, callback, handle_message );
  will_return( mock_add_message_received_callback, true );

  expect_string( mock_add_message_replied_callback, service_name, SERVICE_NAME );
  expect_value( mock_add_message_replied_callback, callback, handle_list_switches_reply );
  will_return( mock_add_message_replied_callback, true );

  ret = init_openflow_application_interface( SERVICE_NAME );

  assert_true( ret );
  assert_true( openflow_application_interface_initialized );
  assert_string_equal( service_name, SERVICE_NAME );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


static void
test_init_openflow_application_interface_with_too_long_custom_service_name() {
  bool ret;
  char too_long_service_name[ MESSENGER_SERVICE_NAME_LENGTH + 1 ];
  char expected_service_name[ MESSENGER_SERVICE_NAME_LENGTH ];

  memset( too_long_service_name, 'a', sizeof( too_long_service_name ) );
  too_long_service_name[ MESSENGER_SERVICE_NAME_LENGTH ] = '\0';

  memset( expected_service_name, '\0', sizeof( expected_service_name ) );

  ret = init_openflow_application_interface( too_long_service_name );

  assert_true( ret == false );
  assert_true( openflow_application_interface_initialized == false );
  assert_string_equal( service_name, expected_service_name );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


static void
test_init_openflow_application_interface_if_already_initialized() {
  bool ret;

  ret = set_openflow_event_handlers( EVENT_HANDLERS );

  assert_true( ret );
  assert_memory_equal( &event_handlers, &EVENT_HANDLERS, sizeof( event_handlers ) );

  ret = init_openflow_application_interface( SERVICE_NAME );

  assert_true( ret == false );
  assert_true( openflow_application_interface_initialized == true );
  assert_string_equal( service_name, SERVICE_NAME );
  assert_memory_equal( &event_handlers, &EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * init_openflow_application_interface() tests.
 ********************************************************************************/

static void
test_finalize_openflow_application_interface() {
  bool ret;
  char expected_service_name[ MESSENGER_SERVICE_NAME_LENGTH ];

  memset( expected_service_name, '\0', sizeof( expected_service_name ) );

  expect_string( mock_delete_message_received_callback, service_name, SERVICE_NAME );
  expect_value( mock_delete_message_received_callback, callback, handle_message );
  will_return( mock_delete_message_received_callback, true );

  expect_string( mock_delete_message_replied_callback, service_name, SERVICE_NAME );
  expect_value( mock_delete_message_replied_callback, callback, handle_list_switches_reply );
  will_return( mock_delete_message_replied_callback, true );

  ret = finalize_openflow_application_interface();

  assert_true( ret );
  assert_true( openflow_application_interface_initialized == false );
  assert_string_equal( service_name, expected_service_name );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


static void
test_finalize_openflow_application_interface_if_not_initialized() {
  char expected_service_name[ MESSENGER_SERVICE_NAME_LENGTH ];

  memset( expected_service_name, '\0', sizeof( expected_service_name ) );

  expect_assert_failure( finalize_openflow_application_interface() );

  assert_true( openflow_application_interface_initialized == false );
  assert_string_equal( service_name, expected_service_name );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * set_openflow_event_handlers() tests.
 ********************************************************************************/

static void
test_set_openflow_event_handlers() {
  bool ret;

  ret = set_openflow_event_handlers( EVENT_HANDLERS );

  assert_true( ret );
  assert_memory_equal( &event_handlers, &EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * Switch ready handler tests.
 ********************************************************************************/

static void
mock_switch_ready_handler( uint64_t datapath_id, void *user_data ) {
  check_expected( &datapath_id );
  check_expected( user_data );
}


static void
mock_simple_switch_ready_handler( switch_ready event ) {
  uint64_t datapath_id = event.datapath_id;
  void *user_data = event.user_data;

  check_expected( &datapath_id );
  check_expected( user_data );
}


static void
test_set_switch_ready_handler() {
  char user_data[] = "Ready!";
  set_switch_ready_handler( mock_switch_ready_handler, user_data );
  assert_true( event_handlers.switch_ready_callback == mock_switch_ready_handler );
  assert_string_equal( event_handlers.switch_ready_user_data, user_data );
}


static void
test_set_simple_switch_ready_handler() {
  char user_data[] = "Ready!";
  set_switch_ready_handler( mock_simple_switch_ready_handler, user_data );
  assert_true( event_handlers.switch_ready_callback == mock_simple_switch_ready_handler );
  assert_string_equal( event_handlers.switch_ready_user_data, user_data );
}


static void
test_set_switch_ready_handler_should_die_if_handler_is_NULL() {
  char user_data[] = "Ready!";
  expect_string( mock_die, format, "Invalid callback function for switch_ready event." );
  expect_assert_failure( set_switch_ready_handler( NULL, user_data ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


static void
test_handle_switch_ready() {
  char user_data[] = "Ready!";
  buffer *data = alloc_buffer_with_length( sizeof( openflow_service_header_t ) );
  uint64_t *datapath_id = append_back_buffer( data, sizeof( openflow_service_header_t ) );
  *datapath_id = htonll( DATAPATH_ID );

  expect_memory( mock_switch_ready_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_string( mock_switch_ready_handler, user_data, user_data );

  set_switch_ready_handler( mock_switch_ready_handler, user_data );
  handle_message( MESSENGER_OPENFLOW_READY, data->data, data->length );

  stat_entry *stat = lookup_hash_entry( stats, "openflow_application_interface.switch_ready_receive_succeeded" );
  assert_int_equal( ( int ) stat->value, 1 );

  free_buffer( data );
  xfree( delete_hash_entry( stats, "openflow_application_interface.switch_ready_receive_succeeded" ) );
}


static void
test_handle_switch_ready_with_simple_handler() {
  char user_data[] = "Ready!";
  buffer *data = alloc_buffer_with_length( sizeof( openflow_service_header_t ) );
  uint64_t *datapath_id = append_back_buffer( data, sizeof( openflow_service_header_t ) );
  *datapath_id = htonll( DATAPATH_ID );

  expect_memory( mock_simple_switch_ready_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_string( mock_simple_switch_ready_handler, user_data, user_data );

  set_switch_ready_handler( mock_simple_switch_ready_handler, user_data );
  handle_message( MESSENGER_OPENFLOW_READY, data->data, data->length );

  stat_entry *stat = lookup_hash_entry( stats, "openflow_application_interface.switch_ready_receive_succeeded" );
  assert_int_equal( ( int ) stat->value, 1 );

  free_buffer( data );
  xfree( delete_hash_entry( stats, "openflow_application_interface.switch_ready_receive_succeeded" ) );
}


/********************************************************************************
 * set_switch_disconnected_handler() tests.
 ********************************************************************************/

static void
test_set_switch_disconnected_handler() {
  assert_true( set_switch_disconnected_handler( SWITCH_DISCONNECTED_HANDLER, SWITCH_DISCONNECTED_USER_DATA ) );
  assert_int_equal( event_handlers.switch_disconnected_callback, SWITCH_DISCONNECTED_HANDLER );
  assert_int_equal( event_handlers.switch_disconnected_user_data, SWITCH_DISCONNECTED_USER_DATA );
}


static void
test_set_switch_disconnected_handler_if_handler_is_NULL() {
  expect_string( mock_die, format, "Callback function ( switch_disconnected_handler ) must not be NULL." );
  expect_assert_failure( set_switch_disconnected_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * set_error_handler() tests.
 ********************************************************************************/

static void
test_set_error_handler() {
  assert_true( set_error_handler( ERROR_HANDLER, ERROR_USER_DATA ) );
  assert_int_equal( event_handlers.error_callback, ERROR_HANDLER );
  assert_int_equal( event_handlers.error_user_data, ERROR_USER_DATA );
}


static void
test_set_error_handler_if_handler_is_NULL() {
  expect_string( mock_die, format, "Callback function ( error_handler ) must not be NULL." );
  expect_assert_failure( set_error_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * set_experimenter_error_handler() tests.
 ********************************************************************************/

static void
test_set_experimenter_error_handler() {
  assert_true( set_experimenter_error_handler( EXPERIMENTER_ERROR_HANDLER, EXPERIMENTER_ERROR_USER_DATA ) );
  assert_int_equal( event_handlers.experimenter_error_callback, EXPERIMENTER_ERROR_HANDLER );
  assert_int_equal( event_handlers.experimenter_error_user_data, EXPERIMENTER_ERROR_USER_DATA );
}


static void
test_set_experimenter_error_handler_if_handler_is_NULL() {
  expect_string( mock_die, format, "Callback function ( experimenter_error_handler ) must not be NULL." );
  expect_assert_failure( set_experimenter_error_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * set_echo_reply_handler() tests.
 ********************************************************************************/

static void
test_set_echo_reply_handler() {
  assert_true( set_echo_reply_handler( ECHO_REPLY_HANDLER, ECHO_REPLY_USER_DATA ) );
  assert_int_equal( event_handlers.echo_reply_callback, ECHO_REPLY_HANDLER );
  assert_int_equal( event_handlers.echo_reply_user_data, ECHO_REPLY_USER_DATA );
}


static void
test_set_echo_reply_handler_if_handler_is_NULL() {
  expect_string( mock_die, format, "Callback function ( echo_reply_handler ) must not be NULL." );
  expect_assert_failure( set_echo_reply_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * set_experimenter_handler() tests.
 ********************************************************************************/

static void
test_set_experimenter_handler() {
  assert_true( set_experimenter_handler( EXPERIMENTER_HANDLER, EXPERIMENTER_USER_DATA ) );
  assert_int_equal( event_handlers.experimenter_callback, EXPERIMENTER_HANDLER );
  assert_int_equal( event_handlers.experimenter_user_data, EXPERIMENTER_USER_DATA );
}


static void
test_set_experimenter_handler_if_handler_is_NULL() {
  expect_string( mock_die, format, "Callback function ( experimenter_handler ) must not be NULL." );
  expect_assert_failure( set_experimenter_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * set_features_reply_handler() tests.
 ********************************************************************************/

static void
test_set_features_reply_handler() {
  assert_true( set_features_reply_handler( FEATURES_REPLY_HANDLER, FEATURES_REPLY_USER_DATA ) );
  assert_int_equal( event_handlers.features_reply_callback, FEATURES_REPLY_HANDLER );
  assert_int_equal( event_handlers.features_reply_user_data, FEATURES_REPLY_USER_DATA );
}


static void
test_set_features_reply_handler_if_handler_is_NULL() {
  expect_string( mock_die, format, "Callback function ( features_reply_handler ) must not be NULL." );
  expect_assert_failure( set_features_reply_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * set_get_config_reply_handler() tests.
 ********************************************************************************/

static void
test_set_get_config_reply_handler() {
  assert_true( set_get_config_reply_handler( GET_CONFIG_REPLY_HANDLER, GET_CONFIG_REPLY_USER_DATA ) );
  assert_int_equal( event_handlers.get_config_reply_callback, GET_CONFIG_REPLY_HANDLER );
  assert_int_equal( event_handlers.get_config_reply_user_data, GET_CONFIG_REPLY_USER_DATA );
}


static void
test_set_get_config_reply_handler_if_handler_is_NULL() {
  expect_string( mock_die, format, "Callback function ( get_config_reply_handler ) must not be NULL." );
  expect_assert_failure( set_get_config_reply_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * Packet in handler tests.
 ********************************************************************************/
static void
test_set_packet_in_handler() {
  set_packet_in_handler( mock_packet_in_handler, PACKET_IN_USER_DATA );
  assert_true( event_handlers.packet_in_callback == mock_packet_in_handler );
  assert_true( event_handlers.packet_in_user_data == PACKET_IN_USER_DATA );
}


static void
test_set_simple_packet_in_handler() {
  set_packet_in_handler( mock_simple_packet_in_handler, PACKET_IN_USER_DATA );
  assert_true( event_handlers.packet_in_callback == mock_simple_packet_in_handler );
  assert_true( event_handlers.packet_in_user_data == PACKET_IN_USER_DATA );
}


static void
test_set_packet_in_handler_should_die_if_handler_is_NULL() {
  expect_string( mock_die, format, "Callback function ( packet_in_handler ) must not be NULL." );
  expect_assert_failure( set_packet_in_handler( NULL, PACKET_IN_USER_DATA ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * set_flow_removed_handler() tests.
 ********************************************************************************/
static void
test_set_flow_removed_handler() {
  set_flow_removed_handler( mock_flow_removed_handler, FLOW_REMOVED_USER_DATA );
  assert_true( event_handlers.flow_removed_callback == mock_flow_removed_handler );
  assert_true( event_handlers.flow_removed_user_data == FLOW_REMOVED_USER_DATA );
}


static void
test_set_simple_flow_removed_handler() {
  set_flow_removed_handler( mock_simple_flow_removed_handler, FLOW_REMOVED_USER_DATA );
  assert_true( event_handlers.flow_removed_callback == mock_simple_flow_removed_handler );
  assert_true( event_handlers.flow_removed_user_data == FLOW_REMOVED_USER_DATA );
}


static void
test_set_flow_removed_handler_if_handler_is_NULL() {
  expect_string( mock_die, format, "Callback function ( flow_removed_handler ) must not be NULL." );
  expect_assert_failure( set_flow_removed_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * set_port_status_handler() tests.
 ********************************************************************************/

static void
test_set_port_status_handler() {
  assert_true( set_port_status_handler( PORT_STATUS_HANDLER, PORT_STATUS_USER_DATA ) );
  assert_int_equal( event_handlers.port_status_callback, PORT_STATUS_HANDLER );
  assert_int_equal( event_handlers.port_status_user_data, PORT_STATUS_USER_DATA );
}


static void
test_set_port_status_handler_if_handler_is_NULL() {
  expect_string( mock_die, format, "Callback function ( port_status_handler ) must not be NULL." );
  expect_assert_failure( set_port_status_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * set_multipart_reply_handler() tests.
 ********************************************************************************/

static void
test_set_multipart_reply_handler() {
  assert_true( set_multipart_reply_handler( MULTIPART_REPLY_HANDLER, MULTIPART_REPLY_USER_DATA ) );
  assert_int_equal( event_handlers.multipart_reply_callback, MULTIPART_REPLY_HANDLER );
  assert_int_equal( event_handlers.multipart_reply_user_data, MULTIPART_REPLY_USER_DATA );
}


static void
test_set_multipart_reply_handler_if_handler_is_NULL() {
  expect_string( mock_die, format, "Callback function ( multipart_reply_handler ) must not be NULL." );
  expect_assert_failure( set_multipart_reply_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * set_barrier_reply_handler() tests.
 ********************************************************************************/

static void
test_set_barrier_reply_handler() {
  assert_true( set_barrier_reply_handler( BARRIER_REPLY_HANDLER, BARRIER_REPLY_USER_DATA ) );
  assert_int_equal( event_handlers.barrier_reply_callback, BARRIER_REPLY_HANDLER );
  assert_int_equal( event_handlers.barrier_reply_user_data, BARRIER_REPLY_USER_DATA );
}


static void
test_set_barrier_reply_handler_if_handler_is_NULL() {
  expect_string( mock_die, format, "Callback function ( barrier_reply_handler ) must not be NULL." );
  expect_assert_failure( set_barrier_reply_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * set_queue_get_config_reply_handler() tests.
 ********************************************************************************/

static void
test_set_queue_get_config_reply_handler() {
  assert_true( set_queue_get_config_reply_handler( QUEUE_GET_CONFIG_REPLY_HANDLER, QUEUE_GET_CONFIG_REPLY_USER_DATA ) );
  assert_int_equal( event_handlers.queue_get_config_reply_callback, QUEUE_GET_CONFIG_REPLY_HANDLER );
  assert_int_equal( event_handlers.queue_get_config_reply_user_data, QUEUE_GET_CONFIG_REPLY_USER_DATA );
}


static void
test_set_queue_get_config_reply_handler_if_handler_is_NULL() {
  expect_string( mock_die, format, "Callback function ( queue_get_config_reply_handler ) must not be NULL." );
  expect_assert_failure( set_queue_get_config_reply_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * set_role_reply_handler() tests.
 ********************************************************************************/

static void
test_set_role_reply_handler() {
  assert_true( set_role_reply_handler( ROLE_REPLY_HANDLER, ROLE_REPLY_USER_DATA ) );
  assert_int_equal( event_handlers.role_reply_callback, ROLE_REPLY_HANDLER );
  assert_int_equal( event_handlers.role_reply_user_data, ROLE_REPLY_USER_DATA );
}


static void
test_set_role_reply_handler_if_handler_is_NULL() {
  expect_string( mock_die, format, "Callback function ( role_reply_handler ) must not be NULL." );
  expect_assert_failure( set_role_reply_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * set_get_async_reply_handler() tests.
 ********************************************************************************/

static void
test_set_get_async_reply_handler() {
  assert_true( set_get_async_reply_handler( GET_ASYNC_REPLY_HANDLER, GET_ASYNC_REPLY_USER_DATA ) );
  assert_int_equal( event_handlers.get_async_reply_callback, GET_ASYNC_REPLY_HANDLER );
  assert_int_equal( event_handlers.get_async_reply_user_data, GET_ASYNC_REPLY_USER_DATA );
}


static void
test_set_get_async_reply_handler_if_handler_is_NULL() {
  expect_string( mock_die, format, "Callback function ( get_async_reply_handler ) must not be NULL." );
  expect_assert_failure( set_get_async_reply_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * set_list_switches_reply_handler() tests.
 ********************************************************************************/


static void
test_set_list_switches_reply_handler() {
  assert_true( set_list_switches_reply_handler( LIST_SWITCHES_REPLY_HANDLER ) );
  assert_int_equal( event_handlers.list_switches_reply_callback, LIST_SWITCHES_REPLY_HANDLER );
}


static void
test_set_list_switches_reply_handler_if_handler_is_NULL() {
  expect_string( mock_die, format, "Callback function ( list_switches_reply_handler ) must not be NULL." );
  expect_assert_failure( set_list_switches_reply_handler( NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * send_openflow_message() tests.
 ********************************************************************************/

static void
test_send_openflow_message() {
  void *expected_data;
  bool ret;
  size_t expected_length, header_length;
  buffer *buffer;
  openflow_service_header_t *header;

  buffer = create_hello( TRANSACTION_ID, NULL );

  assert_true( buffer != NULL );

  header_length = ( size_t ) ( sizeof( openflow_service_header_t ) +
                               strlen( SERVICE_NAME ) + 1 );
  expected_length = ( size_t ) ( header_length + sizeof( struct ofp_header ) );

  expected_data = xcalloc( 1, expected_length );

  header = expected_data;
  header->datapath_id = htonll( DATAPATH_ID );
  header->service_name_length = htons( ( uint16_t ) ( strlen( SERVICE_NAME ) + 1 ) );

  memcpy( ( char * ) expected_data + sizeof( openflow_service_header_t ),
          SERVICE_NAME, strlen( SERVICE_NAME ) + 1 );
  memcpy( ( char * ) expected_data + header_length, buffer->data, buffer->length );

  expect_string( mock_send_message, service_name, REMOTE_SERVICE_NAME );
  expect_value( mock_send_message, tag32, MESSENGER_OPENFLOW_MESSAGE );
  expect_value( mock_send_message, len, expected_length );
  expect_memory( mock_send_message, data, expected_data, expected_length );
  will_return( mock_send_message, true );

  ret = send_openflow_message( DATAPATH_ID, buffer );
  
  assert_true( ret );
  stat_entry *stat = lookup_hash_entry( stats, "openflow_application_interface.hello_send_succeeded" );
  assert_int_equal( ( int ) stat->value, 1 );

  free_buffer( buffer );
  xfree( expected_data );
  xfree( delete_hash_entry( stats, "openflow_application_interface.hello_send_succeeded" ) );
}


static void
test_send_openflow_message_if_message_is_NULL() {
  expect_assert_failure( send_openflow_message( DATAPATH_ID, NULL ) );
}


static void
test_send_openflow_message_if_message_length_is_zero() {
  buffer *buffer;

  buffer = alloc_buffer_with_length( 128 );

  assert_true( buffer != NULL );

  expect_assert_failure( send_openflow_message( DATAPATH_ID, NULL ) );

  free_buffer( buffer );
}


/********************************************************************************
 * handle_error() tests.
 ********************************************************************************/

static void
test_handle_error() {
  buffer *buffer, *data;

  data = alloc_buffer_with_length( 16 );
  append_back_buffer( data, 16 );
  memset( data->data, 'a', 16 );

  buffer = create_error( TRANSACTION_ID, OFPET_HELLO_FAILED, OFPHFC_INCOMPATIBLE, data );

  expect_memory( mock_error_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_error_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_error_handler, type32, OFPET_HELLO_FAILED );
  expect_value( mock_error_handler, code32, OFPHFC_INCOMPATIBLE );
  expect_value( mock_error_handler, data->length, data->length );
  expect_memory( mock_error_handler, data->data, data->data, data->length );
  expect_memory( mock_error_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_error_handler( mock_error_handler, USER_DATA );
  handle_error( DATAPATH_ID, buffer );

  free_buffer( data );
  free_buffer( buffer );
}


static void
test_handle_error_if_handler_is_not_registered() {
  buffer *buffer, *data;

  data = alloc_buffer_with_length( 16 );
  append_back_buffer( data, 16 );
  memset( data->data, 'a', 16 );

  buffer = create_error( TRANSACTION_ID, OFPET_HELLO_FAILED, OFPHFC_INCOMPATIBLE, data );

  // FIXME

  handle_error( DATAPATH_ID, buffer );

  free_buffer( data );
  free_buffer( buffer );
}


static void
test_handle_error_if_message_is_NULL() {
  set_error_handler( mock_error_handler, USER_DATA );
  expect_assert_failure( handle_error( DATAPATH_ID, NULL ) );
}


static void
test_handle_error_if_message_length_is_zero() {
  buffer *buffer;

  buffer = alloc_buffer_with_length( 32 );

  set_error_handler( mock_error_handler, USER_DATA );
  expect_assert_failure( handle_error( DATAPATH_ID, buffer ) );

  free_buffer( buffer );
}


/********************************************************************************
 * handle_experimenter_error() tests.
 ********************************************************************************/

static void
test_handle_experimenter_error() {
    uint16_t type = OFPET_EXPERIMENTER;

    uint16_t exp_type = 0x3344;
    uint32_t experimenter = 0x55667788;
    buffer *buffer, *data;
    
    data = alloc_buffer_with_length( 16 );
    append_back_buffer( data, 16 );
    memset( data->data, 'a', 16 );

    buffer = create_error_experimenter( TRANSACTION_ID, type, exp_type, experimenter, data );
    
    expect_memory( mock_experimenter_error_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_experimenter_error_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_experimenter_error_handler, type32, ( uint32_t ) type );
    expect_value( mock_experimenter_error_handler, exp_type32, ( uint32_t ) exp_type );
    expect_value( mock_experimenter_error_handler, experimenter, experimenter );
    expect_value( mock_experimenter_error_handler, data->length, data->length );
    expect_memory( mock_experimenter_error_handler, data->data, data->data, data->length );
    expect_memory( mock_experimenter_error_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_experimenter_error_handler( mock_experimenter_error_handler, USER_DATA );
    handle_experimenter_error( DATAPATH_ID, buffer );

    free_buffer( data );
    free_buffer( buffer );
}


static void
test_handle_experimenter_error_if_handler_is_not_registered() {
    uint16_t type = OFPET_EXPERIMENTER;

    uint16_t exp_type = 0x3344;
    uint32_t experimenter = 0x55667788;
    buffer *buffer, *data;
    
    data = alloc_buffer_with_length( 16 );
    append_back_buffer( data, 16 );
    memset( data->data, 'a', 16 );

    buffer = create_error_experimenter( TRANSACTION_ID, type, exp_type, experimenter, data );

  // FIXME

    handle_experimenter_error( DATAPATH_ID, buffer );

    free_buffer( data );
    free_buffer( buffer );
}


static void
test_handle_experimenter_error_if_message_is_NULL() {
  set_experimenter_error_handler( mock_experimenter_error_handler, USER_DATA );
  expect_assert_failure( handle_experimenter_error( DATAPATH_ID, NULL ) );
}


static void
test_handle_experimenter_error_if_message_length_is_zero() {
  buffer *buffer;

  buffer = alloc_buffer_with_length( 32 );

  set_experimenter_error_handler( mock_experimenter_error_handler, USER_DATA );
  expect_assert_failure( handle_experimenter_error( DATAPATH_ID, buffer ) );

  free_buffer( buffer );
}


/********************************************************************************
 * handle_echo_reply() tests.
 ********************************************************************************/

static void
test_handle_echo_reply() {
  buffer *buffer, *data;

  data = alloc_buffer_with_length( 16 );
  append_back_buffer( data, 16 );
  memset( data->data, 'a', 16 );

  buffer = create_echo_reply( TRANSACTION_ID, data );

  expect_memory( mock_echo_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_echo_reply_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_echo_reply_handler, data->length, data->length );
  expect_memory( mock_echo_reply_handler, data->data, data->data, data->length );
  expect_memory( mock_echo_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_echo_reply_handler( mock_echo_reply_handler, USER_DATA );
  handle_echo_reply( DATAPATH_ID, buffer );

  free_buffer( data );
  free_buffer( buffer );
}


static void
test_handle_echo_reply_without_data() {
  buffer *buffer;

  buffer = create_echo_reply( TRANSACTION_ID, NULL );

  expect_memory( mock_echo_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_echo_reply_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_echo_reply_handler, data_uc, NULL );
  expect_memory( mock_echo_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_echo_reply_handler( mock_echo_reply_handler, USER_DATA );
  handle_echo_reply( DATAPATH_ID, buffer );

  free_buffer( buffer );
}


static void
test_handle_echo_reply_if_handler_is_not_registered() {
  buffer *buffer, *data;

  data = alloc_buffer_with_length( 16 );
  append_back_buffer( data, 16 );
  memset( data->data, 'a', 16 );

  buffer = create_echo_reply( TRANSACTION_ID, data );

  // FIXME

  handle_echo_reply( DATAPATH_ID, buffer );

  free_buffer( data );
  free_buffer( buffer );
}


static void
test_handle_echo_reply_if_message_is_NULL() {
  set_echo_reply_handler( mock_echo_reply_handler, USER_DATA );
  expect_assert_failure( handle_echo_reply( DATAPATH_ID, NULL ) );
}


static void
test_handle_echo_reply_if_message_length_is_zero() {
  buffer *buffer;

  buffer = alloc_buffer_with_length( 32 );

  set_echo_reply_handler( mock_echo_reply_handler, USER_DATA );
  expect_assert_failure( handle_echo_reply( DATAPATH_ID, buffer ) );

  free_buffer( buffer );
}


/********************************************************************************
 * handle_experimenter() tests.
 ********************************************************************************/

static void
test_handle_experimenter() {
  buffer *buffer, *data;
  uint32_t exp_type = 0x1122;

  data = alloc_buffer_with_length( 16 );
  append_back_buffer( data, 16 );
  memset( data->data, 'a', 16 );

  buffer = create_experimenter( TRANSACTION_ID, VENDOR_ID, exp_type, data );

  expect_memory( mock_experimenter_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_experimenter_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_experimenter_handler, experimenter, VENDOR_ID );
  expect_value( mock_experimenter_handler, exp_type, exp_type );
  expect_value( mock_experimenter_handler, data->length, data->length );
  expect_memory( mock_experimenter_handler, data->data, data->data, data->length );
  expect_memory( mock_experimenter_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_experimenter_handler( mock_experimenter_handler, USER_DATA );
  handle_experimenter( DATAPATH_ID, buffer );

  free_buffer( data );
  free_buffer( buffer );
}


static void
test_handle_experimenter_without_data() {
  buffer *buffer, *data;
  uint32_t exp_type = 0x1122;

  data = alloc_buffer_with_length( 16 );
  append_back_buffer( data, 16 );
  memset( data->data, 'a', 16 );

  buffer = create_experimenter( TRANSACTION_ID, VENDOR_ID, exp_type, NULL );

  expect_memory( mock_experimenter_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_experimenter_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_experimenter_handler, experimenter, VENDOR_ID );
  expect_value( mock_experimenter_handler, exp_type, exp_type );
  expect_value( mock_experimenter_handler, data_uc, NULL );
  expect_memory( mock_experimenter_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_experimenter_handler( mock_experimenter_handler, USER_DATA );
  handle_experimenter( DATAPATH_ID, buffer );

  free_buffer( data );
  free_buffer( buffer );
}


static void
test_handle_experimenter_if_handler_is_not_registered() {
  buffer *buffer, *data;
  uint32_t exp_type = 0x1122;

  data = alloc_buffer_with_length( 16 );
  append_back_buffer( data, 16 );
  memset( data->data, 'a', 16 );

  buffer = create_experimenter( TRANSACTION_ID, VENDOR_ID, exp_type, data );

  // FIXME

  handle_experimenter( DATAPATH_ID, buffer );

  free_buffer( data );
  free_buffer( buffer );
}


static void
test_handle_experimenter_if_message_is_NULL() {
  set_experimenter_handler( mock_experimenter_handler, USER_DATA );
  expect_assert_failure( handle_experimenter( DATAPATH_ID, NULL ) );
}


static void
test_handle_experimenter_if_message_length_is_zero() {
  buffer *buffer;

  buffer = alloc_buffer_with_length( 32 );

  set_experimenter_handler( mock_experimenter_handler, USER_DATA );
  expect_assert_failure( handle_experimenter( DATAPATH_ID, buffer ) );

  free_buffer( buffer );
}


/********************************************************************************
 * handle_features_reply() tests.
 ********************************************************************************/

static void
test_handle_features_reply() {
  uint32_t n_buffers = 1024;
  uint8_t n_tables = 2;
  uint8_t auxiliary_id = 0x11;
  uint32_t capabilities;
  buffer *buffer;

  capabilities = ( OFPC_FLOW_STATS | OFPC_TABLE_STATS | OFPC_PORT_STATS |
                   OFPC_GROUP_STATS | OFPC_IP_REASM | OFPC_QUEUE_STATS | OFPC_PORT_BLOCKED );

  buffer = create_features_reply( TRANSACTION_ID, DATAPATH_ID, n_buffers, n_tables,
                                  auxiliary_id, capabilities );

  expect_memory( mock_features_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_features_reply_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_features_reply_handler, n_buffers, n_buffers );
  expect_value( mock_features_reply_handler, n_tables32, ( uint32_t ) n_tables );
  expect_value( mock_features_reply_handler, auxiliary_id32, ( uint32_t ) auxiliary_id );
  expect_value( mock_features_reply_handler, capabilities, capabilities );
  expect_memory( mock_features_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_features_reply_handler( mock_features_reply_handler, USER_DATA );
  handle_features_reply( DATAPATH_ID, buffer );

  free_buffer( buffer );
}


static void
test_handle_features_reply_if_handler_is_not_registered() {
  uint32_t n_buffers = 1024;
  uint8_t n_tables = 2;
  uint8_t auxiliary_id = 0x11;
  uint32_t capabilities;
  buffer *buffer;

  capabilities = ( OFPC_FLOW_STATS | OFPC_TABLE_STATS | OFPC_PORT_STATS |
                   OFPC_GROUP_STATS | OFPC_IP_REASM | OFPC_QUEUE_STATS | OFPC_PORT_BLOCKED );

  buffer = create_features_reply( TRANSACTION_ID, DATAPATH_ID, n_buffers, n_tables,
                                  auxiliary_id, capabilities );

  // FIXME

  handle_features_reply( DATAPATH_ID, buffer );

  free_buffer( buffer );
}


static void
test_handle_features_reply_if_message_is_NULL() {
  set_features_reply_handler( mock_features_reply_handler, USER_DATA );
  expect_assert_failure( handle_features_reply( DATAPATH_ID, NULL ) );
}


static void
test_handle_features_reply_if_message_length_is_zero() {
  buffer *buffer;

  buffer = alloc_buffer_with_length( 32 );

  set_features_reply_handler( mock_features_reply_handler, USER_DATA );
  expect_assert_failure( handle_features_reply( DATAPATH_ID, buffer ) );

  free_buffer( buffer );
}


/********************************************************************************
 * handle_get_config_reply() tests.
 ********************************************************************************/

static void
test_handle_get_config_reply() {
  uint16_t flags = OFPC_FRAG_NORMAL;
  uint16_t miss_send_len = 128;
  buffer *buffer;

  buffer = create_get_config_reply( TRANSACTION_ID, flags, miss_send_len );

  expect_memory( mock_get_config_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_get_config_reply_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_get_config_reply_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_get_config_reply_handler, miss_send_len32, ( uint32_t ) miss_send_len );
  expect_memory( mock_get_config_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_get_config_reply_handler( mock_get_config_reply_handler, USER_DATA );
  handle_get_config_reply( DATAPATH_ID, buffer );

  free_buffer( buffer );
}


static void
test_handle_get_config_reply_if_handler_is_not_registered() {
  uint16_t flags = OFPC_FRAG_NORMAL;
  uint16_t miss_send_len = 128;
  buffer *buffer;

  buffer = create_get_config_reply( TRANSACTION_ID, flags, miss_send_len );

  // FIXME

  handle_get_config_reply( DATAPATH_ID, buffer );

  free_buffer( buffer );
}


static void
test_handle_get_config_reply_if_message_is_NULL() {
  set_get_config_reply_handler( mock_get_config_reply_handler, USER_DATA );
  expect_assert_failure( handle_get_config_reply( DATAPATH_ID, NULL ) );
}


static void
test_handle_get_config_reply_if_message_length_is_zero() {
  buffer *buffer;

  buffer = alloc_buffer_with_length( 32 );

  set_get_config_reply_handler( mock_get_config_reply_handler, USER_DATA );
  expect_assert_failure( handle_get_config_reply( DATAPATH_ID, buffer ) );

  free_buffer( buffer );
}


/********************************************************************************
 * handle_packet_in() tests.
 ********************************************************************************/
static void
test_handle_packet_in() {
  uint32_t buffer_id = 0x01020304;
  uint8_t reason = OFPR_NO_MATCH;
  uint8_t table_id = 0x01;
  uint64_t cookie = 0xAAAABBBBCCCCDDDD;
  oxm_matches *match;
  size_t match1_len, match2_len;
  oxm_match_header *queue[ 2 ];
  uint32_t* value;
  
  match1_len = ( sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_IN_PORT ) );
  queue[ 0 ] = xcalloc( 1, match1_len );
  value = ( uint32_t* ) (queue[ 0 ] + 1);
  *queue[ 0 ] = OXM_OF_IN_PORT;
  *value = 0x2468ACEF;
    
  match2_len = ( sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_IN_PHY_PORT ) );
  queue[ 1 ] = xcalloc( 1, match2_len );
  value = ( uint32_t* ) (queue[ 1 ] + 1);
  *queue[ 1 ] = OXM_OF_IN_PHY_PORT;
  *value = 0xFECA8642;

  match = create_oxm_matches();
  match->n_matches = 2;
  append_to_tail( &match->list, queue[ 0 ] );
  append_to_tail( &match->list, queue[ 1 ] );

  buffer *data = alloc_buffer_with_length( 64 );
  calloc_packet_info( data );
  append_back_buffer( data, 64 );
  memset( data->data, 0x01, 64 );
  uint16_t total_len = ( uint16_t ) data->length ;


  buffer *buffer = create_packet_in( TRANSACTION_ID, buffer_id, total_len, reason, table_id, cookie, match, data );
  
  will_return( mock_parse_packet, true );
  expect_memory( mock_packet_in_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_packet_in_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_packet_in_handler, buffer_id, buffer_id );
  expect_value( mock_packet_in_handler, total_len32, ( uint32_t ) total_len );
  expect_value( mock_packet_in_handler, reason32, ( uint32_t ) reason );
  expect_value( mock_packet_in_handler, table_id32, ( uint32_t ) table_id );
  expect_memory( mock_packet_in_handler, &cookie, &cookie, sizeof( uint64_t ) );
  expect_memory( mock_packet_in_handler, match1, queue[ 0 ], match1_len );
  expect_memory( mock_packet_in_handler, match2, queue[ 1 ], match2_len );
  expect_value( mock_packet_in_handler, data->length, data->length );
  expect_memory( mock_packet_in_handler, data->data, data->data, data->length );
  expect_memory( mock_packet_in_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_packet_in_handler( mock_packet_in_handler, USER_DATA );
  handle_packet_in( DATAPATH_ID, buffer );

  delete_oxm_matches(match);
  free_buffer( buffer );
  free_buffer( data );
}


static void
test_handle_packet_in_with_simple_handler() {
  uint32_t buffer_id = 0x01020304;
  uint8_t reason = OFPR_NO_MATCH;
  uint8_t table_id = 0x01;
  uint64_t cookie = 0xAAAABBBBCCCCDDDD;
  oxm_matches *match;
  size_t match1_len, match2_len;
  oxm_match_header *queue[ 2 ];
  uint32_t* value;
  
  match1_len = ( sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_IN_PORT ) );
  queue[ 0 ] = xcalloc( 1, match1_len );
  value = ( uint32_t* ) (queue[ 0 ] + 1);
  *queue[ 0 ] = OXM_OF_IN_PORT;
  *value = 0x2468ACEF;
    
  match2_len = ( sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_IN_PHY_PORT ) );
  queue[ 1 ] = xcalloc( 1, match2_len );
  value = ( uint32_t* ) (queue[ 1 ] + 1);
  *queue[ 1 ] = OXM_OF_IN_PHY_PORT;
  *value = 0xFECA8642;

  match = create_oxm_matches();
  match->n_matches = 2;
  append_to_tail( &match->list, queue[ 0 ] );
  append_to_tail( &match->list, queue[ 1 ] );

  buffer *data = alloc_buffer_with_length( 64 );
  calloc_packet_info( data );
  append_back_buffer( data, 64 );
  memset( data->data, 0x01, 64 );
  uint16_t total_len = ( uint16_t ) data->length ;

  buffer *buffer = create_packet_in( TRANSACTION_ID, buffer_id, total_len, reason, table_id, cookie, match, data );
  
  will_return( mock_parse_packet, true );
  expect_memory( mock_simple_packet_in_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_simple_packet_in_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_simple_packet_in_handler, buffer_id, buffer_id );
  expect_value( mock_simple_packet_in_handler, total_len32, ( uint32_t ) total_len );
  expect_value( mock_simple_packet_in_handler, reason32, ( uint32_t ) reason );
  expect_value( mock_simple_packet_in_handler, table_id32, ( uint32_t ) table_id );
  expect_memory( mock_simple_packet_in_handler, &cookie, &cookie, sizeof( uint64_t ) );
  expect_memory( mock_simple_packet_in_handler, match1, queue[ 0 ], match1_len );
  expect_memory( mock_simple_packet_in_handler, match2, queue[ 1 ], match2_len );
  expect_value( mock_simple_packet_in_handler, data->length, data->length );
  expect_memory( mock_simple_packet_in_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_packet_in_handler( mock_simple_packet_in_handler, USER_DATA );
  handle_packet_in( DATAPATH_ID, buffer );

  delete_oxm_matches(match);
  free_buffer( buffer );
  free_buffer( data );
}


static void
test_handle_packet_in_with_malformed_packet() {
  uint32_t buffer_id = 0x01020304;
  uint8_t reason = OFPR_NO_MATCH;
  uint8_t table_id = 0x01;
  uint64_t cookie = 0xAAAABBBBCCCCDDDD;
  oxm_matches *match;
  size_t match1_len, match2_len;
  oxm_match_header *queue[ 2 ];
  uint32_t* value;
  
  match1_len = ( sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_IN_PORT ) );
  queue[ 0 ] = xcalloc( 1, match1_len );
  value = ( uint32_t* ) (queue[ 0 ] + 1);
  *queue[ 0 ] = OXM_OF_IN_PORT;
  *value = 0x2468ACEF;
    
  match2_len = ( sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_IN_PHY_PORT ) );
  queue[ 1 ] = xcalloc( 1, match2_len );
  value = ( uint32_t* ) (queue[ 1 ] + 1);
  *queue[ 1 ] = OXM_OF_IN_PHY_PORT;
  *value = 0xFECA8642;

  match = create_oxm_matches();
  match->n_matches = 2;
  append_to_tail( &match->list, queue[ 0 ] );
  append_to_tail( &match->list, queue[ 1 ] );

  buffer *data = alloc_buffer_with_length( 64 );
  calloc_packet_info( data );
  append_back_buffer( data, 64 );
  memset( data->data, 0x01, 64 );
  uint16_t total_len = ( uint16_t ) data->length ;

  buffer *buffer = create_packet_in( TRANSACTION_ID, buffer_id, total_len, reason, table_id, cookie, match, data );

  will_return( mock_parse_packet, false );

  set_packet_in_handler( mock_packet_in_handler, USER_DATA );

  handle_packet_in( DATAPATH_ID, buffer );

  assert_false( packet_in_handler_called );

  delete_oxm_matches(match);
  free_buffer( buffer );
  free_buffer( data );
}


static void
test_handle_packet_in_without_data() {
  uint32_t buffer_id = 0x01020304;
  uint8_t reason = OFPR_NO_MATCH;
  uint8_t table_id = 0x01;
  uint64_t cookie = 0xAAAABBBBCCCCDDDD;
  oxm_matches *match;
  size_t match1_len, match2_len;
  oxm_match_header *queue[ 2 ];
  uint32_t* value;
  
  match1_len = ( sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_IN_PORT ) );
  queue[ 0 ] = xcalloc( 1, match1_len );
  value = ( uint32_t* ) (queue[ 0 ] + 1);
  *queue[ 0 ] = OXM_OF_IN_PORT;
  *value = 0x2468ACEF;
    
  match2_len = ( sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_IN_PHY_PORT ) );
  queue[ 1 ] = xcalloc( 1, match2_len );
  value = ( uint32_t* ) (queue[ 1 ] + 1);
  *queue[ 1 ] = OXM_OF_IN_PHY_PORT;
  *value = 0xFECA8642;

  match = create_oxm_matches();
  match->n_matches = 2;
  append_to_tail( &match->list, queue[ 0 ] );
  append_to_tail( &match->list, queue[ 1 ] );

  buffer *data = alloc_buffer_with_length( 64 );
  append_back_buffer( data, 64 );
  memset( data->data, 0x01, 64 );
  uint16_t total_len = ( uint16_t ) data->length ;

  buffer *buffer = create_packet_in( TRANSACTION_ID, buffer_id, total_len, reason, table_id, cookie, match, NULL );
  
  expect_memory( mock_packet_in_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_packet_in_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_packet_in_handler, buffer_id, buffer_id );
  expect_value( mock_packet_in_handler, total_len32, ( uint32_t ) total_len );
  expect_value( mock_packet_in_handler, reason32, ( uint32_t ) reason );
  expect_value( mock_packet_in_handler, table_id32, ( uint32_t ) table_id );
  expect_memory( mock_packet_in_handler, &cookie, &cookie, sizeof( uint64_t ) );
  expect_memory( mock_packet_in_handler, match1, queue[ 0 ], match1_len );
  expect_memory( mock_packet_in_handler, match2, queue[ 1 ], match2_len );
  expect_value( mock_packet_in_handler, data_uc, NULL );
  expect_memory( mock_packet_in_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_packet_in_handler( mock_packet_in_handler, USER_DATA );
  handle_packet_in( DATAPATH_ID, buffer );

  delete_oxm_matches(match);
  free_buffer( data );
  free_buffer( buffer );
}


static void
test_handle_packet_in_without_handler() {
  uint32_t buffer_id = 0x01020304;
  uint8_t reason = OFPR_NO_MATCH;
  uint8_t table_id = 0x01;
  uint64_t cookie = 0xAAAABBBBCCCCDDDD;
  oxm_matches *match;
  size_t match1_len, match2_len;
  oxm_match_header *queue[ 2 ];
  uint32_t* value;
  
  match1_len = ( sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_IN_PORT ) );
  queue[ 0 ] = xcalloc( 1, match1_len );
  value = ( uint32_t* ) (queue[ 0 ] + 1);
  *queue[ 0 ] = OXM_OF_IN_PORT;
  *value = 0x2468ACEF;
    
  match2_len = ( sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_IN_PHY_PORT ) );
  queue[ 1 ] = xcalloc( 1, match2_len );
  value = ( uint32_t* ) (queue[ 1 ] + 1);
  *queue[ 1 ] = OXM_OF_IN_PHY_PORT;
  *value = 0xFECA8642;

  match = create_oxm_matches();
  match->n_matches = 2;
  append_to_tail( &match->list, queue[ 0 ] );
  append_to_tail( &match->list, queue[ 1 ] );

  buffer *data = alloc_buffer_with_length( 64 );
  append_back_buffer( data, 64 );
  memset( data->data, 0x01, 64 );
  uint16_t total_len = ( uint16_t ) data->length ;

  buffer *buffer = create_packet_in( TRANSACTION_ID, buffer_id, total_len, reason, table_id, cookie, match, data );
  handle_packet_in( DATAPATH_ID, buffer );
  assert_false( packet_in_handler_called );

  free_buffer( data );
  delete_oxm_matches(match);
  free_buffer( buffer );
}


static void
test_handle_packet_in_should_die_if_message_is_NULL() {
  expect_string( mock_die, format, "handle_packet_in(): packet_in message should not be empty." );
  set_packet_in_handler( mock_packet_in_handler, USER_DATA );
  expect_assert_failure( handle_packet_in( DATAPATH_ID, NULL ) );
}


static void
test_handle_packet_in_should_die_if_message_length_is_zero() {
  buffer *buffer = alloc_buffer_with_length( 32 );

  expect_string( mock_die, format, "handle_packet_in(): packet_in message should not be empty." );
  set_packet_in_handler( mock_packet_in_handler, USER_DATA );
  expect_assert_failure( handle_packet_in( DATAPATH_ID, buffer ) );

  free_buffer( buffer );
}


/********************************************************************************
 * handle_flow_removed() tests.
 ********************************************************************************/

static void
test_handle_flow_removed() {
  uint64_t cookie = 0x1111222233334444;
  uint16_t priority = UINT16_MAX;
  uint8_t reason =  OFPRR_IDLE_TIMEOUT;
  uint8_t table_id = 0xAA;
  uint32_t duration_sec = 180;
  uint32_t duration_nsec = 10000;
  uint16_t idle_timeout = 60;
  uint16_t hard_timeout = 120;
  uint64_t packet_count = 1000;
  uint64_t byte_count = 100000;
  oxm_matches *match;
  size_t match1_len, match2_len;
  oxm_match_header *queue[ 2 ];
  uint32_t* value;
  
  match1_len = ( sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_IN_PORT ) );
  queue[ 0 ] = xcalloc( 1, match1_len );
  value = ( uint32_t* ) (queue[ 0 ] + 1);
  *queue[ 0 ] = OXM_OF_IN_PORT;
  *value = 0x2468ACEF;
    
  match2_len = ( sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_IN_PHY_PORT ) );
  queue[ 1 ] = xcalloc( 1, match2_len );
  value = ( uint32_t* ) (queue[ 1 ] + 1);
  *queue[ 1 ] = OXM_OF_IN_PHY_PORT;
  *value = 0xFECA8642;

  match = create_oxm_matches();
  match->n_matches = 2;
  append_to_tail( &match->list, queue[ 0 ] );
  append_to_tail( &match->list, queue[ 1 ] );

  buffer *buffer = create_flow_removed(
    TRANSACTION_ID,
    cookie,
    priority,
    reason,
    table_id,
    duration_sec,
    duration_nsec,
    idle_timeout,
    hard_timeout,
    packet_count,
    byte_count,
    match
  );

  expect_memory( mock_flow_removed_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_flow_removed_handler, transaction_id, TRANSACTION_ID );
  expect_memory( mock_flow_removed_handler, &cookie, &cookie, sizeof( uint64_t ) );
  expect_value( mock_flow_removed_handler, priority32, ( uint32_t ) priority );
  expect_value( mock_flow_removed_handler, reason32, ( uint32_t ) reason );
  expect_value( mock_flow_removed_handler, table_id32, ( uint32_t ) table_id );
  expect_value( mock_flow_removed_handler, duration_sec, duration_sec );
  expect_value( mock_flow_removed_handler, duration_nsec, duration_nsec );
  expect_value( mock_flow_removed_handler, idle_timeout32, ( uint32_t ) idle_timeout );
  expect_value( mock_flow_removed_handler, hard_timeout32, ( uint32_t ) hard_timeout );
  expect_memory( mock_flow_removed_handler, &packet_count, &packet_count, sizeof( uint64_t ) );
  expect_memory( mock_flow_removed_handler, &byte_count, &byte_count, sizeof( uint64_t ) );
  expect_memory( mock_flow_removed_handler, match1, queue[ 0 ], match1_len );
  expect_memory( mock_flow_removed_handler, match2, queue[ 1 ], match2_len );
  expect_memory( mock_flow_removed_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_flow_removed_handler( mock_flow_removed_handler, USER_DATA );
  handle_flow_removed( DATAPATH_ID, buffer );

  delete_oxm_matches(match);
  free_buffer( buffer );
}


static void
test_handle_flow_removed_with_simple_handler() {
  uint64_t cookie = 0x1111222233334444;
  uint16_t priority = UINT16_MAX;
  uint8_t reason =  OFPRR_IDLE_TIMEOUT;
  uint8_t table_id = 0xAA;
  uint32_t duration_sec = 180;
  uint32_t duration_nsec = 10000;
  uint16_t idle_timeout = 60;
  uint16_t hard_timeout = 120;
  uint64_t packet_count = 1000;
  uint64_t byte_count = 100000;
  oxm_matches *match;
  size_t match1_len, match2_len;
  oxm_match_header *queue[ 2 ];
  uint32_t* value;
  
  match1_len = ( sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_IN_PORT ) );
  queue[ 0 ] = xcalloc( 1, match1_len );
  value = ( uint32_t* ) (queue[ 0 ] + 1);
  *queue[ 0 ] = OXM_OF_IN_PORT;
  *value = 0x2468ACEF;
    
  match2_len = ( sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_IN_PHY_PORT ) );
  queue[ 1 ] = xcalloc( 1, match2_len );
  value = ( uint32_t* ) (queue[ 1 ] + 1);
  *queue[ 1 ] = OXM_OF_IN_PHY_PORT;
  *value = 0xFECA8642;

  match = create_oxm_matches();
  match->n_matches = 2;
  append_to_tail( &match->list, queue[ 0 ] );
  append_to_tail( &match->list, queue[ 1 ] );

  buffer *buffer = create_flow_removed(
    TRANSACTION_ID,
    cookie,
    priority,
    reason,
    table_id,
    duration_sec,
    duration_nsec,
    idle_timeout,
    hard_timeout,
    packet_count,
    byte_count,
    match
  );

  expect_memory( mock_simple_flow_removed_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_simple_flow_removed_handler, transaction_id, TRANSACTION_ID );
  expect_memory( mock_simple_flow_removed_handler, &cookie, &cookie, sizeof( uint64_t ) );
  expect_value( mock_simple_flow_removed_handler, priority32, ( uint32_t ) priority );
  expect_value( mock_simple_flow_removed_handler, reason32, ( uint32_t ) reason );
  expect_value( mock_simple_flow_removed_handler, table_id32, ( uint32_t ) table_id );
  expect_value( mock_simple_flow_removed_handler, duration_sec, duration_sec );
  expect_value( mock_simple_flow_removed_handler, duration_nsec, duration_nsec );
  expect_value( mock_simple_flow_removed_handler, idle_timeout32, ( uint32_t ) idle_timeout );
  expect_value( mock_simple_flow_removed_handler, hard_timeout32, ( uint32_t ) hard_timeout );
  expect_memory( mock_simple_flow_removed_handler, &packet_count, &packet_count, sizeof( uint64_t ) );
  expect_memory( mock_simple_flow_removed_handler, &byte_count, &byte_count, sizeof( uint64_t ) );
  expect_memory( mock_simple_flow_removed_handler, match1, queue[ 0 ], match1_len );
  expect_memory( mock_simple_flow_removed_handler, match2, queue[ 1 ], match2_len );
  expect_memory( mock_simple_flow_removed_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_flow_removed_handler( mock_simple_flow_removed_handler, USER_DATA );
  handle_flow_removed( DATAPATH_ID, buffer );

  delete_oxm_matches(match);
  free_buffer( buffer );
}


static void
test_handle_flow_removed_if_handler_is_not_registered() {
  uint64_t cookie = 0x1111222233334444;
  uint16_t priority = UINT16_MAX;
  uint8_t reason =  OFPRR_IDLE_TIMEOUT;
  uint8_t table_id = 0xAA;
  uint32_t duration_sec = 180;
  uint32_t duration_nsec = 10000;
  uint16_t idle_timeout = 60;
  uint16_t hard_timeout = 120;
  uint64_t packet_count = 1000;
  uint64_t byte_count = 100000;
  oxm_matches *match;
  size_t match1_len, match2_len;
  oxm_match_header *queue[ 2 ];
  uint32_t* value;
  
  match1_len = ( sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_IN_PORT ) );
  queue[ 0 ] = xcalloc( 1, match1_len );
  value = ( uint32_t* ) (queue[ 0 ] + 1);
  *queue[ 0 ] = OXM_OF_IN_PORT;
  *value = 0x2468ACEF;
    
  match2_len = ( sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_IN_PHY_PORT ) );
  queue[ 1 ] = xcalloc( 1, match2_len );
  value = ( uint32_t* ) (queue[ 1 ] + 1);
  *queue[ 1 ] = OXM_OF_IN_PHY_PORT;
  *value = 0xFECA8642;

  match = create_oxm_matches();
  match->n_matches = 2;
  append_to_tail( &match->list, queue[ 0 ] );
  append_to_tail( &match->list, queue[ 1 ] );

  buffer *buffer;
  buffer = create_flow_removed(
    TRANSACTION_ID,
    cookie,
    priority,
    reason,
    table_id,
    duration_sec,
    duration_nsec,
    idle_timeout,
    hard_timeout,
    packet_count,
    byte_count,
    match
  );

  // FIXME
  handle_flow_removed( DATAPATH_ID, buffer );

  delete_oxm_matches(match);
  free_buffer( buffer );
}


static void
test_handle_flow_removed_if_message_is_NULL() {
  set_flow_removed_handler( mock_flow_removed_handler, USER_DATA );
  expect_assert_failure( handle_flow_removed( DATAPATH_ID, NULL ) );
}


static void
test_handle_flow_removed_if_message_length_is_zero() {
  buffer *buffer;

  buffer = alloc_buffer_with_length( 32 );

  set_flow_removed_handler( mock_flow_removed_handler, USER_DATA );
  expect_assert_failure( handle_flow_removed( DATAPATH_ID, buffer ) );

  free_buffer( buffer );
}


/********************************************************************************
 * handle_port_status() tests.
 ********************************************************************************/

static void
test_handle_port_status() {
  uint8_t reason = OFPPR_MODIFY;
  buffer *buffer;
  struct ofp_port desc;

  desc.port_no = 1;
  memset( desc.pad, 0, sizeof( desc.pad ) );
  memcpy( desc.hw_addr, MAC_ADDR_X, sizeof( desc.hw_addr ) );
  memset( desc.pad2, 0, sizeof( desc.pad2 ) );
  memset( desc.name, '\0', OFP_MAX_PORT_NAME_LEN );
  memcpy( desc.name, PORT_NAME, strlen( PORT_NAME ) );
  desc.config = OFPPC_PORT_DOWN;
  desc.state = OFPPS_LINK_DOWN;
  desc.curr = ( OFPPF_1GB_FD | OFPPF_COPPER | OFPPF_PAUSE );
  desc.advertised = PORT_FEATURES;
  desc.supported = PORT_FEATURES;
  desc.peer = PORT_FEATURES;
  desc.curr_speed = 0x1024;
  desc.max_speed = 0x2048;

  buffer = create_port_status( TRANSACTION_ID, reason, desc );

  expect_memory( mock_port_status_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_port_status_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_port_status_handler, reason32, ( uint32_t ) reason );
  expect_memory( mock_port_status_handler, &desc, &desc, sizeof( struct ofp_port ) );
  expect_memory( mock_port_status_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_port_status_handler( mock_port_status_handler, USER_DATA );
  handle_port_status( DATAPATH_ID, buffer );

  free_buffer( buffer );
}


static void
test_handle_port_status_if_handler_is_not_registered() {
  uint8_t reason = OFPPR_MODIFY;
  buffer *buffer;
  struct ofp_port desc;

  desc.port_no = 1;
  memset( desc.pad, 0, sizeof( desc.pad ) );
  memcpy( desc.hw_addr, MAC_ADDR_X, sizeof( desc.hw_addr ) );
  memset( desc.pad2, 0, sizeof( desc.pad2 ) );
  memset( desc.name, '\0', OFP_MAX_PORT_NAME_LEN );
  memcpy( desc.name, PORT_NAME, strlen( PORT_NAME ) );
  desc.config = OFPPC_PORT_DOWN;
  desc.state = OFPPS_LINK_DOWN;
  desc.curr = ( OFPPF_1GB_FD | OFPPF_COPPER | OFPPF_PAUSE );
  desc.advertised = PORT_FEATURES;
  desc.supported = PORT_FEATURES;
  desc.peer = PORT_FEATURES;
  desc.curr_speed = 0x1024;
  desc.max_speed = 0x2048;

  buffer = create_port_status( TRANSACTION_ID, reason, desc );

  // FIXME

  handle_port_status( DATAPATH_ID, buffer );

  free_buffer( buffer );
}


static void
test_handle_port_status_if_message_is_NULL() {
  set_port_status_handler( mock_port_status_handler, USER_DATA );
  expect_assert_failure( handle_port_status( DATAPATH_ID, NULL ) );
}


static void
test_handle_port_status_if_message_length_is_zero() {
  buffer *buffer;

  buffer = alloc_buffer_with_length( 32 );

  set_port_status_handler( mock_port_status_handler, USER_DATA );
  expect_assert_failure( handle_port_status( DATAPATH_ID, buffer ) );

  free_buffer( buffer );
}


/********************************************************************************
 * handle_multipart_reply() tests.
 ********************************************************************************/

static void
test_handle_multipart_reply_if_type_is_OFPMP_DESC() {
  char mfr_desc[ DESC_STR_LEN ];
  char hw_desc[ DESC_STR_LEN ];
  char sw_desc[ DESC_STR_LEN ];
  char serial_num[ SERIAL_NUM_LEN ];
  char dp_desc[ DESC_STR_LEN ];
  uint16_t flags = 0;
  uint32_t body_len;
  buffer *buffer;
  struct ofp_multipart_reply *multipart_reply;

  memset( mfr_desc, '\0', DESC_STR_LEN );
  memset( hw_desc, '\0', DESC_STR_LEN );
  memset( sw_desc, '\0', DESC_STR_LEN );
  memset( serial_num, '\0', SERIAL_NUM_LEN );
  memset( dp_desc, '\0', DESC_STR_LEN );
  sprintf( mfr_desc, "NEC Coporation" );
  sprintf( hw_desc, "OpenFlow Switch Hardware" );
  sprintf( sw_desc, "OpenFlow Switch Software" );
  sprintf( serial_num, "123456" );
  sprintf( dp_desc, "Datapath 0" );

  buffer = create_desc_multipart_reply( TRANSACTION_ID, flags, mfr_desc, hw_desc,
                                    sw_desc, serial_num, dp_desc );

  multipart_reply = buffer->data;
  body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                            offsetof( struct ofp_multipart_reply, body ) );

  expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_reply_handler, type32, OFPMP_DESC );
  expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_reply_handler, data->length, body_len );
  expect_memory( mock_multipart_reply_handler, data->data, multipart_reply->body, body_len );
  expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
  handle_multipart_reply( DATAPATH_ID, buffer );

  free_buffer( buffer );
}


static void
test_handle_multipart_reply_if_type_is_OFPMP_FLOW() {
  void *expected_data;
  uint16_t flags = OFPMPF_REPLY_MORE;
  list_element *expected_list;
  buffer *buffer;
  uint16_t stats_len = 0;
  uint32_t body_len;
  struct ofp_multipart_reply *multipart_reply;
  struct ofp_flow_stats *expected_stats[ 2 ];
  struct ofp_instruction *inst;

  // with match
  {
    create_oxm_match_testdata();
    create_instruction_testdata();

    stats_len = ( uint16_t ) ( offsetof( struct ofp_flow_stats, match ) + expected_ofp_match_len + expected_ofp_instruction_len );

    expected_stats[ 0 ] = xcalloc( 1, stats_len );
    expected_stats[ 1 ] = xcalloc( 1, stats_len );

    expected_stats[ 0 ]->length = stats_len;
    expected_stats[ 0 ]->table_id = 1;
    expected_stats[ 0 ]->pad = 0;
    expected_stats[ 0 ]->duration_sec = 60;
    expected_stats[ 0 ]->duration_nsec = 10000;
    expected_stats[ 0 ]->priority = 1024;
    expected_stats[ 0 ]->idle_timeout = 60;
    expected_stats[ 0 ]->hard_timeout = 3600;
    expected_stats[ 0 ]->flags = OFPFF_NO_BYT_COUNTS;
    memset( expected_stats[ 0 ]->pad2, 0, sizeof( expected_stats[ 0 ]->pad2 ) );
    expected_stats[ 0 ]->cookie = 0x0102030405060708ULL;
    expected_stats[ 0 ]->packet_count = 1000;
    expected_stats[ 0 ]->byte_count = 100000;
    memcpy( &expected_stats[ 0 ]->match, expected_ofp_match, expected_ofp_match_len );
    inst = ( struct ofp_instruction * ) ( ( char * ) &expected_stats[ 0 ]->match + expected_ofp_match_len );
    memcpy( inst, expected_ofp_instruction, expected_ofp_instruction_len );

    memcpy( expected_stats[ 1 ], expected_stats[ 0 ], stats_len );
    expected_stats[ 1 ]->cookie = 0x0203040506070809ULL;

    create_list( &expected_list );
    append_to_tail( &expected_list, expected_stats[ 0 ] );
    append_to_tail( &expected_list, expected_stats[ 1 ] );

    expected_data = xcalloc( 1, ( size_t ) ( stats_len * 2 ) );
    memcpy( expected_data, expected_stats[ 0 ], stats_len );
    memcpy( ( char * ) expected_data + stats_len, expected_stats[ 1 ], stats_len );

    buffer = create_flow_multipart_reply( TRANSACTION_ID, flags, expected_list );

    multipart_reply = buffer->data;
    body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                              offsetof( struct ofp_multipart_reply, body ) );

    expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_reply_handler, type32, OFPMP_FLOW );
    expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_reply_handler, data->length, body_len );
    expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
    expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
    handle_multipart_reply( DATAPATH_ID, buffer );

    xfree( expected_stats[ 0 ] );
    xfree( expected_stats[ 1 ] );
    delete_list( expected_list );

    delete_oxm_match_testdata();
    delete_instruction_testdata();
    free_buffer( buffer );
    xfree( expected_data );
  }
}


static void
test_handle_multipart_reply_if_type_is_OFPMP_AGGREGATE() {
  uint16_t flags = 0;
  uint32_t body_len;
  uint32_t flow_count = 1000;
  uint64_t packet_count = 1000;
  uint64_t byte_count = 10000;
  buffer *buffer;
  struct ofp_multipart_reply *multipart_reply;
  struct ofp_aggregate_stats_reply aggregate_multipart_reply;

  buffer = create_aggregate_multipart_reply( TRANSACTION_ID, flags, packet_count,
                                             byte_count, flow_count );

  multipart_reply = buffer->data;
  body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                            offsetof( struct ofp_multipart_reply, body ) );

  expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_reply_handler, type32, OFPMP_AGGREGATE );
  expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_reply_handler, data->length, body_len );
  ntoh_aggregate_stats( &aggregate_multipart_reply,
                        ( struct ofp_aggregate_stats_reply * ) multipart_reply->body );
  expect_memory( mock_multipart_reply_handler, data->data, &aggregate_multipart_reply, body_len );
  expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
  handle_multipart_reply( DATAPATH_ID, buffer );

  free_buffer( buffer );
}


static void
test_handle_multipart_reply_if_type_is_OFPMP_TABLE() {
  void *expected_data;
  uint16_t flags = OFPMPF_REPLY_MORE;
  uint16_t stats_len;
  uint32_t body_len;
  buffer *buffer;
  list_element *table_stats;
  struct ofp_multipart_reply *multipart_reply;
  struct ofp_table_stats *stats[ 2 ];

  stats_len = sizeof( struct ofp_table_stats );

  stats[ 0 ] = xcalloc( 1, stats_len );
  stats[ 1 ] = xcalloc( 1, stats_len );

  stats[ 0 ]->table_id = 1;
  memset( stats[ 0 ]->pad, 0, sizeof( stats[ 0 ]->pad ));
  stats[ 0 ]->active_count = 1000;
  stats[ 0 ]->lookup_count = 100000;
  stats[ 0 ]->matched_count = 10000;

  memcpy( stats[ 1 ], stats[ 0 ], stats_len );
  stats[ 1 ]->table_id = 2;

  create_list( &table_stats );
  append_to_tail( &table_stats, stats[ 0 ] );
  append_to_tail( &table_stats, stats[ 1 ] );

  expected_data = xcalloc( 1, ( size_t ) ( stats_len * 2 ) );
  memcpy( expected_data, stats[ 0 ], stats_len );
  memcpy( ( char * ) expected_data + stats_len, stats[ 1 ], stats_len );

  buffer = create_table_multipart_reply( TRANSACTION_ID, flags, table_stats );

  multipart_reply = buffer->data;
  body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                            offsetof( struct ofp_multipart_reply, body ) );

  expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_reply_handler, type32, OFPMP_TABLE );
  expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_reply_handler, data->length, body_len );
  expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
  expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
  handle_multipart_reply( DATAPATH_ID, buffer );

  xfree( stats[ 0 ] );
  xfree( stats[ 1 ] );
  delete_list( table_stats );
  xfree( expected_data );
  free_buffer( buffer );
}


static void
test_handle_multipart_reply_if_type_is_OFPMP_PORT_STATS() {
  void *expected_data;
  uint16_t flags = OFPMPF_REPLY_MORE;
  uint16_t stats_len;
  uint32_t body_len;
  buffer *buffer;
  list_element *port_stats;
  struct ofp_multipart_reply *multipart_reply;
  struct ofp_port_stats *stats[ 2 ];

  stats_len = sizeof( struct ofp_port_stats );

  stats[ 0 ] = xcalloc( 1, stats_len );
  stats[ 1 ] = xcalloc( 1, stats_len );

  stats[ 0 ]->port_no = 1;
  memset( stats[ 0 ]->pad, 0, sizeof( stats[ 0 ]->pad ));
  stats[ 0 ]->rx_packets = 10000;
  stats[ 0 ]->tx_packets = 20000;
  stats[ 0 ]->rx_bytes = 30000;
  stats[ 0 ]->tx_bytes = 40000;
  stats[ 0 ]->rx_dropped = 50000;
  stats[ 0 ]->tx_dropped = 60000;
  stats[ 0 ]->rx_errors = 70000;
  stats[ 0 ]->tx_errors = 80000;
  stats[ 0 ]->rx_frame_err = 1;
  stats[ 0 ]->rx_over_err = 2;
  stats[ 0 ]->rx_crc_err = 1;
  stats[ 0 ]->collisions = 3;
  stats[ 0 ]->duration_sec = 10;
  stats[ 0 ]->duration_nsec = 100;

  memcpy( stats[ 1 ], stats[ 0 ], stats_len );
  stats[ 1 ]->port_no = 2;

  create_list( &port_stats );
  append_to_tail( &port_stats, stats[ 0 ] );
  append_to_tail( &port_stats, stats[ 1 ] );

  expected_data = xcalloc( 1, ( size_t ) ( stats_len * 2 ) );
  memcpy( expected_data, stats[ 0 ], stats_len );
  memcpy( ( char * ) expected_data + stats_len, stats[ 1 ], stats_len );

  buffer = create_port_multipart_reply( TRANSACTION_ID, flags, port_stats );

  multipart_reply = buffer->data;
  body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                            offsetof( struct ofp_multipart_reply, body ) );

  expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_reply_handler, type32, OFPMP_PORT_STATS );
  expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_reply_handler, data->length, body_len );
  expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
  expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
  handle_multipart_reply( DATAPATH_ID, buffer );

  xfree( stats[ 0 ] );
  xfree( stats[ 1 ] );
  delete_list( port_stats );
  xfree( expected_data );
  free_buffer( buffer );
}


static void
test_handle_multipart_reply_if_type_is_OFPMP_QUEUE() {
  void *expected_data;
  uint16_t flags = OFPMPF_REPLY_MORE;
  uint16_t stats_len;
  uint32_t body_len;
  buffer *buffer;
  list_element *queue_stats;
  struct ofp_multipart_reply *multipart_reply;
  struct ofp_queue_stats *stats[ 2 ];

  stats_len = sizeof( struct ofp_queue_stats );

  stats[ 0 ] = xcalloc( 1, stats_len );
  stats[ 1 ] = xcalloc( 1, stats_len );

  stats[ 0 ]->port_no = 1;
  stats[ 0 ]->queue_id = 2;
  stats[ 0 ]->tx_bytes = 100000;
  stats[ 0 ]->tx_packets = 60000;
  stats[ 0 ]->tx_errors = 80;
  stats[ 0 ]->duration_sec = 10;
  stats[ 0 ]->duration_nsec = 100;

  memcpy( stats[ 1 ], stats[ 0 ], stats_len );
  stats[ 1 ]->queue_id = 3;

  create_list( &queue_stats );
  append_to_tail( &queue_stats, stats[ 0 ] );
  append_to_tail( &queue_stats, stats[ 1 ] );

  expected_data = xcalloc( 1, ( size_t ) ( stats_len * 2 ) );
  memcpy( expected_data, stats[ 0 ], stats_len );
  memcpy( ( char * ) expected_data + stats_len, stats[ 1 ], stats_len );

  buffer = create_queue_multipart_reply( TRANSACTION_ID, flags, queue_stats );

  multipart_reply = buffer->data;
  body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                            offsetof( struct ofp_multipart_reply, body ) );

  expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_reply_handler, type32, OFPMP_QUEUE );
  expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_reply_handler, data->length, body_len );
  expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
  expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
  handle_multipart_reply( DATAPATH_ID, buffer );

  xfree( stats[ 0 ] );
  xfree( stats[ 1 ] );
  delete_list( queue_stats );
  xfree( expected_data );
  free_buffer( buffer );
}


static void
test_handle_multipart_reply_if_type_is_OFPMP_GROUP() {
  void *expected_data;
  uint16_t flags = OFPMPF_REPLY_MORE;
  uint16_t stats_len;
  uint32_t body_len;
  size_t grpsts_0len, grpsts_1len;
  list_element *list;
  buffer *buffer;
  struct ofp_group_stats *grpsts[ 2 ];
  struct ofp_bucket_counter *bktcnt;
  struct ofp_multipart_reply *multipart_reply;

  grpsts_0len = offsetof( struct ofp_group_stats, bucket_stats ) + sizeof( struct ofp_bucket_counter );
  grpsts_1len = offsetof( struct ofp_group_stats, bucket_stats ) + sizeof( struct ofp_bucket_counter );

  stats_len = ( uint16_t ) ( grpsts_0len + grpsts_1len );

  grpsts[ 0 ] = xcalloc( 1, grpsts_0len );
  grpsts[ 1 ] = xcalloc( 1, grpsts_1len );

  grpsts[ 0 ]->length = ( uint16_t ) grpsts_0len;
  grpsts[ 0 ]->group_id = 1;
  grpsts[ 0 ]->ref_count = 2;
  grpsts[ 0 ]->packet_count = 3;
  grpsts[ 0 ]->byte_count = 4;
  grpsts[ 0 ]->duration_sec = 5;
  grpsts[ 0 ]->duration_nsec = 6;
  bktcnt = ( struct ofp_bucket_counter * ) grpsts[ 0 ]->bucket_stats;
  bktcnt->packet_count = 7;
  bktcnt->byte_count = 8;

  grpsts[ 1 ]->length = ( uint16_t ) grpsts_1len;
  grpsts[ 1 ]->group_id = 11;
  grpsts[ 1 ]->ref_count = 12;
  grpsts[ 1 ]->packet_count = 13;
  grpsts[ 1 ]->byte_count = 14;
  grpsts[ 1 ]->duration_sec = 15;
  grpsts[ 1 ]->duration_nsec = 16;
  bktcnt = ( struct ofp_bucket_counter * ) grpsts[ 1 ]->bucket_stats;
  bktcnt->packet_count = 17;
  bktcnt->byte_count = 18;

  create_list( &list );
  append_to_tail( &list, grpsts[ 0 ] );
  append_to_tail( &list, grpsts[ 1 ] );

  expected_data = xcalloc( 1, ( size_t ) ( grpsts_0len + grpsts_1len ) );
  memcpy( expected_data, grpsts[ 0 ], grpsts_0len );
  memcpy( ( char * ) expected_data + grpsts_0len, grpsts[ 1 ], grpsts_1len );

  buffer = create_group_multipart_reply( TRANSACTION_ID, flags, list );

  multipart_reply = buffer->data;
  body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                            offsetof( struct ofp_multipart_reply, body ) );

  expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_reply_handler, type32, OFPMP_GROUP );
  expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_reply_handler, data->length, body_len );
  expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
  expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
  handle_multipart_reply( DATAPATH_ID, buffer );

  xfree( grpsts[ 0 ] );
  xfree( grpsts[ 1 ] );
  delete_list( list );
  xfree( expected_data );
  free_buffer( buffer );
}


static void
test_handle_multipart_reply_if_type_is_OFPMP_GROUP_DESC() {
  void *expected_data;
  uint16_t flags = OFPMPF_REPLY_MORE;
  uint16_t stats_len;
  uint32_t body_len;
  uint16_t grpdsc_len[2];
  buffer *buffer;
  list_element *expected_list;
  struct ofp_group_desc_stats *dsc1, *dsc2;
  struct ofp_multipart_reply *multipart_reply;

  create_bucket_testdata();

  grpdsc_len[0] = ( uint16_t ) ( offsetof( struct ofp_group_desc_stats, buckets ) + bucket_testdata_len[0] );
  dsc1 = xcalloc( 1, grpdsc_len[0] );
  dsc1->length = grpdsc_len[0];
  dsc1->type = OFPGT_SELECT;
  dsc1->group_id = 0x11223344;
  memcpy( dsc1->buckets, bucket_testdata[0], bucket_testdata_len[0] );

  grpdsc_len[1] = ( uint16_t ) ( offsetof( struct ofp_group_desc_stats, buckets ) + bucket_testdata_len[1] );
  dsc2 = xcalloc( 1, grpdsc_len[1] );
  dsc2->length = grpdsc_len[1];
  dsc2->type = OFPGT_INDIRECT;
  dsc2->group_id = 0x55667788;
  memcpy( dsc2->buckets, bucket_testdata[1], bucket_testdata_len[1] );

  stats_len = ( uint16_t ) ( grpdsc_len[0] + grpdsc_len[1] );

  create_list( &expected_list );
  append_to_tail( &expected_list, dsc1 );
  append_to_tail( &expected_list, dsc2 );

  expected_data = xcalloc( 1, ( size_t ) ( stats_len ) );
  memcpy( expected_data, dsc1, grpdsc_len[0] );
  memcpy( ( char * ) expected_data + grpdsc_len[0], dsc2, grpdsc_len[1] );

  buffer = create_group_desc_multipart_reply( TRANSACTION_ID, flags, expected_list );

  multipart_reply = buffer->data;
  body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                            offsetof( struct ofp_multipart_reply, body ) );

  expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_reply_handler, type32, OFPMP_GROUP_DESC );
  expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_reply_handler, data->length, body_len );
  expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
  expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
  handle_multipart_reply( DATAPATH_ID, buffer );

  delete_bucket_testdata();
  xfree( dsc1 );
  xfree( dsc2 );
  delete_list( expected_list );
  xfree( expected_data );
  free_buffer( buffer );
}


static void
test_handle_multipart_reply_if_type_is_OFPMP_GROUP_FEATURES() {
  void *expected_data;
  uint16_t flags = OFPMPF_REPLY_MORE;
  uint16_t stats_len;
  uint32_t body_len;
  buffer *buffer;
  struct ofp_group_features *grpftr;
  struct ofp_multipart_reply *multipart_reply;

  uint16_t grpftr_len = sizeof( struct ofp_group_features );

  stats_len = grpftr_len;

  grpftr = xcalloc( 1, grpftr_len );
  grpftr->types = OFPGT_SELECT;
  grpftr->capabilities = OFPGFC_CHAINING;
  grpftr->max_groups[0] = 1;
  grpftr->max_groups[1] = 2;
  grpftr->max_groups[2] = 3;
  grpftr->max_groups[3] = 4;
  grpftr->actions[0] = 5;
  grpftr->actions[1] = 6;
  grpftr->actions[2] = 7;
  grpftr->actions[3] = 8;

  buffer = create_group_features_multipart_reply( TRANSACTION_ID, flags, grpftr->types,
    grpftr->capabilities, grpftr->max_groups, grpftr->actions );

  expected_data = grpftr;

  multipart_reply = buffer->data;
  body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                            offsetof( struct ofp_multipart_reply, body ) );

  expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_reply_handler, type32, OFPMP_GROUP_FEATURES );
  expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_reply_handler, data->length, body_len );
  expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
  expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
  handle_multipart_reply( DATAPATH_ID, buffer );

  xfree( expected_data );
  free_buffer( buffer );
}


static void
test_handle_multipart_reply_if_type_is_OFPMP_METER() {
  void *expected_data;
  uint16_t flags = OFPMPF_REPLY_MORE;
  uint16_t stats_len;
  uint32_t body_len;
  uint16_t mtrsts_len[2];
  buffer *buffer;
  list_element *expected_list;
  struct ofp_meter_stats *mtr1, *mtr2;
  struct ofp_meter_band_stats *mtrbnd;
  struct ofp_multipart_reply *multipart_reply;

  mtrsts_len[0] = ( uint16_t ) ( offsetof( struct ofp_meter_stats, band_stats ) + sizeof( struct ofp_meter_band_stats ) );
  mtr1 = xcalloc( 1, mtrsts_len[0] );
  mtr1->meter_id = 0xaabbccdd;
  mtr1->len = mtrsts_len[0];
  mtr1->flow_count = 1;
  mtr1->packet_in_count = 2;
  mtr1->byte_in_count = 3;
  mtr1->duration_sec = 4;
  mtr1->duration_nsec = 5;
  mtrbnd = mtr1->band_stats;
  mtrbnd->packet_band_count = 0x11223344;
  mtrbnd->byte_band_count = 0x55667788;

  mtrsts_len[1] = ( uint16_t ) ( offsetof( struct ofp_meter_stats, band_stats ) + sizeof( struct ofp_meter_band_stats ) );
  mtr2 = xcalloc( 1, mtrsts_len[1] );
  mtr2->meter_id = 0x12345566;
  mtr2->len = mtrsts_len[1];
  mtr2->flow_count = 1;
  mtr2->packet_in_count = 2;
  mtr2->byte_in_count = 3;
  mtr2->duration_sec = 4;
  mtr2->duration_nsec = 5;
  mtrbnd = mtr2->band_stats;
  mtrbnd->packet_band_count = 0x11223344;
  mtrbnd->byte_band_count = 0x55667788;

  stats_len = ( uint16_t ) ( mtrsts_len[0] + mtrsts_len[1] );

  create_list( &expected_list );
  append_to_tail( &expected_list, mtr1 );
  append_to_tail( &expected_list, mtr2 );

  expected_data = xcalloc( 1, ( size_t ) ( stats_len ) );
  memcpy( expected_data, mtr1, mtrsts_len[0] );
  memcpy( ( char * ) expected_data + mtrsts_len[0], mtr2, mtrsts_len[1] );

  buffer = create_meter_multipart_reply( TRANSACTION_ID, flags, expected_list );

  multipart_reply = buffer->data;
  body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                            offsetof( struct ofp_multipart_reply, body ) );

  expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_reply_handler, type32, OFPMP_METER );
  expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_reply_handler, data->length, body_len );
  expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
  expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
  handle_multipart_reply( DATAPATH_ID, buffer );

  xfree( mtr1 );
  xfree( mtr2 );
  delete_list( expected_list );
  xfree( expected_data );
  free_buffer( buffer );
}


static void
test_handle_multipart_reply_if_type_is_OFPMP_METER_CONFIG() {
  void *expected_data;
  uint16_t flags = OFPMPF_REPLY_MORE;
  uint16_t stats_len;
  uint32_t body_len;
  uint16_t mtrcfg_len[2];
  buffer *buffer;
  list_element *expected_list;
  struct ofp_meter_config *mtr1, *mtr2;
  struct ofp_meter_band_drop *mtrbnd;
  struct ofp_multipart_reply *multipart_reply;

  mtrcfg_len[0] = ( uint16_t ) ( offsetof( struct ofp_meter_config, bands ) + sizeof( struct ofp_meter_band_drop ) );
  mtr1 = xcalloc( 1, mtrcfg_len[0] );
  mtr1->length = mtrcfg_len[0];
  mtr1->flags = OFPMC_MODIFY;
  mtr1->meter_id = 1;
  mtrbnd = ( struct ofp_meter_band_drop * ) mtr1->bands;
  mtrbnd->type = OFPMBT_DROP;
  mtrbnd->len = sizeof( struct ofp_meter_band_drop );
  mtrbnd->rate = 0x11223344;
  mtrbnd->burst_size = 0x55667788;

  mtrcfg_len[1] = ( uint16_t ) ( offsetof( struct ofp_meter_config, bands ) + sizeof( struct ofp_meter_band_drop ) );
  mtr2 = xcalloc( 1, mtrcfg_len[1] );
  mtr2->length = mtrcfg_len[1];
  mtr2->flags = OFPMC_DELETE;
  mtr2->meter_id = 1;
  mtrbnd = ( struct ofp_meter_band_drop * ) mtr2->bands;
  mtrbnd->type = OFPMBT_DROP;
  mtrbnd->len = sizeof( struct ofp_meter_band_drop );
  mtrbnd->rate = 0x12345555;
  mtrbnd->burst_size = 0x56789999;

  stats_len = ( uint16_t ) ( mtrcfg_len[0] + mtrcfg_len[1] );

  create_list( &expected_list );
  append_to_tail( &expected_list, mtr1 );
  append_to_tail( &expected_list, mtr2 );

  expected_data = xcalloc( 1, ( size_t ) ( stats_len ) );
  memcpy( expected_data, mtr1, mtrcfg_len[0] );
  memcpy( ( char * ) expected_data + mtrcfg_len[0], mtr2, mtrcfg_len[1] );

  buffer = create_meter_config_multipart_reply( TRANSACTION_ID, flags, expected_list );

  multipart_reply = buffer->data;
  body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                            offsetof( struct ofp_multipart_reply, body ) );

  expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_reply_handler, type32, OFPMP_METER_CONFIG );
  expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_reply_handler, data->length, body_len );
  expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
  expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
  handle_multipart_reply( DATAPATH_ID, buffer );

  xfree( mtr1 );
  xfree( mtr2 );
  delete_list( expected_list );
  xfree( expected_data );
  free_buffer( buffer );
}


static void
test_handle_multipart_reply_if_type_is_OFPMP_METER_FEATURES() {
  void *expected_data;
  uint16_t flags = OFPMPF_REPLY_MORE;
  uint16_t stats_len;
  uint32_t body_len;
  buffer *buffer;
  struct ofp_multipart_reply *multipart_reply;
  struct ofp_meter_features *mtrftr;

  stats_len = sizeof( struct ofp_meter_features );
  mtrftr = xcalloc( 1, stats_len );
  mtrftr->max_meter = 1;
  mtrftr->band_types = OFPMBT_DROP;
  mtrftr->capabilities = OFPMF_KBPS;
  mtrftr->max_bands = 10;
  mtrftr->max_color = 20;
  memset( mtrftr->pad, 0, sizeof( mtrftr->pad ) );

  buffer = create_meter_features_multipart_reply( TRANSACTION_ID, flags, mtrftr->max_meter,
    mtrftr->band_types, mtrftr->capabilities, mtrftr->max_bands, mtrftr->max_color );

  expected_data = mtrftr;

  multipart_reply = buffer->data;
  body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                            offsetof( struct ofp_multipart_reply, body ) );

  expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_reply_handler, type32, OFPMP_METER_FEATURES );
  expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_reply_handler, data->length, body_len );
  expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
  expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
  handle_multipart_reply( DATAPATH_ID, buffer );

  xfree( expected_data );
  free_buffer( buffer );
}


static void
test_handle_multipart_reply_if_type_is_OFPMP_TABLE_FEATURES() {
  void *expected_data;
  uint16_t flags = OFPMPF_REPLY_MORE;
  uint16_t stats_len;
  uint32_t body_len;
  buffer *buffer;
  list_element *table_ftr_stats;
  struct ofp_multipart_reply *multipart_reply;
  struct ofp_table_features *stats[ 2 ];
  char name[OFP_MAX_TABLE_NAME_LEN] = "TableName";

  stats_len = sizeof( struct ofp_table_features );

  stats[ 0 ] = xcalloc( 1, stats_len );
  stats[ 1 ] = xcalloc( 1, stats_len );

  stats[ 0 ]->length = ( uint16_t ) sizeof( struct ofp_table_features );
  stats[ 0 ]->table_id = 1;
  memset( stats[ 0 ]->pad, 0, sizeof( stats[ 0 ]->pad ) );
  memcpy( stats[ 0 ]->name, name, sizeof( name ) );
  stats[ 0 ]->metadata_match = 0x1111222233334444;
  stats[ 0 ]->metadata_write = 0x5555666677778888;
  stats[ 0 ]->config = 0x12345678;
  stats[ 0 ]->max_entries = 0xAABBCCDD;

  memcpy( stats[ 1 ], stats[ 0 ], stats_len );
  stats[ 1 ]->table_id = 2;

  create_list( &table_ftr_stats );
  append_to_tail( &table_ftr_stats, stats[ 0 ] );
  append_to_tail( &table_ftr_stats, stats[ 1 ] );

  expected_data = xcalloc( 1, ( size_t ) ( stats_len * 2 ) );
  memcpy( expected_data, stats[ 0 ], stats_len );
  memcpy( ( char * ) expected_data + stats_len, stats[ 1 ], stats_len );

  buffer = create_table_features_multipart_reply( TRANSACTION_ID, flags, table_ftr_stats );

  multipart_reply = buffer->data;
  body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                            offsetof( struct ofp_multipart_reply, body ) );

  expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_reply_handler, type32, OFPMP_TABLE_FEATURES );
  expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_reply_handler, data->length, body_len );
  expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
  expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
  handle_multipart_reply( DATAPATH_ID, buffer );

  xfree( stats[ 0 ] );
  xfree( stats[ 1 ] );
  delete_list( table_ftr_stats );
  xfree( expected_data );
  free_buffer( buffer );
}


static void
test_handle_multipart_reply_if_type_is_OFPMP_PORT_DESC() {
  void *expected_data;
  uint16_t flags = OFPMPF_REPLY_MORE;
  uint16_t stats_len;
  uint32_t body_len;
  buffer *buffer;
  list_element *port_desc_stats;
  struct ofp_multipart_reply *multipart_reply;
  struct ofp_port *stats[ 2 ];
  char name[OFP_MAX_PORT_NAME_LEN] = "PortName";

  stats_len = sizeof( struct ofp_port );

  stats[ 0 ] = xcalloc( 1, stats_len );
  stats[ 1 ] = xcalloc( 1, stats_len );

  stats[ 0 ]->port_no = 1;
  memset( stats[ 0 ]->pad, 0, sizeof( stats[ 0 ]->pad ) );
  memcpy( stats[ 0 ]->hw_addr, MAC_ADDR_X, sizeof( OFP_ETH_ALEN ) );
  memset( stats[ 0 ]->pad2, 0, sizeof( stats[ 0 ]->pad2 ) );
  memcpy( stats[ 0 ]->name, name, sizeof( name ) );
  stats[ 0 ]->config = OFPPC_PORT_DOWN;
  stats[ 0 ]->state = OFPPS_BLOCKED;
  stats[ 0 ]->curr = 0x12345678;
  stats[ 0 ]->advertised = 0x9ABCDEF0;
  stats[ 0 ]->supported = 0xFEDCBA90;
  stats[ 0 ]->peer = 0x87654321;
  stats[ 0 ]->curr_speed = 0x11223344;
  stats[ 0 ]->max_speed = 0xAABBCCDD;

  memcpy( stats[ 1 ], stats[ 0 ], stats_len );
  stats[ 1 ]->port_no = 2;

  create_list( &port_desc_stats );
  append_to_tail( &port_desc_stats, stats[ 0 ] );
  append_to_tail( &port_desc_stats, stats[ 1 ] );

  expected_data = xcalloc( 1, ( size_t ) ( stats_len * 2 ) );
  memcpy( expected_data, stats[ 0 ], stats_len );
  memcpy( ( char * ) expected_data + stats_len, stats[ 1 ], stats_len );

  buffer = create_port_desc_multipart_reply( TRANSACTION_ID, flags, port_desc_stats );

  multipart_reply = buffer->data;
  body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                            offsetof( struct ofp_multipart_reply, body ) );

  expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_reply_handler, type32, OFPMP_PORT_DESC );
  expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_reply_handler, data->length, body_len );
  expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
  expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
  handle_multipart_reply( DATAPATH_ID, buffer );

  xfree( stats[ 0 ] );
  xfree( stats[ 1 ] );
  delete_list( port_desc_stats );
  xfree( expected_data );
  free_buffer( buffer );
}


static void
test_handle_multipart_reply_if_type_is_OFPMP_EXPERIMENTER() {
  void *expected_data;
  uint16_t flags = 0;
  uint16_t stats_len;
  uint32_t body_len;
  uint32_t experimenter = VENDOR_ID;
  uint32_t exp_type = 1;
  buffer *body, *experimenter_multipart_reply;
  struct ofp_multipart_reply *multipart_reply;
  struct ofp_experimenter_multipart_header *stats;

  body = alloc_buffer_with_length( 128 );
  append_back_buffer( body, 128 );
  memset( body->data, 0xa1, body->length );
  experimenter_multipart_reply = create_experimenter_multipart_reply( TRANSACTION_ID, flags, experimenter, exp_type, body );

  stats_len = ( uint16_t ) ( sizeof( struct ofp_experimenter_multipart_header ) + body->length );

  expected_data = xcalloc( 1, ( size_t ) stats_len );
  stats = ( struct ofp_experimenter_multipart_header * ) expected_data;
  stats->experimenter = experimenter;
  stats->exp_type = exp_type;
  memcpy( stats + 1, body->data, body->length );

  multipart_reply = experimenter_multipart_reply->data;
  body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                            offsetof( struct ofp_multipart_reply, body ) );

  expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_reply_handler, type32, OFPMP_EXPERIMENTER );
  expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_reply_handler, data->length, body_len );
  expect_memory( mock_multipart_reply_handler, data->data, expected_data, body_len );
  expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
  handle_multipart_reply( DATAPATH_ID, experimenter_multipart_reply );

  xfree( expected_data );
  free_buffer( body );
  free_buffer( experimenter_multipart_reply );
}


static void
test_handle_multipart_reply_with_undefined_type() {
  void *expected_data;
  uint16_t flags = 0;
  uint16_t stats_len;
  uint32_t experimenter = VENDOR_ID;
  uint32_t exp_type = 1;
  buffer *body, *experimenter_multipart_reply;
  struct ofp_multipart_reply *multipart_reply;
  struct ofp_experimenter_multipart_header *stats;

  body = alloc_buffer_with_length( 128 );
  append_back_buffer( body, 128 );
  memset( body->data, 0xa1, body->length );
  experimenter_multipart_reply = create_experimenter_multipart_reply( TRANSACTION_ID, flags, experimenter, exp_type, body );

  stats_len = ( uint16_t ) ( sizeof( struct ofp_experimenter_multipart_header ) + body->length );

  expected_data = xcalloc( 1, ( size_t ) stats_len );
  stats = ( struct ofp_experimenter_multipart_header * ) expected_data;
  stats->experimenter = experimenter;
  stats->exp_type = exp_type;
  memcpy( stats + 1, body->data, body->length );

  multipart_reply = experimenter_multipart_reply->data;
  multipart_reply->type = htons( 0xfffe );

  set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
  expect_assert_failure( handle_multipart_reply( DATAPATH_ID, experimenter_multipart_reply ) );

  xfree( expected_data );
  free_buffer( body );
  free_buffer( experimenter_multipart_reply );
}


static void
test_handle_multipart_reply_if_handler_is_not_registered() {
  char mfr_desc[ DESC_STR_LEN ];
  char hw_desc[ DESC_STR_LEN ];
  char sw_desc[ DESC_STR_LEN ];
  char serial_num[ SERIAL_NUM_LEN ];
  char dp_desc[ DESC_STR_LEN ];
  uint16_t flags = 0;
  buffer *buffer;

  memset( mfr_desc, '\0', DESC_STR_LEN );
  memset( hw_desc, '\0', DESC_STR_LEN );
  memset( sw_desc, '\0', DESC_STR_LEN );
  memset( serial_num, '\0', SERIAL_NUM_LEN );
  memset( dp_desc, '\0', DESC_STR_LEN );
  sprintf( mfr_desc, "NEC Coporation" );
  sprintf( hw_desc, "OpenFlow Switch Hardware" );
  sprintf( sw_desc, "OpenFlow Switch Software" );
  sprintf( serial_num, "123456" );
  sprintf( dp_desc, "Datapath 0" );

  buffer = create_desc_multipart_reply( TRANSACTION_ID, flags, mfr_desc, hw_desc,
                                    sw_desc, serial_num, dp_desc );

  // FIXME
  handle_multipart_reply( DATAPATH_ID, buffer );

  free_buffer( buffer );
}


static void
test_handle_multipart_reply_if_message_is_NULL() {
  set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
  expect_assert_failure( handle_multipart_reply( DATAPATH_ID, NULL ) );
}


static void
test_handle_multipart_reply_if_message_length_is_zero() {
  buffer *buffer;

  buffer = alloc_buffer_with_length( 32 );

  set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
  expect_assert_failure( handle_multipart_reply( DATAPATH_ID, buffer ) );

  free_buffer( buffer );
}


/********************************************************************************
 * handle_barrier_reply() tests.
 ********************************************************************************/

static void
test_handle_barrier_reply() {
  buffer *buffer;

  buffer = create_barrier_reply( TRANSACTION_ID );

  expect_memory( mock_barrier_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_barrier_reply_handler, transaction_id, TRANSACTION_ID );
  expect_memory( mock_barrier_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_barrier_reply_handler( mock_barrier_reply_handler, USER_DATA );
  handle_barrier_reply( DATAPATH_ID, buffer );

  free_buffer( buffer );
}


static void
test_handle_barrier_reply_if_handler_is_not_registered() {
  buffer *buffer;

  buffer = create_barrier_reply( TRANSACTION_ID );

  // FIXME
  
  handle_barrier_reply( DATAPATH_ID, buffer );

  free_buffer( buffer );
}


static void
test_handle_barrier_reply_if_message_is_NULL() {
  set_barrier_reply_handler( mock_barrier_reply_handler, USER_DATA );
  expect_assert_failure( handle_barrier_reply( DATAPATH_ID, NULL ) );
}


static void
test_handle_barrier_reply_if_message_length_is_zero() {
  buffer *buffer;

  buffer = alloc_buffer_with_length( 32 );

  set_barrier_reply_handler( mock_barrier_reply_handler, USER_DATA );
  expect_assert_failure( handle_barrier_reply( DATAPATH_ID, buffer ) );

  free_buffer( buffer );
}


/********************************************************************************
 * handle_queue_get_config_reply() tests.
 ********************************************************************************/

static void
test_handle_queue_get_config_reply() {
  size_t queue_len;
  uint32_t port = 1;
  list_element *list;
  buffer *expected_message;
  struct ofp_packet_queue *queue[ 2 ];
  struct ofp_queue_prop_min_rate *prop_header;

  queue_len = offsetof( struct ofp_packet_queue, properties ) + sizeof( struct ofp_queue_prop_min_rate );
  queue[ 0 ] = xcalloc( 1, queue_len );
  queue[ 1 ] = xcalloc( 1, queue_len );

  queue[ 0 ]->queue_id = 1;
  queue[ 0 ]->port = 2;
  queue[ 0 ]->len = ( uint16_t ) queue_len;
  prop_header = ( struct ofp_queue_prop_min_rate * ) queue[ 0 ]->properties;
  prop_header->prop_header.property = OFPQT_MIN_RATE;
  prop_header->prop_header.len = sizeof( struct ofp_queue_prop_min_rate );
  prop_header->rate = 1234;

  queue[ 1 ]->queue_id = 2;
  queue[ 1 ]->port = 3;
  queue[ 1 ]->len = ( uint16_t ) queue_len;
  prop_header = ( struct ofp_queue_prop_min_rate * ) queue[ 1 ]->properties;
  prop_header->prop_header.property = OFPQT_MIN_RATE;
  prop_header->prop_header.len = sizeof( struct ofp_queue_prop_min_rate );
  prop_header->rate = 5678;

  create_list( &list );
  append_to_tail( &list, queue[ 0 ] );
  append_to_tail( &list, queue[ 1 ] );

  expected_message = create_queue_get_config_reply( TRANSACTION_ID, port, list );

  expect_memory( mock_queue_get_config_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_queue_get_config_reply_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_queue_get_config_reply_handler, port, port );
  expect_memory( mock_queue_get_config_reply_handler, queue1, queue[ 0 ], queue_len );
  expect_memory( mock_queue_get_config_reply_handler, queue2, queue[ 1 ], queue_len );
  expect_memory( mock_queue_get_config_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_queue_get_config_reply_handler( mock_queue_get_config_reply_handler, USER_DATA );
  handle_queue_get_config_reply( DATAPATH_ID, expected_message );

  xfree( queue[ 0 ] );
  xfree( queue[ 1 ] );
  delete_list( list );
  free_buffer( expected_message );
}


static void
test_handle_queue_get_config_reply_without_queues() {
  uint16_t port = 1;
  buffer *buffer;

  buffer = create_queue_get_config_reply( TRANSACTION_ID, port, NULL );

  set_queue_get_config_reply_handler( mock_queue_get_config_reply_handler, USER_DATA );
  expect_assert_failure( handle_queue_get_config_reply( DATAPATH_ID, buffer ) );

  free_buffer( buffer );
}


static void
test_handle_queue_get_config_reply_if_handler_is_not_registered() {
  size_t queue_len;
  uint32_t port = 1;
  list_element *list;
  buffer *expected_message;
  struct ofp_packet_queue *queue[ 2 ];
  struct ofp_queue_prop_min_rate *prop_header;

  queue_len = offsetof( struct ofp_packet_queue, properties ) + sizeof( struct ofp_queue_prop_min_rate );
  queue[ 0 ] = xcalloc( 1, queue_len );
  queue[ 1 ] = xcalloc( 1, queue_len );

  queue[ 0 ]->queue_id = 1;
  queue[ 0 ]->port = 2;
  queue[ 0 ]->len = ( uint16_t ) queue_len;
  prop_header = ( struct ofp_queue_prop_min_rate * ) queue[ 0 ]->properties;
  prop_header->prop_header.property = OFPQT_MIN_RATE;
  prop_header->prop_header.len = sizeof( struct ofp_queue_prop_min_rate );
  prop_header->rate = 1234;

  queue[ 1 ]->queue_id = 2;
  queue[ 1 ]->port = 3;
  queue[ 1 ]->len = ( uint16_t ) queue_len;
  prop_header = ( struct ofp_queue_prop_min_rate * ) queue[ 1 ]->properties;
  prop_header->prop_header.property = OFPQT_MIN_RATE;
  prop_header->prop_header.len = sizeof( struct ofp_queue_prop_min_rate );
  prop_header->rate = 5678;

  create_list( &list );
  append_to_tail( &list, queue[ 0 ] );
  append_to_tail( &list, queue[ 1 ] );

  expected_message = create_queue_get_config_reply( TRANSACTION_ID, port, list );

  // FIXME
  handle_queue_get_config_reply( DATAPATH_ID, expected_message );

  xfree( queue[ 0 ] );
  xfree( queue[ 1 ] );
  delete_list( list );
  free_buffer( expected_message );
}


static void
test_handle_queue_get_config_reply_if_message_is_NULL() {
  set_queue_get_config_reply_handler( mock_queue_get_config_reply_handler, USER_DATA );
  expect_assert_failure( handle_queue_get_config_reply( DATAPATH_ID, NULL ) );
}


static void
test_handle_queue_get_config_reply_if_message_length_is_zero() {
  buffer *buffer;

  buffer = alloc_buffer_with_length( 32 );

  set_queue_get_config_reply_handler( mock_queue_get_config_reply_handler, USER_DATA );
  expect_assert_failure( handle_queue_get_config_reply( DATAPATH_ID, buffer ) );

  free_buffer( buffer );
}



/********************************************************************************
 * handle_role_reply() tests.
 ********************************************************************************/

static void
test_handle_role_reply() {
  uint32_t role = OFPCR_ROLE_NOCHANGE;
  uint64_t generation_id = 0xAAAABBBBCCCCDDDD;
  buffer *buffer;

  buffer = create_role_reply( TRANSACTION_ID, role, generation_id );

  expect_memory( mock_role_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_role_reply_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_role_reply_handler, role, role );
  expect_memory( mock_role_reply_handler, &generation_id, &generation_id, sizeof( uint64_t ) );
  expect_memory( mock_role_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_role_reply_handler( mock_role_reply_handler, USER_DATA );
  handle_role_reply( DATAPATH_ID, buffer );

  free_buffer( buffer );
}


static void
test_handle_role_reply_if_handler_is_not_registered() {
  uint32_t role = OFPCR_ROLE_NOCHANGE;
  uint64_t generation_id = 0xAAAABBBBCCCCDDDD;
  buffer *buffer;

  buffer = create_role_reply( TRANSACTION_ID, role, generation_id );

  // FIXME

  handle_role_reply( DATAPATH_ID, buffer );

  free_buffer( buffer );
}


static void
test_handle_role_reply_if_message_is_NULL() {
  set_role_reply_handler( mock_role_reply_handler, USER_DATA );
  expect_assert_failure( handle_role_reply( DATAPATH_ID, NULL ) );
}


static void
test_handle_role_reply_if_message_length_is_zero() {
  buffer *buffer;

  buffer = alloc_buffer_with_length( 32 );

  set_role_reply_handler( mock_role_reply_handler, USER_DATA );
  expect_assert_failure( handle_role_reply( DATAPATH_ID, buffer ) );

  free_buffer( buffer );
}



/********************************************************************************
 * handle_get_async_reply() tests.
 ********************************************************************************/

static void
test_handle_get_async_reply() {
  const uint32_t packet_in_mask[ 2 ] = { 0x01020304, 0x05060708 };
  const uint32_t port_status_mask[ 2 ] = { 0x090A0B0C, 0x0D0E0F01 };
  const uint32_t flow_removed_mask[ 2 ] = { 0x11223344, 0xAABBCCDD };

  buffer *buffer = create_get_async_reply( TRANSACTION_ID, packet_in_mask, port_status_mask, flow_removed_mask );

  expect_memory( mock_get_async_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_get_async_reply_handler, transaction_id, TRANSACTION_ID );
  expect_memory( mock_get_async_reply_handler, packet_in_mask, packet_in_mask, (sizeof( uint32_t ) * 2) );
  expect_memory( mock_get_async_reply_handler, port_status_mask, port_status_mask, (sizeof( uint32_t ) * 2) );
  expect_memory( mock_get_async_reply_handler, flow_removed_mask, flow_removed_mask, (sizeof( uint32_t ) * 2) );
  expect_memory( mock_get_async_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_get_async_reply_handler( mock_get_async_reply_handler, USER_DATA );
  handle_get_async_reply( DATAPATH_ID, buffer );

  free_buffer( buffer );
}


static void
test_handle_get_async_reply_if_handler_is_not_registered() {
  const uint32_t packet_in_mask[ 2 ] = { 0x01020304, 0x05060708 };
  const uint32_t port_status_mask[ 2 ] = { 0x090A0B0C, 0x0D0E0F01 };
  const uint32_t flow_removed_mask[ 2 ] = { 0x11223344, 0xAABBCCDD };

  buffer *buffer = create_get_async_reply( TRANSACTION_ID, packet_in_mask, port_status_mask, flow_removed_mask );
  
  // FIXME
  
  handle_get_async_reply( DATAPATH_ID, buffer );

  free_buffer( buffer );
}


static void
test_handle_get_async_reply_if_message_is_NULL() {
  set_get_async_reply_handler( mock_get_async_reply_handler, USER_DATA );
  expect_assert_failure( handle_get_async_reply( DATAPATH_ID, NULL ) );
}


static void
test_handle_get_async_reply_if_message_length_is_zero() {
  buffer *buffer;

  buffer = alloc_buffer_with_length( 32 );

  set_get_async_reply_handler( mock_get_async_reply_handler, USER_DATA );
  expect_assert_failure( handle_get_async_reply( DATAPATH_ID, buffer ) );

  free_buffer( buffer );
}

/********************************************************************************
 * handle_list_switches_reply() tests.
 ********************************************************************************/

static void
test_insert_dpid() {
  list_element *head;
  create_list( &head );
  uint64_t alice = 0x1;
  uint64_t bob = 0x2;
  uint64_t carol = 0x3;

  insert_dpid( &head, &carol );
  insert_dpid( &head, &alice );
  insert_dpid( &head, &bob );

  list_element *element = head;
  assert_true( element != NULL );
  assert_true( element->data != NULL );
  assert_true( alice == *( uint64_t * ) element->data );

  element = element->next;
  assert_true( element != NULL );
  assert_true( element->data != NULL );
  assert_true( bob == *( uint64_t * ) element->data );

  element = element->next;
  assert_true( element != NULL );
  assert_true( element->data != NULL );
  assert_true( carol == *( uint64_t * ) element->data );

  element = element->next;
  assert_true( element == NULL );

  delete_list( head );
}


static void
test_insert_dpid_if_head_is_NULL() {
  uint64_t dpid = 0x1;

  expect_assert_failure( insert_dpid( NULL, &dpid ) );
}


static void
test_insert_dpid_if_dpid_is_NULL() {
  list_element *head;
  create_list( &head );

  expect_assert_failure( insert_dpid( &head, NULL ) );

  delete_list( head );
}


static void
test_handle_list_switches_reply() {
  uint16_t message_type = 0;
  uint64_t alice = 0x1;
  uint64_t bob = 0x2;
  uint64_t carol = 0x3;
  uint64_t dpid[] = { htonll( bob ), htonll( carol ), htonll( alice ) };
  size_t length = sizeof( dpid );
  void *user_data = LIST_SWITCHES_REPLY_USER_DATA;

  expect_value( mock_handle_list_switches_reply, *dpid1, alice );
  expect_value( mock_handle_list_switches_reply, *dpid2, bob );
  expect_value( mock_handle_list_switches_reply, *dpid3, carol );
  expect_value( mock_handle_list_switches_reply, user_data, LIST_SWITCHES_REPLY_USER_DATA );

  set_list_switches_reply_handler( mock_handle_list_switches_reply );
  handle_list_switches_reply( message_type, dpid, length, user_data );
}


static void
test_handle_list_switches_reply_if_data_is_NULL() {
  uint16_t message_type = 0;
  size_t length = 64;
  void *user_data = LIST_SWITCHES_REPLY_USER_DATA;

  set_list_switches_reply_handler( mock_handle_list_switches_reply );
  expect_assert_failure( handle_list_switches_reply( message_type, NULL, length, user_data ) );
}


static void
test_handle_list_switches_reply_if_length_is_zero() {
  uint16_t message_type = 0;
  uint64_t dpid[] = { 0 };
  void *user_data = LIST_SWITCHES_REPLY_USER_DATA;

  expect_value( mock_handle_list_switches_reply, user_data, LIST_SWITCHES_REPLY_USER_DATA );

  set_list_switches_reply_handler( mock_handle_list_switches_reply );
  handle_list_switches_reply( message_type, dpid, 0, user_data );
}


/********************************************************************************
 * handle_switch_events() tests.
 ********************************************************************************/

static void
test_handle_switch_events_if_type_is_MESSENGER_OPENFLOW_CONNECTED() {
  buffer *data = alloc_buffer_with_length( sizeof( openflow_service_header_t ) );
  append_back_buffer( data, sizeof( openflow_service_header_t ) );

  handle_switch_events( MESSENGER_OPENFLOW_CONNECTED, data->data, data->length );

  stat_entry *stat = lookup_hash_entry( stats, "openflow_application_interface.switch_connected_receive_succeeded" );
  assert_int_equal( ( int ) stat->value, 1 );

  free_buffer( data );
  xfree( delete_hash_entry( stats, "openflow_application_interface.switch_connected_receive_succeeded" ) );
}


static void
test_handle_switch_events_if_type_is_MESSENGER_OPENFLOW_DISCONNECTED() {
  uint64_t *datapath_id;
  buffer *data;

  data = alloc_buffer_with_length( sizeof( openflow_service_header_t ) );
  datapath_id = append_back_buffer( data, sizeof( openflow_service_header_t ) );

  *datapath_id = htonll( DATAPATH_ID );

  expect_memory( mock_switch_disconnected_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_switch_disconnected_handler, user_data, SWITCH_DISCONNECTED_USER_DATA );

  expect_string( mock_clear_send_queue, service_name, REMOTE_SERVICE_NAME );
  will_return( mock_clear_send_queue, true );

  set_switch_disconnected_handler( mock_switch_disconnected_handler, SWITCH_DISCONNECTED_USER_DATA );
  handle_switch_events( MESSENGER_OPENFLOW_DISCONNECTED, data->data, data->length );

  stat_entry *stat = lookup_hash_entry( stats, "openflow_application_interface.switch_disconnected_receive_succeeded" );
  assert_int_equal( ( int ) stat->value, 1 );

  free_buffer( data );
  xfree( delete_hash_entry( stats, "openflow_application_interface.switch_disconnected_receive_succeeded" ) );
}


static void
test_handle_switch_events_if_message_is_NULL() {
  expect_assert_failure( handle_switch_events( MESSENGER_OPENFLOW_READY, NULL, 1 ) );
}


static void
test_handle_switch_events_if_message_length_is_zero() {
  buffer *data;

  data = alloc_buffer_with_length( sizeof( openflow_service_header_t ) );

  expect_assert_failure( handle_switch_events( MESSENGER_OPENFLOW_READY, data->data, 0 ) );

  free_buffer( data );
}


static void
test_handle_switch_events_if_message_length_is_too_big() {
  buffer *data;

  data = alloc_buffer_with_length( sizeof( openflow_service_header_t ) );

  expect_assert_failure( handle_switch_events( MESSENGER_OPENFLOW_READY, data->data,
                                               data->length + 1 ) );

  free_buffer( data );
}


static void
test_handle_switch_events_if_unhandled_message_type() {
  buffer *data;

  data = alloc_buffer_with_length( sizeof( openflow_service_header_t ) );
  append_back_buffer( data, sizeof( openflow_service_header_t ) );

  // FIXME
  handle_switch_events( MESSENGER_OPENFLOW_MESSAGE, data->data, data->length );

  stat_entry *stat = lookup_hash_entry( stats, "openflow_application_interface.undefined_switch_event_receive_succeeded" );
  assert_int_equal( ( int ) stat->value, 1 );

  free_buffer( data );
  xfree( delete_hash_entry( stats, "openflow_application_interface.undefined_switch_event_receive_succeeded" ) );
}


/********************************************************************************
 * handle_openflow_message() tests.
 ********************************************************************************/

static void
test_handle_openflow_message() {
  openflow_service_header_t messenger_header;
  stat_entry *stat;

  messenger_header.datapath_id = htonll( DATAPATH_ID );
  messenger_header.service_name_length = 0;

  // error
  {
    buffer *buffer, *data;

    data = alloc_buffer_with_length( 16 );
    append_back_buffer( data, 16 );
    memset( data->data, 'a', 16 );

    buffer = create_error( TRANSACTION_ID, OFPET_HELLO_FAILED, OFPHFC_INCOMPATIBLE, data );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );
    expect_memory( mock_error_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_error_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_error_handler, type32, OFPET_HELLO_FAILED );
    expect_value( mock_error_handler, code32, OFPHFC_INCOMPATIBLE );
    expect_value( mock_error_handler, data->length, data->length );
    expect_memory( mock_error_handler, data->data, data->data, data->length );
    expect_memory( mock_error_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_error_handler( mock_error_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.error_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    free_buffer( data );
    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.error_receive_succeeded" ) );
  }
  // experimenter_error
  {
    uint16_t type = OFPET_EXPERIMENTER;

    uint16_t exp_type = 0x3344;
    uint32_t experimenter = 0x55667788;
    buffer *buffer, *data;
    
    data = alloc_buffer_with_length( 16 );
    append_back_buffer( data, 16 );
    memset( data->data, 'a', 16 );

    buffer = create_error_experimenter( TRANSACTION_ID, type, exp_type, experimenter, data );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );
    expect_memory( mock_experimenter_error_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_experimenter_error_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_experimenter_error_handler, type32, ( uint32_t ) type );
    expect_value( mock_experimenter_error_handler, exp_type32, ( uint32_t ) exp_type );
    expect_value( mock_experimenter_error_handler, experimenter, experimenter );
    expect_value( mock_experimenter_error_handler, data->length, data->length );
    expect_memory( mock_experimenter_error_handler, data->data, data->data, data->length );
    expect_memory( mock_experimenter_error_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_experimenter_error_handler( mock_experimenter_error_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.error_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    free_buffer( data );
    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.error_receive_succeeded" ) );
  }

  // echo_reply
  {
    buffer *buffer, *data;

    data = alloc_buffer_with_length( 16 );
    append_back_buffer( data, 16 );
    memset( data->data, 'a', 16 );

    buffer = create_echo_reply( TRANSACTION_ID, data );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );
    expect_memory( mock_echo_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_echo_reply_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_echo_reply_handler, data->length, data->length );
    expect_memory( mock_echo_reply_handler, data->data, data->data, data->length );
    expect_memory( mock_echo_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_echo_reply_handler( mock_echo_reply_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );
    stat = lookup_hash_entry( stats, "openflow_application_interface.echo_reply_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    free_buffer( data );
    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.echo_reply_receive_succeeded" ) );
  }

  // experimenter
  {
    buffer *buffer, *data;
    uint32_t exp_type = 0x1122;

    data = alloc_buffer_with_length( 16 );
    append_back_buffer( data, 16 );
    memset( data->data, 'a', 16 );

    buffer = create_experimenter( TRANSACTION_ID, VENDOR_ID, exp_type, data );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );
    expect_memory( mock_experimenter_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_experimenter_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_experimenter_handler, experimenter, VENDOR_ID );
    expect_value( mock_experimenter_handler, exp_type, exp_type );
    expect_value( mock_experimenter_handler, data->length, data->length );
    expect_memory( mock_experimenter_handler, data->data, data->data, data->length );
    expect_memory( mock_experimenter_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_experimenter_handler( mock_experimenter_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.experimenter_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    free_buffer( data );
    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.experimenter_receive_succeeded" ) );
  }

  // features_reply
  {
    uint32_t n_buffers = 1024;
    uint8_t n_tables = 2;
    uint8_t auxiliary_id = 0x11;
    uint32_t capabilities;
    buffer *buffer;

    capabilities = ( OFPC_FLOW_STATS | OFPC_TABLE_STATS | OFPC_PORT_STATS |
                     OFPC_GROUP_STATS | OFPC_IP_REASM | OFPC_QUEUE_STATS | OFPC_PORT_BLOCKED );

    buffer = create_features_reply( TRANSACTION_ID, DATAPATH_ID, n_buffers, n_tables,
                                    auxiliary_id, capabilities );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );
    expect_memory( mock_features_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_features_reply_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_features_reply_handler, n_buffers, n_buffers );
    expect_value( mock_features_reply_handler, n_tables32, ( uint32_t ) n_tables );
    expect_value( mock_features_reply_handler, auxiliary_id32, ( uint32_t ) auxiliary_id );
    expect_value( mock_features_reply_handler, capabilities, capabilities );
    expect_memory( mock_features_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_features_reply_handler( mock_features_reply_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.features_reply_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );
    
    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.features_reply_receive_succeeded" ) );
  }

  // get_config_reply
  {
    uint16_t flags = OFPC_FRAG_NORMAL;
    uint16_t miss_send_len = 128;
    buffer *buffer;

    buffer = create_get_config_reply( TRANSACTION_ID, flags, miss_send_len );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );
    expect_memory( mock_get_config_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_get_config_reply_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_get_config_reply_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_get_config_reply_handler, miss_send_len32, ( uint32_t ) miss_send_len );
    expect_memory( mock_get_config_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_get_config_reply_handler( mock_get_config_reply_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.get_config_reply_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.get_config_reply_receive_succeeded" ) );
  }

  // packet_in
  {
    uint32_t buffer_id = 0x01020304;
    uint8_t reason = OFPR_NO_MATCH;
    uint8_t table_id = 0x01;
    uint64_t cookie = 0xAAAABBBBCCCCDDDD;
    oxm_matches *match;
    size_t match1_len, match2_len;
    oxm_match_header *queue[ 2 ];
    uint32_t* value;

    match1_len = ( sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_IN_PORT ) );
    queue[ 0 ] = xcalloc( 1, match1_len );
    value = ( uint32_t* ) (queue[ 0 ] + 1);
    *queue[ 0 ] = OXM_OF_IN_PORT;
    *value = 0x2468ACEF;

    match2_len = ( sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_IN_PHY_PORT ) );
    queue[ 1 ] = xcalloc( 1, match2_len );
    value = ( uint32_t* ) (queue[ 1 ] + 1);
    *queue[ 1 ] = OXM_OF_IN_PHY_PORT;
    *value = 0xFECA8642;

    match = create_oxm_matches();
    match->n_matches = 2;
    append_to_tail( &match->list, queue[ 0 ] );
    append_to_tail( &match->list, queue[ 1 ] );

    buffer *data = alloc_buffer_with_length( 64 );
    calloc_packet_info( data );
    append_back_buffer( data, 64 );
    memset( data->data, 0x01, 64 );
    uint16_t total_len = ( uint16_t ) data->length ;

    buffer *buffer = create_packet_in( TRANSACTION_ID, buffer_id, total_len, reason, table_id, cookie, match, data );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );
    will_return( mock_parse_packet, true );
    expect_memory( mock_packet_in_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_packet_in_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_packet_in_handler, buffer_id, buffer_id );
    expect_value( mock_packet_in_handler, total_len32, ( uint32_t ) total_len );
    expect_value( mock_packet_in_handler, reason32, ( uint32_t ) reason );
    expect_value( mock_packet_in_handler, table_id32, ( uint32_t ) table_id );
    expect_memory( mock_packet_in_handler, &cookie, &cookie, sizeof( uint64_t ) );
    expect_memory( mock_packet_in_handler, match1, queue[ 0 ], match1_len );
    expect_memory( mock_packet_in_handler, match2, queue[ 1 ], match2_len );
    expect_value( mock_packet_in_handler, data->length, data->length );
    expect_memory( mock_packet_in_handler, data->data, data->data, data->length );
    expect_memory( mock_packet_in_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_packet_in_handler( mock_packet_in_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.packet_in_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    delete_oxm_matches(match);
    free_buffer( buffer );
    free_buffer( data );
    xfree( delete_hash_entry( stats, "openflow_application_interface.packet_in_receive_succeeded" ) );
  }

  // flow_removed
  {
    uint64_t cookie = 0x1111222233334444;
    uint16_t priority = UINT16_MAX;
    uint8_t reason =  OFPRR_IDLE_TIMEOUT;
    uint8_t table_id = 0xAA;
    uint32_t duration_sec = 180;
    uint32_t duration_nsec = 10000;
    uint16_t idle_timeout = 60;
    uint16_t hard_timeout = 120;
    uint64_t packet_count = 1000;
    uint64_t byte_count = 100000;
    oxm_matches *match;
    size_t match1_len, match2_len;
    oxm_match_header *queue[ 2 ];
    uint32_t* value;
    
    match1_len = ( sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_IN_PORT ) );
    queue[ 0 ] = xcalloc( 1, match1_len );
    value = ( uint32_t* ) (queue[ 0 ] + 1);
    *queue[ 0 ] = OXM_OF_IN_PORT;
    *value = 0x2468ACEF;
      
    match2_len = ( sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_IN_PHY_PORT ) );
    queue[ 1 ] = xcalloc( 1, match2_len );
    value = ( uint32_t* ) (queue[ 1 ] + 1);
    *queue[ 1 ] = OXM_OF_IN_PHY_PORT;
    *value = 0xFECA8642;

    match = create_oxm_matches();
    match->n_matches = 2;
    append_to_tail( &match->list, queue[ 0 ] );
    append_to_tail( &match->list, queue[ 1 ] );

    buffer *buffer = create_flow_removed(
      TRANSACTION_ID,
      cookie,
      priority,
      reason,
      table_id,
      duration_sec,
      duration_nsec,
      idle_timeout,
      hard_timeout,
      packet_count,
      byte_count,
      match
    );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );
    expect_memory( mock_flow_removed_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_flow_removed_handler, transaction_id, TRANSACTION_ID );
    expect_memory( mock_flow_removed_handler, &cookie, &cookie, sizeof( uint64_t ) );
    expect_value( mock_flow_removed_handler, priority32, ( uint32_t ) priority );
    expect_value( mock_flow_removed_handler, reason32, ( uint32_t ) reason );
    expect_value( mock_flow_removed_handler, table_id32, ( uint32_t ) table_id );
    expect_value( mock_flow_removed_handler, duration_sec, duration_sec );
    expect_value( mock_flow_removed_handler, duration_nsec, duration_nsec );
    expect_value( mock_flow_removed_handler, idle_timeout32, ( uint32_t ) idle_timeout );
    expect_value( mock_flow_removed_handler, hard_timeout32, ( uint32_t ) hard_timeout );
    expect_memory( mock_flow_removed_handler, &packet_count, &packet_count, sizeof( uint64_t ) );
    expect_memory( mock_flow_removed_handler, &byte_count, &byte_count, sizeof( uint64_t ) );
    expect_memory( mock_flow_removed_handler, match1, queue[ 0 ], match1_len );
    expect_memory( mock_flow_removed_handler, match2, queue[ 1 ], match2_len );
    expect_memory( mock_flow_removed_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_flow_removed_handler( mock_flow_removed_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.flow_removed_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    delete_oxm_matches(match);
    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.flow_removed_receive_succeeded" ) );
  }

  // port_status
  {
    uint8_t reason = OFPPR_MODIFY;
    buffer *buffer;
    struct ofp_port desc;

    desc.port_no = 1;
    memset( desc.pad, 0, sizeof( desc.pad ) );
    memcpy( desc.hw_addr, MAC_ADDR_X, sizeof( desc.hw_addr ) );
    memset( desc.pad2, 0, sizeof( desc.pad2 ) );
    memset( desc.name, '\0', OFP_MAX_PORT_NAME_LEN );
    memcpy( desc.name, PORT_NAME, strlen( PORT_NAME ) );
    desc.config = OFPPC_PORT_DOWN;
    desc.state = OFPPS_LINK_DOWN;
    desc.curr = ( OFPPF_1GB_FD | OFPPF_COPPER | OFPPF_PAUSE );
    desc.advertised = PORT_FEATURES;
    desc.supported = PORT_FEATURES;
    desc.peer = PORT_FEATURES;
    desc.curr_speed = 0x1024;
    desc.max_speed = 0x2048;

    buffer = create_port_status( TRANSACTION_ID, reason, desc );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );
    expect_memory( mock_port_status_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_port_status_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_port_status_handler, reason32, ( uint32_t ) reason );
    expect_memory( mock_port_status_handler, &desc, &desc, sizeof( struct ofp_port ) );
    expect_memory( mock_port_status_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_port_status_handler( mock_port_status_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.port_status_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.port_status_receive_succeeded" ) );
  }

  // multipart_reply
  {
    char mfr_desc[ DESC_STR_LEN ];
    char hw_desc[ DESC_STR_LEN ];
    char sw_desc[ DESC_STR_LEN ];
    char serial_num[ SERIAL_NUM_LEN ];
    char dp_desc[ DESC_STR_LEN ];
    uint16_t flags = 0;
    uint32_t body_len;
    buffer *buffer;
    struct ofp_multipart_reply *multipart_reply;

    memset( mfr_desc, '\0', DESC_STR_LEN );
    memset( hw_desc, '\0', DESC_STR_LEN );
    memset( sw_desc, '\0', DESC_STR_LEN );
    memset( serial_num, '\0', SERIAL_NUM_LEN );
    memset( dp_desc, '\0', DESC_STR_LEN );
    sprintf( mfr_desc, "NEC Coporation" );
    sprintf( hw_desc, "OpenFlow Switch Hardware" );
    sprintf( sw_desc, "OpenFlow Switch Software" );
    sprintf( serial_num, "123456" );
    sprintf( dp_desc, "Datapath 0" );

    buffer = create_desc_multipart_reply( TRANSACTION_ID, flags, mfr_desc, hw_desc,
                                      sw_desc, serial_num, dp_desc );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );
    multipart_reply = ( struct ofp_multipart_reply * ) ( ( char * ) buffer->data + sizeof( openflow_service_header_t ) );
    body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                              offsetof( struct ofp_multipart_reply, body ) );

    expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_reply_handler, type32, OFPMP_DESC );
    expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_reply_handler, data->length, body_len );
    expect_memory( mock_multipart_reply_handler, data->data, multipart_reply->body, body_len );
    expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" ) );
  }

  {
    void *expected_data;
    uint16_t flags = OFPMPF_REPLY_MORE;
    list_element *expected_list;
    buffer *buffer;
    uint16_t stats_len = 0;
    uint32_t body_len;
    struct ofp_multipart_reply *multipart_reply;
    struct ofp_flow_stats *expected_stats[ 2 ];
    struct ofp_instruction *inst;

    // with match
    {
      create_oxm_match_testdata();
      create_instruction_testdata();

      stats_len = ( uint16_t ) ( offsetof( struct ofp_flow_stats, match ) + expected_ofp_match_len + expected_ofp_instruction_len );

      expected_stats[ 0 ] = xcalloc( 1, stats_len );
      expected_stats[ 1 ] = xcalloc( 1, stats_len );

      expected_stats[ 0 ]->length = stats_len;
      expected_stats[ 0 ]->table_id = 1;
      expected_stats[ 0 ]->pad = 0;
      expected_stats[ 0 ]->duration_sec = 60;
      expected_stats[ 0 ]->duration_nsec = 10000;
      expected_stats[ 0 ]->priority = 1024;
      expected_stats[ 0 ]->idle_timeout = 60;
      expected_stats[ 0 ]->hard_timeout = 3600;
      expected_stats[ 0 ]->flags = OFPFF_NO_BYT_COUNTS;
      memset( expected_stats[ 0 ]->pad2, 0, sizeof( expected_stats[ 0 ]->pad2 ) );
      expected_stats[ 0 ]->cookie = 0x0102030405060708ULL;
      expected_stats[ 0 ]->packet_count = 1000;
      expected_stats[ 0 ]->byte_count = 100000;
      memcpy( &expected_stats[ 0 ]->match, expected_ofp_match, expected_ofp_match_len );
      inst = ( struct ofp_instruction * ) ( ( char * ) &expected_stats[ 0 ]->match + expected_ofp_match_len );
      memcpy( inst, expected_ofp_instruction, expected_ofp_instruction_len );

      memcpy( expected_stats[ 1 ], expected_stats[ 0 ], stats_len );
      expected_stats[ 1 ]->cookie = 0x0203040506070809ULL;

      create_list( &expected_list );
      append_to_tail( &expected_list, expected_stats[ 0 ] );
      append_to_tail( &expected_list, expected_stats[ 1 ] );

      expected_data = xcalloc( 1, ( size_t ) ( stats_len * 2 ) );
      memcpy( expected_data, expected_stats[ 0 ], stats_len );
      memcpy( ( char * ) expected_data + stats_len, expected_stats[ 1 ], stats_len );

      buffer = create_flow_multipart_reply( TRANSACTION_ID, flags, expected_list );
      append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
      memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );
      multipart_reply = ( struct ofp_multipart_reply * ) ( ( char * ) buffer->data + sizeof( openflow_service_header_t ) );
      body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                                offsetof( struct ofp_multipart_reply, body ) );

      expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
      expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
      expect_value( mock_multipart_reply_handler, type32, OFPMP_FLOW );
      expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
      expect_value( mock_multipart_reply_handler, data->length, body_len );
      expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
      expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

      set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
      handle_openflow_message( buffer->data, buffer->length );

      stat = lookup_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" );
      assert_int_equal( ( int ) stat->value, 1 );

      xfree( expected_stats[ 0 ] );
      xfree( expected_stats[ 1 ] );
      delete_list( expected_list );

      delete_oxm_match_testdata();
      delete_instruction_testdata();
      free_buffer( buffer );
      xfree( expected_data );
      xfree( delete_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" ) );
    }
  }
  {
    uint16_t flags = 0;
    uint32_t body_len;
    uint32_t flow_count = 1000;
    uint64_t packet_count = 1000;
    uint64_t byte_count = 10000;
    buffer *buffer;
    struct ofp_multipart_reply *multipart_reply;
    struct ofp_aggregate_stats_reply aggregate_multipart_reply;

    buffer = create_aggregate_multipart_reply( TRANSACTION_ID, flags, packet_count,
                                               byte_count, flow_count );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );

    multipart_reply = ( struct ofp_multipart_reply * ) ( ( char * ) buffer->data + sizeof( openflow_service_header_t ) );
    body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                              offsetof( struct ofp_multipart_reply, body ) );

    expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_reply_handler, type32, OFPMP_AGGREGATE );
    expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_reply_handler, data->length, body_len );
    ntoh_aggregate_stats( &aggregate_multipart_reply,
                          ( struct ofp_aggregate_stats_reply * ) multipart_reply->body );
    expect_memory( mock_multipart_reply_handler, data->data, &aggregate_multipart_reply, body_len );
    expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" ) );
  }
  {
    void *expected_data;
    uint16_t flags = OFPMPF_REPLY_MORE;
    uint16_t stats_len;
    uint32_t body_len;
    buffer *buffer;
    list_element *table_stats;
    struct ofp_multipart_reply *multipart_reply;
    struct ofp_table_stats *tb_stats[ 2 ];

    stats_len = sizeof( struct ofp_table_stats );

    tb_stats[ 0 ] = xcalloc( 1, stats_len );
    tb_stats[ 1 ] = xcalloc( 1, stats_len );

    tb_stats[ 0 ]->table_id = 1;
    memset( tb_stats[ 0 ]->pad, 0, sizeof( tb_stats[ 0 ]->pad ));
    tb_stats[ 0 ]->active_count = 1000;
    tb_stats[ 0 ]->lookup_count = 100000;
    tb_stats[ 0 ]->matched_count = 10000;

    memcpy( tb_stats[ 1 ], tb_stats[ 0 ], stats_len );
    tb_stats[ 1 ]->table_id = 2;

    create_list( &table_stats );
    append_to_tail( &table_stats, tb_stats[ 0 ] );
    append_to_tail( &table_stats, tb_stats[ 1 ] );

    expected_data = xcalloc( 1, ( size_t ) ( stats_len * 2 ) );
    memcpy( expected_data, tb_stats[ 0 ], stats_len );
    memcpy( ( char * ) expected_data + stats_len, tb_stats[ 1 ], stats_len );

    buffer = create_table_multipart_reply( TRANSACTION_ID, flags, table_stats );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );

    multipart_reply = ( struct ofp_multipart_reply * ) ( ( char * ) buffer->data + sizeof( openflow_service_header_t ) );
    body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                              offsetof( struct ofp_multipart_reply, body ) );

    expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_reply_handler, type32, OFPMP_TABLE );
    expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_reply_handler, data->length, body_len );
    expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
    expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    xfree( tb_stats[ 0 ] );
    xfree( tb_stats[ 1 ] );
    delete_list( table_stats );
    xfree( expected_data );
    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" ) );
  }
  {
    void *expected_data;
    uint16_t flags = OFPMPF_REPLY_MORE;
    uint16_t stats_len;
    uint32_t body_len;
    buffer *buffer;
    list_element *port_stats;
    struct ofp_multipart_reply *multipart_reply;
    struct ofp_port_stats *op_port_stats[ 2 ];

    stats_len = sizeof( struct ofp_port_stats );

    op_port_stats[ 0 ] = xcalloc( 1, stats_len );
    op_port_stats[ 1 ] = xcalloc( 1, stats_len );

    op_port_stats[ 0 ]->port_no = 1;
    memset( op_port_stats[ 0 ]->pad, 0, sizeof( op_port_stats[ 0 ]->pad ));
    op_port_stats[ 0 ]->rx_packets = 10000;
    op_port_stats[ 0 ]->tx_packets = 20000;
    op_port_stats[ 0 ]->rx_bytes = 30000;
    op_port_stats[ 0 ]->tx_bytes = 40000;
    op_port_stats[ 0 ]->rx_dropped = 50000;
    op_port_stats[ 0 ]->tx_dropped = 60000;
    op_port_stats[ 0 ]->rx_errors = 70000;
    op_port_stats[ 0 ]->tx_errors = 80000;
    op_port_stats[ 0 ]->rx_frame_err = 1;
    op_port_stats[ 0 ]->rx_over_err = 2;
    op_port_stats[ 0 ]->rx_crc_err = 1;
    op_port_stats[ 0 ]->collisions = 3;
    op_port_stats[ 0 ]->duration_sec = 10;
    op_port_stats[ 0 ]->duration_nsec = 100;

    memcpy( op_port_stats[ 1 ], op_port_stats[ 0 ], stats_len );
    op_port_stats[ 1 ]->port_no = 2;

    create_list( &port_stats );
    append_to_tail( &port_stats, op_port_stats[ 0 ] );
    append_to_tail( &port_stats, op_port_stats[ 1 ] );

    expected_data = xcalloc( 1, ( size_t ) ( stats_len * 2 ) );
    memcpy( expected_data, op_port_stats[ 0 ], stats_len );
    memcpy( ( char * ) expected_data + stats_len, op_port_stats[ 1 ], stats_len );

    buffer = create_port_multipart_reply( TRANSACTION_ID, flags, port_stats );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );

    multipart_reply = ( struct ofp_multipart_reply * ) ( ( char * ) buffer->data + sizeof( openflow_service_header_t ) );
    body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                              offsetof( struct ofp_multipart_reply, body ) );

    expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_reply_handler, type32, OFPMP_PORT_STATS );
    expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_reply_handler, data->length, body_len );
    expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
    expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    xfree( op_port_stats[ 0 ] );
    xfree( op_port_stats[ 1 ] );
    delete_list( port_stats );
    xfree( expected_data );
    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" ) );
  }
  {
    void *expected_data;
    uint16_t flags = OFPMPF_REPLY_MORE;
    uint16_t stats_len;
    uint32_t body_len;
    buffer *buffer;
    list_element *queue_stats;
    struct ofp_multipart_reply *multipart_reply;
    struct ofp_queue_stats *op_queue_stats[ 2 ];

    stats_len = sizeof( struct ofp_queue_stats );

    op_queue_stats[ 0 ] = xcalloc( 1, stats_len );
    op_queue_stats[ 1 ] = xcalloc( 1, stats_len );

    op_queue_stats[ 0 ]->port_no = 1;
    op_queue_stats[ 0 ]->queue_id = 2;
    op_queue_stats[ 0 ]->tx_bytes = 100000;
    op_queue_stats[ 0 ]->tx_packets = 60000;
    op_queue_stats[ 0 ]->tx_errors = 80;
    op_queue_stats[ 0 ]->duration_sec = 10;
    op_queue_stats[ 0 ]->duration_nsec = 100;

    memcpy( op_queue_stats[ 1 ], op_queue_stats[ 0 ], stats_len );
    op_queue_stats[ 1 ]->queue_id = 3;

    create_list( &queue_stats );
    append_to_tail( &queue_stats, op_queue_stats[ 0 ] );
    append_to_tail( &queue_stats, op_queue_stats[ 1 ] );

    expected_data = xcalloc( 1, ( size_t ) ( stats_len * 2 ) );
    memcpy( expected_data, op_queue_stats[ 0 ], stats_len );
    memcpy( ( char * ) expected_data + stats_len, op_queue_stats[ 1 ], stats_len );

    buffer = create_queue_multipart_reply( TRANSACTION_ID, flags, queue_stats );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );
    multipart_reply = ( struct ofp_multipart_reply * ) ( ( char * ) buffer->data + sizeof( openflow_service_header_t ) );
    body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                              offsetof( struct ofp_multipart_reply, body ) );

    expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_reply_handler, type32, OFPMP_QUEUE );
    expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_reply_handler, data->length, body_len );
    expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
    expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    xfree( op_queue_stats[ 0 ] );
    xfree( op_queue_stats[ 1 ] );
    delete_list( queue_stats );
    xfree( expected_data );
    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" ) );
  }
  {
    void *expected_data;
    uint16_t flags = OFPMPF_REPLY_MORE;
    uint16_t stats_len;
    uint32_t body_len;
    size_t grpsts_0len, grpsts_1len;
    list_element *list;
    buffer *buffer;
    struct ofp_group_stats *grpsts[ 2 ];
    struct ofp_bucket_counter *bktcnt;
    struct ofp_multipart_reply *multipart_reply;

    grpsts_0len = offsetof( struct ofp_group_stats, bucket_stats ) + sizeof( struct ofp_bucket_counter );
    grpsts_1len = offsetof( struct ofp_group_stats, bucket_stats ) + sizeof( struct ofp_bucket_counter );

    stats_len = ( uint16_t ) ( grpsts_0len + grpsts_1len );

    grpsts[ 0 ] = xcalloc( 1, grpsts_0len );
    grpsts[ 1 ] = xcalloc( 1, grpsts_1len );

    grpsts[ 0 ]->length = ( uint16_t ) grpsts_0len;
    grpsts[ 0 ]->group_id = 1;
    grpsts[ 0 ]->ref_count = 2;
    grpsts[ 0 ]->packet_count = 3;
    grpsts[ 0 ]->byte_count = 4;
    grpsts[ 0 ]->duration_sec = 5;
    grpsts[ 0 ]->duration_nsec = 6;
    bktcnt = ( struct ofp_bucket_counter * ) grpsts[ 0 ]->bucket_stats;
    bktcnt->packet_count = 7;
    bktcnt->byte_count = 8;

    grpsts[ 1 ]->length = ( uint16_t ) grpsts_1len;
    grpsts[ 1 ]->group_id = 11;
    grpsts[ 1 ]->ref_count = 12;
    grpsts[ 1 ]->packet_count = 13;
    grpsts[ 1 ]->byte_count = 14;
    grpsts[ 1 ]->duration_sec = 15;
    grpsts[ 1 ]->duration_nsec = 16;
    bktcnt = ( struct ofp_bucket_counter * ) grpsts[ 1 ]->bucket_stats;
    bktcnt->packet_count = 17;
    bktcnt->byte_count = 18;

    create_list( &list );
    append_to_tail( &list, grpsts[ 0 ] );
    append_to_tail( &list, grpsts[ 1 ] );

    expected_data = xcalloc( 1, ( size_t ) ( grpsts_0len + grpsts_1len ) );
    memcpy( expected_data, grpsts[ 0 ], grpsts_0len );
    memcpy( ( char * ) expected_data + grpsts_0len, grpsts[ 1 ], grpsts_1len );

    buffer = create_group_multipart_reply( TRANSACTION_ID, flags, list );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );
    multipart_reply = ( struct ofp_multipart_reply * ) ( ( char * ) buffer->data + sizeof( openflow_service_header_t ) );
    body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                              offsetof( struct ofp_multipart_reply, body ) );

    expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_reply_handler, type32, OFPMP_GROUP );
    expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_reply_handler, data->length, body_len );
    expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
    expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    xfree( grpsts[ 0 ] );
    xfree( grpsts[ 1 ] );
    delete_list( list );
    xfree( expected_data );
    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" ) );
  }
  {
    void *expected_data;
    uint16_t flags = OFPMPF_REPLY_MORE;
    uint16_t stats_len;
    uint32_t body_len;
    uint16_t grpdsc_len[2];
    buffer *buffer;
    list_element *expected_list;
    struct ofp_group_desc_stats *dsc1, *dsc2;
    struct ofp_multipart_reply *multipart_reply;

    create_bucket_testdata();

    grpdsc_len[0] = ( uint16_t ) ( offsetof( struct ofp_group_desc_stats, buckets ) + bucket_testdata_len[0] );
    dsc1 = xcalloc( 1, grpdsc_len[0] );
    dsc1->length = grpdsc_len[0];
    dsc1->type = OFPGT_SELECT;
    dsc1->group_id = 0x11223344;
    memcpy( dsc1->buckets, bucket_testdata[0], bucket_testdata_len[0] );

    grpdsc_len[1] = ( uint16_t ) ( offsetof( struct ofp_group_desc_stats, buckets ) + bucket_testdata_len[1] );
    dsc2 = xcalloc( 1, grpdsc_len[1] );
    dsc2->length = grpdsc_len[1];
    dsc2->type = OFPGT_INDIRECT;
    dsc2->group_id = 0x55667788;
    memcpy( dsc2->buckets, bucket_testdata[1], bucket_testdata_len[1] );

    stats_len = ( uint16_t ) ( grpdsc_len[0] + grpdsc_len[1] );

    create_list( &expected_list );
    append_to_tail( &expected_list, dsc1 );
    append_to_tail( &expected_list, dsc2 );

    expected_data = xcalloc( 1, ( size_t ) ( stats_len ) );
    memcpy( expected_data, dsc1, grpdsc_len[0] );
    memcpy( ( char * ) expected_data + grpdsc_len[0], dsc2, grpdsc_len[1] );

    buffer = create_group_desc_multipart_reply( TRANSACTION_ID, flags, expected_list );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );

    multipart_reply = ( struct ofp_multipart_reply * ) ( ( char * ) buffer->data + sizeof( openflow_service_header_t ) );
    body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                              offsetof( struct ofp_multipart_reply, body ) );

    expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_reply_handler, type32, OFPMP_GROUP_DESC );
    expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_reply_handler, data->length, body_len );
    expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
    expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    delete_bucket_testdata();
    xfree( dsc1 );
    xfree( dsc2 );
    delete_list( expected_list );
    xfree( expected_data );
    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" ) );
  }
  {
    void *expected_data;
    uint16_t flags = OFPMPF_REPLY_MORE;
    uint16_t stats_len;
    uint32_t body_len;
    buffer *buffer;
    struct ofp_group_features *grpftr;
    struct ofp_multipart_reply *multipart_reply;

    uint16_t grpftr_len = sizeof( struct ofp_group_features );

    stats_len = grpftr_len;

    grpftr = xcalloc( 1, grpftr_len );
    grpftr->types = OFPGT_SELECT;
    grpftr->capabilities = OFPGFC_CHAINING;
    grpftr->max_groups[0] = 1;
    grpftr->max_groups[1] = 2;
    grpftr->max_groups[2] = 3;
    grpftr->max_groups[3] = 4;
    grpftr->actions[0] = 5;
    grpftr->actions[1] = 6;
    grpftr->actions[2] = 7;
    grpftr->actions[3] = 8;

    buffer = create_group_features_multipart_reply( TRANSACTION_ID, flags, grpftr->types,
      grpftr->capabilities, grpftr->max_groups, grpftr->actions );

    expected_data = grpftr;

    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );
    multipart_reply = ( struct ofp_multipart_reply * ) ( ( char * ) buffer->data + sizeof( openflow_service_header_t ) );
    body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                              offsetof( struct ofp_multipart_reply, body ) );

    expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_reply_handler, type32, OFPMP_GROUP_FEATURES );
    expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_reply_handler, data->length, body_len );
    expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
    expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    xfree( expected_data );
    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" ) );
  }
  {
    void *expected_data;
    uint16_t flags = OFPMPF_REPLY_MORE;
    uint16_t stats_len;
    uint32_t body_len;
    uint16_t mtrsts_len[2];
    buffer *buffer;
    list_element *expected_list;
    struct ofp_meter_stats *mtr1, *mtr2;
    struct ofp_meter_band_stats *mtrbnd;
    struct ofp_multipart_reply *multipart_reply;

    mtrsts_len[0] = ( uint16_t ) ( offsetof( struct ofp_meter_stats, band_stats ) + sizeof( struct ofp_meter_band_stats ) );
    mtr1 = xcalloc( 1, mtrsts_len[0] );
    mtr1->meter_id = 0xaabbccdd;
    mtr1->len = mtrsts_len[0];
    mtr1->flow_count = 1;
    mtr1->packet_in_count = 2;
    mtr1->byte_in_count = 3;
    mtr1->duration_sec = 4;
    mtr1->duration_nsec = 5;
    mtrbnd = mtr1->band_stats;
    mtrbnd->packet_band_count = 0x11223344;
    mtrbnd->byte_band_count = 0x55667788;

    mtrsts_len[1] = ( uint16_t ) ( offsetof( struct ofp_meter_stats, band_stats ) + sizeof( struct ofp_meter_band_stats ) );
    mtr2 = xcalloc( 1, mtrsts_len[1] );
    mtr2->meter_id = 0x12345566;
    mtr2->len = mtrsts_len[1];
    mtr2->flow_count = 1;
    mtr2->packet_in_count = 2;
    mtr2->byte_in_count = 3;
    mtr2->duration_sec = 4;
    mtr2->duration_nsec = 5;
    mtrbnd = mtr2->band_stats;
    mtrbnd->packet_band_count = 0x11223344;
    mtrbnd->byte_band_count = 0x55667788;

    stats_len = ( uint16_t ) ( mtrsts_len[0] + mtrsts_len[1] );

    create_list( &expected_list );
    append_to_tail( &expected_list, mtr1 );
    append_to_tail( &expected_list, mtr2 );

    expected_data = xcalloc( 1, ( size_t ) ( stats_len ) );
    memcpy( expected_data, mtr1, mtrsts_len[0] );
    memcpy( ( char * ) expected_data + mtrsts_len[0], mtr2, mtrsts_len[1] );

    buffer = create_meter_multipart_reply( TRANSACTION_ID, flags, expected_list );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );
    multipart_reply = ( struct ofp_multipart_reply * ) ( ( char * ) buffer->data + sizeof( openflow_service_header_t ) );
    body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                              offsetof( struct ofp_multipart_reply, body ) );

    expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_reply_handler, type32, OFPMP_METER );
    expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_reply_handler, data->length, body_len );
    expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
    expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    xfree( mtr1 );
    xfree( mtr2 );
    delete_list( expected_list );
    xfree( expected_data );
    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" ) );
  }
  {
    void *expected_data;
    uint16_t flags = OFPMPF_REPLY_MORE;
    uint16_t stats_len;
    uint32_t body_len;
    uint16_t mtrcfg_len[2];
    buffer *buffer;
    list_element *expected_list;
    struct ofp_meter_config *mtr1, *mtr2;
    struct ofp_meter_band_drop *mtrbnd;
    struct ofp_multipart_reply *multipart_reply;

    mtrcfg_len[0] = ( uint16_t ) ( offsetof( struct ofp_meter_config, bands ) + sizeof( struct ofp_meter_band_drop ) );
    mtr1 = xcalloc( 1, mtrcfg_len[0] );
    mtr1->length = mtrcfg_len[0];
    mtr1->flags = OFPMC_MODIFY;
    mtr1->meter_id = 1;
    mtrbnd = ( struct ofp_meter_band_drop * ) mtr1->bands;
    mtrbnd->type = OFPMBT_DROP;
    mtrbnd->len = sizeof( struct ofp_meter_band_drop );
    mtrbnd->rate = 0x11223344;
    mtrbnd->burst_size = 0x55667788;

    mtrcfg_len[1] = ( uint16_t ) ( offsetof( struct ofp_meter_config, bands ) + sizeof( struct ofp_meter_band_drop ) );
    mtr2 = xcalloc( 1, mtrcfg_len[1] );
    mtr2->length = mtrcfg_len[1];
    mtr2->flags = OFPMC_DELETE;
    mtr2->meter_id = 1;
    mtrbnd = ( struct ofp_meter_band_drop * ) mtr2->bands;
    mtrbnd->type = OFPMBT_DROP;
    mtrbnd->len = sizeof( struct ofp_meter_band_drop );
    mtrbnd->rate = 0x12345555;
    mtrbnd->burst_size = 0x56789999;

    stats_len = ( uint16_t ) ( mtrcfg_len[0] + mtrcfg_len[1] );

    create_list( &expected_list );
    append_to_tail( &expected_list, mtr1 );
    append_to_tail( &expected_list, mtr2 );

    expected_data = xcalloc( 1, ( size_t ) ( stats_len ) );
    memcpy( expected_data, mtr1, mtrcfg_len[0] );
    memcpy( ( char * ) expected_data + mtrcfg_len[0], mtr2, mtrcfg_len[1] );

    buffer = create_meter_config_multipart_reply( TRANSACTION_ID, flags, expected_list );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );
    multipart_reply = ( struct ofp_multipart_reply * ) ( ( char * ) buffer->data + sizeof( openflow_service_header_t ) );
    body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                              offsetof( struct ofp_multipart_reply, body ) );

    expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_reply_handler, type32, OFPMP_METER_CONFIG );
    expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_reply_handler, data->length, body_len );
    expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
    expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    xfree( mtr1 );
    xfree( mtr2 );
    delete_list( expected_list );
    xfree( expected_data );
    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" ) );
  }
  {
    void *expected_data;
    uint16_t flags = OFPMPF_REPLY_MORE;
    uint16_t stats_len;
    uint32_t body_len;
    buffer *buffer;
    struct ofp_multipart_reply *multipart_reply;
    struct ofp_meter_features *mtrftr;

    stats_len = sizeof( struct ofp_meter_features );

    mtrftr = xcalloc( 1, stats_len );
    mtrftr->max_meter = 1;
    mtrftr->band_types = ( 1 << OFPMBT_DROP );
    mtrftr->capabilities = ( 1 << OFPMF_KBPS );
    mtrftr->max_bands = 10;
    mtrftr->max_color = 20;
    memset( mtrftr->pad, 0, sizeof( mtrftr->pad ) );

    expected_data = mtrftr;

    buffer = create_meter_features_multipart_reply( TRANSACTION_ID, flags, mtrftr->max_meter,
      mtrftr->band_types, mtrftr->capabilities, mtrftr->max_bands, mtrftr->max_color );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );
    multipart_reply = ( struct ofp_multipart_reply * ) ( ( char * ) buffer->data + sizeof( openflow_service_header_t ) );
    body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                              offsetof( struct ofp_multipart_reply, body ) );

    expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_reply_handler, type32, OFPMP_METER_FEATURES );
    expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_reply_handler, data->length, body_len );
    expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
    expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    xfree( expected_data );
    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" ) );
  }
  {
    void *expected_data;
    uint16_t flags = OFPMPF_REPLY_MORE;
    uint16_t stats_len;
    uint32_t body_len;
    buffer *buffer;
    list_element *table_ftr_stats;
    struct ofp_multipart_reply *multipart_reply;
    struct ofp_table_features *tbf_stats[ 2 ];
    char name[OFP_MAX_TABLE_NAME_LEN] = "TableName";

    stats_len = sizeof( struct ofp_table_features );

    tbf_stats[ 0 ] = xcalloc( 1, stats_len );
    tbf_stats[ 1 ] = xcalloc( 1, stats_len );

    tbf_stats[ 0 ]->length = ( uint16_t ) sizeof( struct ofp_table_features );
    tbf_stats[ 0 ]->table_id = 1;
    memset( tbf_stats[ 0 ]->pad, 0, sizeof( tbf_stats[ 0 ]->pad ) );
    memcpy( tbf_stats[ 0 ]->name, name, sizeof( name ) );
    tbf_stats[ 0 ]->metadata_match = 0x1111222233334444;
    tbf_stats[ 0 ]->metadata_write = 0x5555666677778888;
    tbf_stats[ 0 ]->config = 0x12345678;
    tbf_stats[ 0 ]->max_entries = 0xAABBCCDD;

    memcpy( tbf_stats[ 1 ], tbf_stats[ 0 ], stats_len );
    tbf_stats[ 1 ]->table_id = 2;

    create_list( &table_ftr_stats );
    append_to_tail( &table_ftr_stats, tbf_stats[ 0 ] );
    append_to_tail( &table_ftr_stats, tbf_stats[ 1 ] );

    expected_data = xcalloc( 1, ( size_t ) ( stats_len * 2 ) );
    memcpy( expected_data, tbf_stats[ 0 ], stats_len );
    memcpy( ( char * ) expected_data + stats_len, tbf_stats[ 1 ], stats_len );

    buffer = create_table_features_multipart_reply( TRANSACTION_ID, flags, table_ftr_stats );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );
    multipart_reply = ( struct ofp_multipart_reply * ) ( ( char * ) buffer->data + sizeof( openflow_service_header_t ) );
    body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                              offsetof( struct ofp_multipart_reply, body ) );

    expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_reply_handler, type32, OFPMP_TABLE_FEATURES );
    expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_reply_handler, data->length, body_len );
    expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
    expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    xfree( tbf_stats[ 0 ] );
    xfree( tbf_stats[ 1 ] );
    delete_list( table_ftr_stats );
    xfree( expected_data );
    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" ) );
  }
  {
    void *expected_data;
    uint16_t flags = OFPMPF_REPLY_MORE;
    uint16_t stats_len;
    uint32_t body_len;
    buffer *buffer;
    list_element *port_desc_stats;
    struct ofp_multipart_reply *multipart_reply;
    struct ofp_port *port_stats[ 2 ];
    char name[OFP_MAX_PORT_NAME_LEN] = "PortName";

    stats_len = sizeof( struct ofp_port );

    port_stats[ 0 ] = xcalloc( 1, stats_len );
    port_stats[ 1 ] = xcalloc( 1, stats_len );

    port_stats[ 0 ]->port_no = 1;
    memset( port_stats[ 0 ]->pad, 0, sizeof( port_stats[ 0 ]->pad ) );
    memcpy( port_stats[ 0 ]->hw_addr, MAC_ADDR_X, sizeof( OFP_ETH_ALEN ) );
    memset( port_stats[ 0 ]->pad2, 0, sizeof( port_stats[ 0 ]->pad2 ) );
    memcpy( port_stats[ 0 ]->name, name, sizeof( name ) );
    port_stats[ 0 ]->config = OFPPC_PORT_DOWN;
    port_stats[ 0 ]->state = OFPPS_BLOCKED;
    port_stats[ 0 ]->curr = PORT_FEATURES;
    port_stats[ 0 ]->advertised = PORT_FEATURES;
    port_stats[ 0 ]->supported = PORT_FEATURES;
    port_stats[ 0 ]->peer = PORT_FEATURES;
    port_stats[ 0 ]->curr_speed = 0x11223344;
    port_stats[ 0 ]->max_speed = 0xAABBCCDD;

    memcpy( port_stats[ 1 ], port_stats[ 0 ], stats_len );
    port_stats[ 1 ]->port_no = 2;

    create_list( &port_desc_stats );
    append_to_tail( &port_desc_stats, port_stats[ 0 ] );
    append_to_tail( &port_desc_stats, port_stats[ 1 ] );

    expected_data = xcalloc( 1, ( size_t ) ( stats_len * 2 ) );
    memcpy( expected_data, port_stats[ 0 ], stats_len );
    memcpy( ( char * ) expected_data + stats_len, port_stats[ 1 ], stats_len );

    buffer = create_port_desc_multipart_reply( TRANSACTION_ID, flags, port_desc_stats );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );

    multipart_reply = ( struct ofp_multipart_reply * ) ( ( char * ) buffer->data + sizeof( openflow_service_header_t ) );
    body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                              offsetof( struct ofp_multipart_reply, body ) );

    expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_reply_handler, type32, OFPMP_PORT_DESC );
    expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_reply_handler, data->length, body_len );
    expect_memory( mock_multipart_reply_handler, data->data, expected_data, stats_len );
    expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    xfree( port_stats[ 0 ] );
    xfree( port_stats[ 1 ] );
    delete_list( port_desc_stats );
    xfree( expected_data );
    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" ) );
  }
  {
    void *expected_data;
    uint16_t flags = 0;
    uint16_t stats_len;
    uint32_t body_len;
    uint32_t experimenter = VENDOR_ID;
    uint32_t exp_type = 1;
    buffer *body, *experimenter_multipart_reply;
    struct ofp_multipart_reply *multipart_reply;
    struct ofp_experimenter_multipart_header *exp_stats;

    body = alloc_buffer_with_length( 128 );
    append_back_buffer( body, 128 );
    memset( body->data, 0xa1, body->length );
    experimenter_multipart_reply = create_experimenter_multipart_reply( TRANSACTION_ID, flags, experimenter, exp_type, body );
    append_front_buffer( experimenter_multipart_reply, sizeof( openflow_service_header_t ) );
    memcpy( experimenter_multipart_reply->data, &messenger_header, sizeof( openflow_service_header_t ) );

    stats_len = ( uint16_t ) ( sizeof( struct ofp_experimenter_multipart_header ) + body->length );

    expected_data = xcalloc( 1, ( size_t ) stats_len );
    exp_stats = ( struct ofp_experimenter_multipart_header * ) expected_data;
    exp_stats->experimenter = experimenter;
    exp_stats->exp_type = exp_type;
    memcpy( exp_stats + 1, body->data, body->length );

    multipart_reply = ( struct ofp_multipart_reply * ) ( ( char * ) experimenter_multipart_reply->data + sizeof( openflow_service_header_t ) );
    body_len = ( uint32_t ) ( ntohs( multipart_reply->header.length ) -
                              offsetof( struct ofp_multipart_reply, body ) );

    expect_memory( mock_multipart_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_multipart_reply_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_reply_handler, type32, OFPMP_EXPERIMENTER );
    expect_value( mock_multipart_reply_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_reply_handler, data->length, body_len );
    expect_memory( mock_multipart_reply_handler, data->data, expected_data, body_len );
    expect_memory( mock_multipart_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_reply_handler( mock_multipart_reply_handler, USER_DATA );
    handle_openflow_message( experimenter_multipart_reply->data, experimenter_multipart_reply->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );


    xfree( expected_data );
    free_buffer( body );
    free_buffer( experimenter_multipart_reply );
    xfree( delete_hash_entry( stats, "openflow_application_interface.multipart_reply_receive_succeeded" ) );
  }

  // barrier_reply
  {
    buffer *buffer;

    buffer = create_barrier_reply( TRANSACTION_ID );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );

    expect_memory( mock_barrier_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_barrier_reply_handler, transaction_id, TRANSACTION_ID );
    expect_memory( mock_barrier_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_barrier_reply_handler( mock_barrier_reply_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.barrier_reply_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.barrier_reply_receive_succeeded" ) );
  }

  // queue_get_config_reply
  {
    size_t queue_len;
    uint32_t port = 1;
    list_element *list;
    buffer *expected_message;
    struct ofp_packet_queue *queue[ 2 ];
    struct ofp_queue_prop_min_rate *prop_header;

    queue_len = offsetof( struct ofp_packet_queue, properties ) + sizeof( struct ofp_queue_prop_min_rate );
    queue[ 0 ] = xcalloc( 1, queue_len );
    queue[ 1 ] = xcalloc( 1, queue_len );

    queue[ 0 ]->queue_id = 1;
    queue[ 0 ]->port = 2;
    queue[ 0 ]->len = ( uint16_t ) queue_len;
    prop_header = ( struct ofp_queue_prop_min_rate * ) queue[ 0 ]->properties;
    prop_header->prop_header.property = OFPQT_MIN_RATE;
    prop_header->prop_header.len = sizeof( struct ofp_queue_prop_min_rate );
    prop_header->rate = 1234;

    queue[ 1 ]->queue_id = 2;
    queue[ 1 ]->port = 3;
    queue[ 1 ]->len = ( uint16_t ) queue_len;
    prop_header = ( struct ofp_queue_prop_min_rate * ) queue[ 1 ]->properties;
    prop_header->prop_header.property = OFPQT_MIN_RATE;
    prop_header->prop_header.len = sizeof( struct ofp_queue_prop_min_rate );
    prop_header->rate = 5678;

    create_list( &list );
    append_to_tail( &list, queue[ 0 ] );
    append_to_tail( &list, queue[ 1 ] );

    expected_message = create_queue_get_config_reply( TRANSACTION_ID, port, list );
    append_front_buffer( expected_message, sizeof( openflow_service_header_t ) );
    memcpy( expected_message->data, &messenger_header, sizeof( openflow_service_header_t ) );

    expect_memory( mock_queue_get_config_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_queue_get_config_reply_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_queue_get_config_reply_handler, port, port );
    expect_memory( mock_queue_get_config_reply_handler, queue1, queue[ 0 ], queue_len );
    expect_memory( mock_queue_get_config_reply_handler, queue2, queue[ 1 ], queue_len );
    expect_memory( mock_queue_get_config_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_queue_get_config_reply_handler( mock_queue_get_config_reply_handler, USER_DATA );
    handle_openflow_message( expected_message->data, expected_message->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.queue_get_config_reply_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    xfree( queue[ 0 ] );
    xfree( queue[ 1 ] );
    delete_list( list );
    free_buffer( expected_message );
    xfree( delete_hash_entry( stats, "openflow_application_interface.queue_get_config_reply_receive_succeeded" ) );
  }

  // role_reply
  {
    uint32_t role = OFPCR_ROLE_NOCHANGE;
    uint64_t generation_id = 0xAAAABBBBCCCCDDDD;
    buffer *buffer;

    buffer = create_role_reply( TRANSACTION_ID, role, generation_id );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );
    expect_memory( mock_role_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_role_reply_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_role_reply_handler, role, role );
    expect_memory( mock_role_reply_handler, &generation_id, &generation_id, sizeof( uint64_t ) );
    expect_memory( mock_role_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_role_reply_handler( mock_role_reply_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.role_reply_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.role_reply_receive_succeeded" ) );
  }

  // get_async_reply
  {
    const uint32_t packet_in_mask[2] = { OFPR_ACTION, OFPR_INVALID_TTL };
    const uint32_t port_status_mask[2] = { OFPPR_DELETE, OFPPR_MODIFY };
    const uint32_t flow_removed_mask[2] = { OFPRR_DELETE, OFPRR_GROUP_DELETE };

    buffer *buffer = create_get_async_reply( TRANSACTION_ID, packet_in_mask, port_status_mask, flow_removed_mask );
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );
    expect_memory( mock_get_async_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
    expect_value( mock_get_async_reply_handler, transaction_id, TRANSACTION_ID );
    expect_memory( mock_get_async_reply_handler, packet_in_mask, packet_in_mask, (sizeof( uint32_t ) * 2) );
    expect_memory( mock_get_async_reply_handler, port_status_mask, port_status_mask, (sizeof( uint32_t ) * 2) );
    expect_memory( mock_get_async_reply_handler, flow_removed_mask, flow_removed_mask, (sizeof( uint32_t ) * 2) );
    expect_memory( mock_get_async_reply_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_get_async_reply_handler( mock_get_async_reply_handler, USER_DATA );
    handle_openflow_message( buffer->data, buffer->length );

    stat = lookup_hash_entry( stats, "openflow_application_interface.get_async_reply_receive_succeeded" );
    assert_int_equal( ( int ) stat->value, 1 );

    free_buffer( buffer );
    xfree( delete_hash_entry( stats, "openflow_application_interface.get_async_reply_receive_succeeded" ) );
  }

  // unhandled message
  {
    buffer *buffer;

    buffer = create_hello( TRANSACTION_ID, NULL );
    struct ofp_header *header = buffer->data;
    header->type = OFPT_QUEUE_GET_CONFIG_REPLY + 1;
    append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
    memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );

    // FIXME
    handle_openflow_message( buffer->data, buffer->length );

    free_buffer( buffer );
  }
}


static void
test_handle_openflow_message_with_malformed_message() {
  buffer *buffer;
  openflow_service_header_t messenger_header;
  struct ofp_header *header;

  messenger_header.datapath_id = htonll( DATAPATH_ID );
  messenger_header.service_name_length = 0;

  buffer = create_hello( TRANSACTION_ID, NULL );
  header = buffer->data;
  header->length = htons( UINT16_MAX );
  append_front_buffer( buffer, sizeof( openflow_service_header_t ) );
  memcpy( buffer->data, &messenger_header, sizeof( openflow_service_header_t ) );

  handle_openflow_message( buffer->data, buffer->length );
    
  free_buffer( buffer );
}


static void
test_handle_openflow_message_if_message_is_NULL() {
  expect_assert_failure( handle_openflow_message( NULL, 1 ) );
}


static void
test_handle_openflow_message_if_message_length_is_zero() {
  buffer *data;

  data = alloc_buffer_with_length( 32 );

  expect_assert_failure( handle_openflow_message( data, 0 ) );

  free_buffer( data );
}


static void
test_handle_openflow_message_if_unhandled_message_type() {
  buffer *data;

  data = alloc_buffer_with_length( 32 );
  append_back_buffer( data, 32 );

  // FIXME
  handle_openflow_message( data, data->length );

  free_buffer( data );
}


/********************************************************************************
 * handle_message() tests.
 ********************************************************************************/

static void
test_handle_message_if_type_is_MESSENGER_OPENFLOW_MESSAGE() {
  buffer *data;
  openflow_service_header_t *header;

  data = create_barrier_reply( TRANSACTION_ID );

  assert_true( data != NULL );

  append_front_buffer( data, sizeof( openflow_service_header_t ) );

  header = data->data;
  header->datapath_id = htonll( DATAPATH_ID );
  header->service_name_length = 0;

  expect_memory( mock_barrier_reply_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_barrier_reply_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_barrier_reply_handler, user_data, BARRIER_REPLY_USER_DATA );

  set_barrier_reply_handler( mock_barrier_reply_handler, BARRIER_REPLY_USER_DATA );
  handle_message( MESSENGER_OPENFLOW_MESSAGE, data->data, data->length );

  stat_entry *stat = lookup_hash_entry( stats, "openflow_application_interface.barrier_reply_receive_succeeded" );
  assert_int_equal( ( int ) stat->value, 1 );


  free_buffer( data );
  xfree( delete_hash_entry( stats, "openflow_application_interface.barrier_reply_receive_succeeded" ) );
}


static void
test_handle_message_if_type_is_MESSENGER_OPENFLOW_CONNECTED() {
  buffer *data = alloc_buffer_with_length( sizeof( openflow_service_header_t ) );
  append_back_buffer( data, sizeof( openflow_service_header_t ) );

  handle_message( MESSENGER_OPENFLOW_CONNECTED, data->data, data->length );

  stat_entry *stat = lookup_hash_entry( stats, "openflow_application_interface.switch_connected_receive_succeeded" );
  assert_int_equal( ( int ) stat->value, 1 );

  free_buffer( data );
  xfree( delete_hash_entry( stats, "openflow_application_interface.switch_connected_receive_succeeded" ) );
}


static void
test_handle_message_if_type_is_MESSENGER_OPENFLOW_DISCONNECTED() {
  uint64_t *datapath_id;
  buffer *data;

  data = alloc_buffer_with_length( sizeof( openflow_service_header_t ) );
  datapath_id = append_back_buffer( data, sizeof( openflow_service_header_t ) );

  *datapath_id = htonll( DATAPATH_ID );

  expect_memory( mock_switch_disconnected_handler, &datapath_id, &DATAPATH_ID, sizeof( uint64_t ) );
  expect_value( mock_switch_disconnected_handler, user_data, SWITCH_DISCONNECTED_USER_DATA );

  expect_string( mock_clear_send_queue, service_name, REMOTE_SERVICE_NAME );
  will_return( mock_clear_send_queue, true );

  set_switch_disconnected_handler( mock_switch_disconnected_handler, SWITCH_DISCONNECTED_USER_DATA );
  handle_message( MESSENGER_OPENFLOW_DISCONNECTED, data->data, data->length );

  stat_entry *stat = lookup_hash_entry( stats, "openflow_application_interface.switch_disconnected_receive_succeeded" );
  assert_int_equal( ( int ) stat->value, 1 );

  free_buffer( data );
  xfree( delete_hash_entry( stats, "openflow_application_interface.switch_disconnected_receive_succeeded" ) );
}


static void
test_handle_message_if_message_is_NULL() {
  expect_assert_failure( handle_message( MESSENGER_OPENFLOW_MESSAGE, NULL, 1 ) );
}


static void
test_handle_message_if_message_length_is_zero() {
  buffer *data;

  data = alloc_buffer_with_length( sizeof( openflow_service_header_t ) );

  expect_assert_failure( handle_message( MESSENGER_OPENFLOW_MESSAGE, data->data, 0 ) );

  free_buffer( data );
}


static void
test_handle_message_if_unhandled_message_type() {
  buffer *data;

  data = alloc_buffer_with_length( sizeof( openflow_service_header_t ) );
  append_back_buffer( data, sizeof( openflow_service_header_t ) );

  // FIXME
  handle_message( MESSENGER_OPENFLOW_DISCONNECTED + 1, data->data, data->length );

  stat_entry *stat = lookup_hash_entry( stats, "openflow_application_interface.undefined_switch_event_receive_succeeded" );
  assert_int_equal( ( int ) stat->value, 1 );

  free_buffer( data );
  xfree( delete_hash_entry( stats, "openflow_application_interface.undefined_switch_event_receive_succeeded" ) );
}


/********************************************************************************
 * delete_openflow_messages() tests.
 ********************************************************************************/

static void
test_delete_openflow_messages() {
  expect_string( mock_clear_send_queue, service_name, REMOTE_SERVICE_NAME );
  will_return( mock_clear_send_queue, true );

  assert_true( delete_openflow_messages( DATAPATH_ID ) );
}


static void
test_delete_openflow_messages_if_clear_send_queue_fails() {
  expect_string( mock_clear_send_queue, service_name, REMOTE_SERVICE_NAME );
  will_return( mock_clear_send_queue, false );

  assert_false( delete_openflow_messages( DATAPATH_ID ) );
}


/********************************************************************************
 * Run tests.
 ********************************************************************************/

int
main() {
  const UnitTest tests[] = {
    // initialization and finalization tests.
    unit_test_setup_teardown( test_init_openflow_application_interface_with_valid_custom_service_name, cleanup, cleanup ),
    unit_test_setup_teardown( test_init_openflow_application_interface_with_too_long_custom_service_name, cleanup, cleanup ),
    unit_test_setup_teardown( test_init_openflow_application_interface_if_already_initialized, init, cleanup ),

    unit_test_setup_teardown( test_finalize_openflow_application_interface, init, cleanup ),
    unit_test_setup_teardown( test_finalize_openflow_application_interface_if_not_initialized, cleanup, cleanup ),

    unit_test_setup_teardown( test_set_openflow_event_handlers, init, cleanup ),

    // switch ready handler tests.
    unit_test_setup_teardown( test_set_switch_ready_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_simple_switch_ready_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_switch_ready_handler_should_die_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_switch_ready, init, cleanup ),
    unit_test_setup_teardown( test_handle_switch_ready_with_simple_handler, init, cleanup ),

    // switch disconnected handler tests.
    unit_test_setup_teardown( test_set_switch_disconnected_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_switch_disconnected_handler_if_handler_is_NULL, init, cleanup ),

    // error handler tests.
    unit_test_setup_teardown( test_set_error_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_error_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_error, init, cleanup ),
    unit_test_setup_teardown( test_handle_error_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_error_if_message_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_error_if_message_length_is_zero, init, cleanup ),

    // experimenter error handler tests.
    unit_test_setup_teardown( test_set_experimenter_error_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_experimenter_error_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_experimenter_error, init, cleanup ),
    unit_test_setup_teardown( test_handle_experimenter_error_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_experimenter_error_if_message_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_experimenter_error_if_message_length_is_zero, init, cleanup ),

    // echo_reply handler tests.
    unit_test_setup_teardown( test_set_echo_reply_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_echo_reply_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_echo_reply, init, cleanup ),
    unit_test_setup_teardown( test_handle_echo_reply_without_data, init, cleanup ),
    unit_test_setup_teardown( test_handle_echo_reply_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_echo_reply_if_message_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_echo_reply_if_message_length_is_zero, init, cleanup ),

    // experimenter handler tests.
    unit_test_setup_teardown( test_set_experimenter_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_experimenter_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_experimenter, init, cleanup ),
    unit_test_setup_teardown( test_handle_experimenter_without_data, init, cleanup ),
    unit_test_setup_teardown( test_handle_experimenter_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_experimenter_if_message_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_experimenter_if_message_length_is_zero, init, cleanup ),

    // features reply handler tests.
    unit_test_setup_teardown( test_set_features_reply_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_features_reply_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_features_reply, init, cleanup ),
    unit_test_setup_teardown( test_handle_features_reply_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_features_reply_if_message_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_features_reply_if_message_length_is_zero, init, cleanup ),

    // get config reply handler tests.
    unit_test_setup_teardown( test_set_get_config_reply_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_get_config_reply_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_get_config_reply, init, cleanup ),
    unit_test_setup_teardown( test_handle_get_config_reply_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_get_config_reply_if_message_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_get_config_reply_if_message_length_is_zero, init, cleanup ),

    // flow removed handler tests.
    unit_test_setup_teardown( test_set_flow_removed_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_flow_removed_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_flow_removed, init, cleanup ),
    unit_test_setup_teardown( test_handle_flow_removed_with_simple_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_simple_flow_removed_handler, init, cleanup ),
    unit_test_setup_teardown( test_handle_flow_removed_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_flow_removed_if_message_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_flow_removed_if_message_length_is_zero, init, cleanup ),

    // port status handler tests.
    unit_test_setup_teardown( test_set_port_status_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_port_status_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_port_status, init, cleanup ),
    unit_test_setup_teardown( test_handle_port_status_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_port_status_if_message_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_port_status_if_message_length_is_zero, init, cleanup ),

    // multipart reply handler tests.
    unit_test_setup_teardown( test_set_multipart_reply_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_multipart_reply_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_reply_if_type_is_OFPMP_DESC, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_reply_if_type_is_OFPMP_FLOW, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_reply_if_type_is_OFPMP_AGGREGATE, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_reply_if_type_is_OFPMP_TABLE, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_reply_if_type_is_OFPMP_PORT_STATS, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_reply_if_type_is_OFPMP_QUEUE, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_reply_if_type_is_OFPMP_GROUP, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_reply_if_type_is_OFPMP_GROUP_DESC, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_reply_if_type_is_OFPMP_GROUP_FEATURES, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_reply_if_type_is_OFPMP_METER, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_reply_if_type_is_OFPMP_METER_CONFIG, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_reply_if_type_is_OFPMP_METER_FEATURES, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_reply_if_type_is_OFPMP_TABLE_FEATURES, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_reply_if_type_is_OFPMP_PORT_DESC, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_reply_if_type_is_OFPMP_EXPERIMENTER, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_reply_with_undefined_type, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_reply_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_reply_if_message_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_reply_if_message_length_is_zero, init, cleanup ),

    // barrier reply handler tests.
    unit_test_setup_teardown( test_set_barrier_reply_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_barrier_reply_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_barrier_reply, init, cleanup ),
    unit_test_setup_teardown( test_handle_barrier_reply_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_barrier_reply_if_message_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_barrier_reply_if_message_length_is_zero, init, cleanup ),

    // queue get config reply handler tests.
    unit_test_setup_teardown( test_set_queue_get_config_reply_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_queue_get_config_reply_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_queue_get_config_reply, init, cleanup ),
    unit_test_setup_teardown( test_handle_queue_get_config_reply_without_queues, init, cleanup ),
    unit_test_setup_teardown( test_handle_queue_get_config_reply_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_queue_get_config_reply_if_message_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_queue_get_config_reply_if_message_length_is_zero, init, cleanup ),

    // role reply handler tests.
    unit_test_setup_teardown( test_set_role_reply_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_role_reply_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_role_reply, init, cleanup ),
    unit_test_setup_teardown( test_handle_role_reply_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_role_reply_if_message_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_role_reply_if_message_length_is_zero, init, cleanup ),

    // get async reply handler tests.
    unit_test_setup_teardown( test_set_get_async_reply_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_get_async_reply_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_get_async_reply, init, cleanup ),
    unit_test_setup_teardown( test_handle_get_async_reply_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_get_async_reply_if_message_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_get_async_reply_if_message_length_is_zero, init, cleanup ),

    // list switches reply handler tests.
    unit_test_setup_teardown( test_set_list_switches_reply_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_list_switches_reply_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_list_switches_reply, init, cleanup ),
    unit_test_setup_teardown( test_handle_list_switches_reply_if_data_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_list_switches_reply_if_length_is_zero, init, cleanup ),

    // packet-in handler tests.
    unit_test_setup_teardown( test_set_packet_in_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_simple_packet_in_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_packet_in_handler_should_die_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_packet_in, init, cleanup ),
    unit_test_setup_teardown( test_handle_packet_in_with_simple_handler, init, cleanup ),
    unit_test_setup_teardown( test_handle_packet_in_with_malformed_packet, init, cleanup ),
    unit_test_setup_teardown( test_handle_packet_in_without_data, init, cleanup ),
    unit_test_setup_teardown( test_handle_packet_in_without_handler, init, cleanup ),
    unit_test_setup_teardown( test_handle_packet_in_should_die_if_message_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_packet_in_should_die_if_message_length_is_zero, init, cleanup ),

    // miscellaneous tests.
    unit_test_setup_teardown( test_insert_dpid, init, cleanup ),
    unit_test_setup_teardown( test_insert_dpid_if_head_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_insert_dpid_if_dpid_is_NULL, init, cleanup ),

    unit_test_setup_teardown( test_handle_switch_events_if_type_is_MESSENGER_OPENFLOW_CONNECTED, init, cleanup ),
    unit_test_setup_teardown( test_handle_switch_events_if_type_is_MESSENGER_OPENFLOW_DISCONNECTED, init, cleanup ),
    unit_test_setup_teardown( test_handle_switch_events_if_message_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_switch_events_if_message_length_is_zero, init, cleanup ),
    unit_test_setup_teardown( test_handle_switch_events_if_message_length_is_too_big, init, cleanup ),
    unit_test_setup_teardown( test_handle_switch_events_if_unhandled_message_type, init, cleanup ),

    unit_test_setup_teardown( test_handle_openflow_message, init, cleanup ),
    unit_test_setup_teardown( test_handle_openflow_message_with_malformed_message, init, cleanup ),
    unit_test_setup_teardown( test_handle_openflow_message_if_message_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_openflow_message_if_message_length_is_zero, init, cleanup ),
    unit_test_setup_teardown( test_handle_openflow_message_if_unhandled_message_type, init, cleanup ),

    unit_test_setup_teardown( test_handle_message_if_type_is_MESSENGER_OPENFLOW_MESSAGE, init, cleanup ),
    unit_test_setup_teardown( test_handle_message_if_type_is_MESSENGER_OPENFLOW_CONNECTED, init, cleanup ),
    unit_test_setup_teardown( test_handle_message_if_type_is_MESSENGER_OPENFLOW_DISCONNECTED, init, cleanup ),
    unit_test_setup_teardown( test_handle_message_if_message_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_message_if_message_length_is_zero, init, cleanup ),
    unit_test_setup_teardown( test_handle_message_if_unhandled_message_type, init, cleanup ),

    // send_openflow_message() tests.
    unit_test_setup_teardown( test_send_openflow_message, init, cleanup ),
    unit_test_setup_teardown( test_send_openflow_message_if_message_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_send_openflow_message_if_message_length_is_zero, init, cleanup ),

    // delete_openflow_messages() tests.
    unit_test_setup_teardown( test_delete_openflow_messages, init, cleanup ),
    unit_test_setup_teardown( test_delete_openflow_messages_if_clear_send_queue_fails, init, cleanup ),
  };
  setup_leak_detector();
  return run_tests( tests );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
