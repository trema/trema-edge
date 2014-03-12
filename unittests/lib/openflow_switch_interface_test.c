/*
 * Unit tests for OpenFlow Application Interface.
 *
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


#include <openflow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bool.h"
#include "checks.h"
#include "cmockery_trema.h"
#include "buffer.h"
#include "hash_table.h"
#include "log.h"
#include "messenger.h"
#include "timer.h"
#include "secure_channel.h"
#include "openflow_switch_interface.h"
#include "openflow_message.h"
#include "wrapper.h"


/********************************************************************************
 * Helpers.
 ********************************************************************************/

extern buffer *create_multipart_request( const uint32_t transaction_id,
       const uint16_t type, const uint16_t length, const uint16_t flags );
extern void handle_local_message( uint16_t tag, void *data, size_t length );
extern void handle_experimenter_error( buffer *data );
extern void handle_error( buffer *data );
extern void handle_experimenter( buffer *data );
extern void handle_packet_out( buffer *data );
extern void handle_flow_mod( buffer *data );
extern void handle_group_mod( buffer *data );
extern void handle_port_mod( buffer *data );
extern void handle_table_mod( buffer *data );
extern void handle_multipart_request( buffer *data );
extern void handle_queue_get_config_request( buffer *data );
extern void handle_role_request( buffer *data );
extern void handle_get_async_request( buffer *data );
extern void handle_set_async( buffer *data );
extern void handle_meter_mod( buffer *data );
extern bool handle_openflow_message( buffer *message );

extern bool openflow_switch_interface_initialized;
extern openflow_switch_event_handlers event_handlers;
extern hash_table *contexts;

#define CONTROLLER_CONNECTED_HANDLER ( ( void * ) 0x00020001 )
#define CONTROLLER_CONNECTED_USER_DATA ( ( void * ) 0x00020011 )
#define CONTROLLER_DISCONNECTED_HANDLER ( ( void * ) 0x00020002 )
#define CONTROLLER_DISCONNECTED_USER_DATA ( ( void * ) 0x00020021 )
#define HELLO_HANDLER ( ( void * ) 0x00010001 )
#define HELLO_USER_DATA ( ( void * ) 0x00010011 )
#define ERROR_HANDLER ( ( void * ) 0x00010002 )
#define ERROR_USER_DATA ( ( void * ) 0x00010021 )
#define EXPERIMENTER_ERROR_HANDLER ( ( void * ) 0x00010003 )
#define EXPERIMENTER_ERROR_USER_DATA ( ( void * ) 0x00010031 )
#define ECHO_REQUEST_HANDLER ( ( void * ) 0x00010004 )
#define ECHO_REQUEST_USER_DATA ( ( void * ) 0x00010041 )
#define ECHO_REPLY_HANDLER ( ( void * ) 0x00010005 )
#define ECHO_REPLY_USER_DATA ( ( void * ) 0x00010051 )
#define EXPERIMENTER_HANDLER ( ( void * ) 0x00010006 )
#define EXPERIMENTER_USER_DATA ( ( void * ) 0x00010061 )
#define FEATURES_REQUEST_HANDLER ( ( void * ) 0x00010007 )
#define FEATURES_REQUEST_USER_DATA ( ( void * ) 0x00010071 )
#define GET_CONFIG_REQUEST_HANDLER ( ( void * ) 0x00010008 )
#define GET_CONFIG_REQUEST_USER_DATA ( ( void * ) 0x00010081 )
#define SET_CONFIG_HANDLER ( ( void * ) 0x00010009 )
#define SET_CONFIG_USER_DATA ( ( void * ) 0x00010091 )
#define PACKET_OUT_HANDLER ( ( void * ) 0x0001000a )
#define PACKET_OUT_USER_DATA ( ( void * ) 0x000100a1 )
#define FLOW_MOD_HANDLER ( ( void * ) 0x0001000b )
#define FLOW_MOD_USER_DATA ( ( void * ) 0x000100b1 )
#define GROUP_MOD_HANDLER ( ( void * ) 0x0001000c )
#define GROUP_MOD_USER_DATA ( ( void * ) 0x000100c1 )
#define PORT_MOD_HANDLER ( ( void * ) 0x0001000d )
#define PORT_MOD_USER_DATA ( ( void * ) 0x000100d1 )
#define TABLE_MOD_HANDLER ( ( void * ) 0x0001000e )
#define TABLE_MOD_USER_DATA ( ( void * ) 0x000100e1 )
#define MULTIPART_REQUEST_HANDLER ( ( void * ) 0x0001000f )
#define MULTIPART_REQUEST_USER_DATA ( ( void * ) 0x000100f1 )
#define BARRIER_REQUEST_HANDLER ( ( void * ) 0x00030001 )
#define BARRIER_REQUEST_USER_DATA ( ( void * ) 0x00030011 )
#define QUEUE_GET_CONFIG_REQUEST_HANDLER ( ( void * ) 0x00030002 )
#define QUEUE_GET_CONFIG_REQUEST_USER_DATA ( ( void * ) 0x00030021 )
#define ROLE_REQUEST_HANDLER ( ( void * ) 0x00030003 )
#define ROLE_REQUEST_USER_DATA ( ( void * ) 0x00030031 )
#define GET_ASYNC_REQUEST_HANDLER ( ( void * ) 0x00030004 )
#define GET_ASYNC_REQUEST_USER_DATA ( ( void * ) 0x00030041 )
#define SET_ASYNC_HANDLER ( ( void * ) 0x00030005 )
#define SET_ASYNC_USER_DATA ( ( void * ) 0x00030051 )
#define METER_MOD_HANDLER ( ( void * ) 0x00030006 )
#define METER_MOD_USER_DATA ( ( void * ) 0x00030061 )

static const pid_t PID = 12345;
static char SERVICE_NAME[] = "learning switch application 0";

static openflow_switch_event_handlers NULL_EVENT_HANDLERS = {
  ( void * ) 0, ( void * ) 0, ( void * ) 0, ( void * ) 0,
  ( void * ) 0, ( void * ) 0, ( void * ) 0, ( void * ) 0,
  ( void * ) 0, ( void * ) 0, ( void * ) 0, ( void * ) 0,
  ( void * ) 0, ( void * ) 0, ( void * ) 0, ( void * ) 0,
  ( void * ) 0, ( void * ) 0, ( void * ) 0, ( void * ) 0,
  ( void * ) 0, ( void * ) 0, ( void * ) 0, ( void * ) 0,
  ( void * ) 0, ( void * ) 0, ( void * ) 0, ( void * ) 0,
  ( void * ) 0, ( void * ) 0, ( void * ) 0, ( void * ) 0,
  ( void * ) 0, ( void * ) 0, ( void * ) 0, ( void * ) 0,
  ( void * ) 0, ( void * ) 0, ( void * ) 0, ( void * ) 0,
  ( void * ) 0, ( void * ) 0, ( void * ) 0, ( void * ) 0,
  ( void * ) 0, ( void * ) 0,
};

static uint64_t DATAPATH_ID = 0x0102030405060708ULL;
static uint32_t CONTROLLER_IP = 0x01020304;
static uint16_t CONTROLLER_PORT = 0x0102;
static const uint32_t TRANSACTION_ID = 0x04030201;

#define USER_DATA_LEN 64
static uint8_t USER_DATA[ USER_DATA_LEN ];


/********************************************************************************
 * Mocks.
 ********************************************************************************/


pid_t
mock_getpid() {
  return PID;
}


bool
mock_send_message_to_secure_channel( buffer *message ) {
  UNUSED( message );

  return true;
}


bool
mock_send_message( const char *service_name, const uint16_t tag, const void *data, size_t len ) {
  UNUSED( service_name );
  UNUSED( tag );
  UNUSED( data );
  UNUSED( len );

  return true;
}


bool
mock_init_secure_channel( uint32_t ip, uint16_t port,
                          connected_handler connected_callback,
                          disconnected_handler disconnected_callback ) {
  UNUSED( ip );
  UNUSED( port );
  UNUSED( connected_callback );
  UNUSED( disconnected_callback );

  return true;
}


bool
mock_add_periodic_event_callback( const time_t seconds, timer_callback callback, void *user_data ) {
  UNUSED( seconds );
  UNUSED( callback );
  UNUSED( user_data );

  return true;
}


bool
mock_finalize_secure_channel() {
  return true;
}


bool 
mock_delete_timer_event( timer_callback callback, void *user_data ) {
  UNUSED( callback );
  UNUSED( user_data );

  return true;
}


bool
mock_add_message_received_callback( char *service_name,
                                    void ( *callback )( uint16_t tag, void *data, size_t len ) ) {
  check_expected( service_name );
  check_expected( callback );

  return ( bool ) mock();
}


static void
mock_error_handler( uint32_t transaction_id, uint16_t type, uint16_t code,
                    const buffer *data, void *user_data ) {
  uint32_t type32 = type;
  uint32_t code32 = code;

  check_expected( transaction_id );
  check_expected( type32 );
  check_expected( code32 );
  check_expected( data->length );
  check_expected( data->data );
  check_expected( user_data );
}


static void
mock_experimenter_error_handler( uint32_t transaction_id, uint16_t type,
                                 uint16_t exp_type, uint32_t experimenter,
                                 const buffer *data, void *user_data ) {
  uint32_t type32 = type;
  uint32_t exp_type32 = exp_type;

  check_expected( transaction_id );
  check_expected( type32 );
  check_expected( exp_type32 );
  check_expected( experimenter );
  check_expected( data->length );
  check_expected( data->data );
  check_expected( user_data );
}


static void
mock_experimenter_handler( uint32_t transaction_id, uint32_t experimenter,
                           uint32_t exp_type, const buffer *data, void *user_data ) {
  void *data_uc;

  check_expected( transaction_id );
  check_expected( experimenter );
  check_expected( exp_type );
  if ( data != NULL ) {
    check_expected( data->length );
    check_expected( data->data );
  } else {
    data_uc = ( void * ) ( unsigned long ) data;
    check_expected( data_uc );
  }
  check_expected( user_data );
}


static void
mock_packet_out_handler( uint32_t transaction_id, uint32_t buffer_id, uint32_t in_port,
                         const openflow_actions *actions, const buffer *data, void *user_data ) {
  void *data_uc;
  struct ofp_action_header *action1, *action2;

  action1 = actions->list->data;
  action2 = actions->list->next->data;

  check_expected( transaction_id );
  check_expected( buffer_id );
  check_expected( in_port );
  check_expected( action1 );
  check_expected( action2 );
  if ( data != NULL ) {
    check_expected( data->length );
    check_expected( data->data );
  } else {
    data_uc = ( void * ) ( unsigned long ) data;
    check_expected( data_uc );
  }
  check_expected( user_data );
}


static void
mock_flow_mod_handler( uint32_t transaction_id, uint64_t cookie, uint64_t cookie_mask,
                       uint8_t table_id, uint8_t command, uint16_t idle_timeout,
                       uint16_t hard_timeout, uint16_t priority, uint32_t buffer_id,
                       uint32_t out_port, uint32_t out_group, uint16_t flags,
                       const oxm_matches *match, const openflow_instructions *instructions,
                       void *user_data ) {
  uint32_t table_id32 = table_id;
  uint32_t command32 = command;
  uint32_t idle_timeout32 = idle_timeout;
  uint32_t hard_timeout32 = hard_timeout;
  uint32_t priority32 = priority;
  uint32_t flags32 = flags;
  oxm_match_header *match1, *match2;
  struct ofp_instruction *inst1, *inst2;

  match1 = match->list->data;
  match2 = match->list->next->data;
  inst1 = instructions->list->data;
  inst2 = instructions->list->next->data;

  check_expected( transaction_id );
  check_expected( &cookie );
  check_expected( &cookie_mask );
  check_expected( table_id32 );
  check_expected( command32 );
  check_expected( idle_timeout32 );
  check_expected( hard_timeout32 );
  check_expected( priority32 );
  check_expected( buffer_id );
  check_expected( out_port );
  check_expected( out_group );
  check_expected( flags32 );
  check_expected( match1 );
  check_expected( match2 );
  check_expected( inst1 );
  check_expected( inst2 );
  check_expected( user_data );
}


static void
mock_group_mod_handler( uint32_t transaction_id, uint16_t command, uint8_t type,
                        uint32_t group_id, const list_element *buckets, void *user_data ) {
  struct ofp_bucket *bucket1, *bucket2;

  uint32_t command32 = command;
  uint32_t type32 = type;
  bucket1 = buckets->data;
  bucket2 = buckets->next->data;

  check_expected( transaction_id );
  check_expected( command32 );
  check_expected( type32 );
  check_expected( group_id );
  check_expected( bucket1 );
  check_expected( bucket2 );
  check_expected( user_data );
}


static void
mock_port_mod_handler( uint32_t transaction_id, uint32_t port_no, uint8_t hw_addr[ OFP_ETH_ALEN ],
                       uint32_t config, uint32_t mask, uint32_t advertise, void *user_data ) {
  check_expected( transaction_id );
  check_expected( port_no );
  check_expected( hw_addr );
  check_expected( config );
  check_expected( mask );
  check_expected( advertise );
  check_expected( user_data );
}


static void
mock_table_mod_handler( uint32_t transaction_id, uint8_t table_id, uint32_t config, void *user_data ) {
  uint32_t table_id32 = table_id;

  check_expected( transaction_id );
  check_expected( table_id32 );
  check_expected( config );
  check_expected( user_data );
}


static void
mock_multipart_request_handler( uint32_t transaction_id, uint16_t type, uint16_t flags,
                                const buffer *body, void *user_data ) {
  uint32_t type32 = type;
  uint32_t flags32 = flags;

  check_expected( transaction_id );
  check_expected( type32 );
  check_expected( flags32 );
  if ( body != NULL ) {
    check_expected( body->length );
    check_expected( body->data );
  } else {
    check_expected( body );
  }
  check_expected( user_data );
}


static void
mock_queue_get_config_request_handler( uint32_t transaction_id, uint32_t port, void *user_data ) {
  check_expected( transaction_id );
  check_expected( port );
  check_expected( user_data );
}


static void
mock_role_request_handler( uint32_t transaction_id, uint32_t role,
                           uint64_t generation_id, void *user_data ) {
  check_expected( transaction_id );
  check_expected( role );
  check_expected( &generation_id );
  check_expected( user_data );
}


static void
mock_get_async_request_handler( uint32_t transaction_id, void *user_data ) {
  check_expected( transaction_id );
  check_expected( user_data );
}


static void
mock_set_async_handler( uint32_t transaction_id, uint32_t packet_in_mask[ 2 ],
                        uint32_t port_status_mask[ 2 ], uint32_t flow_removed_mask[ 2 ], void *user_data ) {
  check_expected( transaction_id );
  check_expected( packet_in_mask );
  check_expected( port_status_mask );
  check_expected( flow_removed_mask );
  check_expected( user_data );
}


static void
mock_meter_mod_handler( uint32_t transaction_id, uint16_t command, uint16_t flags,
                        uint32_t meter_id, const list_element *bands, void *user_data ) {
  struct ofp_meter_band_header *bands1, *bands2;

  uint32_t command32 = command;
  uint32_t flags32 = flags;
  bands1 = bands->data;
  bands2 = bands->next->data;

  check_expected( transaction_id );
  check_expected( command32 );
  check_expected( flags32 );
  check_expected( meter_id );
  check_expected( bands1 );
  check_expected( bands2 );
  check_expected( user_data );
}


void
mock_debug( char *format, ... ) {
  UNUSED( format );
}


void
mock_error( char *format, ... ) {
  UNUSED( format );
}


static int
mock_get_logging_level() {
  return LOG_DEBUG;
}


/********************************************************************************
 * Setup and teardown function.
 ********************************************************************************/

static void
cleanup() {
  openflow_switch_interface_initialized = false;

  memset( &event_handlers, 0, sizeof( event_handlers ) );
  memset( USER_DATA, 'Z', sizeof( USER_DATA ) );

  if ( contexts != NULL ) {
    delete_hash( contexts );
    contexts = NULL;
  }
}


static void
noinit() {
  get_logging_level = mock_get_logging_level;

  cleanup();
}


static void
init() {
  bool ret;

  get_logging_level = mock_get_logging_level;

  cleanup();

  expect_string( mock_add_message_received_callback, service_name, SERVICE_NAME );
  expect_value( mock_add_message_received_callback, callback, handle_local_message );
  will_return( mock_add_message_received_callback, true );

  ret = init_openflow_switch_interface( DATAPATH_ID, CONTROLLER_IP, CONTROLLER_PORT );

  assert_true( ret );
  assert_true( openflow_switch_interface_initialized );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * switch_set_error_handler() tests.
 ********************************************************************************/

static void
test_switch_set_error_handler() {
  assert_true( switch_set_error_handler( ERROR_HANDLER, ERROR_USER_DATA ) );
  assert_int_equal( event_handlers.error_callback, ERROR_HANDLER );
  assert_int_equal( event_handlers.error_user_data, ERROR_USER_DATA );
}


static void
test_switch_set_error_handler_if_not_initialized() {
  expect_assert_failure( switch_set_error_handler( ERROR_HANDLER, ERROR_USER_DATA ) );
}


static void
test_switch_set_error_handler_if_handler_is_NULL() {
  expect_assert_failure( switch_set_error_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * switch_set_experimenter_error_handler() tests.
 ********************************************************************************/

static void
test_switch_set_experimenter_error_handler() {
  assert_true( switch_set_experimenter_error_handler( EXPERIMENTER_ERROR_HANDLER, EXPERIMENTER_ERROR_USER_DATA ) );
  assert_int_equal( event_handlers.experimenter_error_callback, EXPERIMENTER_ERROR_HANDLER );
  assert_int_equal( event_handlers.experimenter_error_user_data, EXPERIMENTER_ERROR_USER_DATA );
}


static void
test_switch_set_experimenter_error_handler_if_not_initialized() {
  expect_assert_failure( switch_set_experimenter_error_handler( EXPERIMENTER_ERROR_HANDLER, EXPERIMENTER_ERROR_USER_DATA ) );
}


static void
test_switch_set_experimenter_error_handler_if_handler_is_NULL() {
  expect_assert_failure( switch_set_experimenter_error_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * switch_set_experimenter_handler() tests.
 ********************************************************************************/

static void
test_switch_set_experimenter_handler() {
  assert_true( switch_set_experimenter_handler( EXPERIMENTER_HANDLER, EXPERIMENTER_USER_DATA ) );
  assert_int_equal( event_handlers.experimenter_callback, EXPERIMENTER_HANDLER );
  assert_int_equal( event_handlers.experimenter_user_data, EXPERIMENTER_USER_DATA );
}


static void
test_switch_set_experimenter_handler_if_not_initialized() {
  expect_assert_failure( switch_set_experimenter_handler( EXPERIMENTER_HANDLER, EXPERIMENTER_USER_DATA ) );
}


static void
test_switch_set_experimenter_handler_if_handler_is_NULL() {
  expect_assert_failure( switch_set_experimenter_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * set_group_mod_handler() tests.
 ********************************************************************************/

static void
test_set_group_mod_handler() {
  assert_true( set_group_mod_handler( GROUP_MOD_HANDLER, GROUP_MOD_USER_DATA ) );
  assert_int_equal( event_handlers.group_mod_callback, GROUP_MOD_HANDLER );
  assert_int_equal( event_handlers.group_mod_user_data, GROUP_MOD_USER_DATA );
}


static void
test_set_group_mod_handler_if_not_initialized() {
  expect_assert_failure( set_group_mod_handler( GROUP_MOD_HANDLER, GROUP_MOD_USER_DATA ) );
}


static void
test_set_group_mod_handler_if_handler_is_NULL() {
  expect_assert_failure( set_group_mod_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * set_table_mod_handler() tests.
 ********************************************************************************/

static void
test_set_table_mod_handler() {
  assert_true( set_table_mod_handler( TABLE_MOD_HANDLER, TABLE_MOD_USER_DATA ) );
  assert_int_equal( event_handlers.table_mod_callback, TABLE_MOD_HANDLER );
  assert_int_equal( event_handlers.table_mod_user_data, TABLE_MOD_USER_DATA );
}


static void
test_set_table_mod_handler_if_not_initialized() {
  expect_assert_failure( set_table_mod_handler( TABLE_MOD_HANDLER, TABLE_MOD_USER_DATA ) );
}


static void
test_set_table_mod_handler_if_handler_is_NULL() {
  expect_assert_failure( set_table_mod_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * set_multipart_request_handler() tests.
 ********************************************************************************/

static void
test_set_multipart_request_handler() {
  assert_true( set_multipart_request_handler( MULTIPART_REQUEST_HANDLER, MULTIPART_REQUEST_USER_DATA ) );
  assert_int_equal( event_handlers.multipart_request_callback, MULTIPART_REQUEST_HANDLER );
  assert_int_equal( event_handlers.multipart_request_user_data, MULTIPART_REQUEST_USER_DATA );
}


static void
test_set_multipart_request_handler_if_not_initialized() {
  expect_assert_failure( set_multipart_request_handler( MULTIPART_REQUEST_HANDLER, MULTIPART_REQUEST_USER_DATA ) );
}


static void
test_set_multipart_request_handler_if_handler_is_NULL() {
  expect_assert_failure( set_multipart_request_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * set_role_request_handler() tests.
 ********************************************************************************/

static void
test_set_role_request_handler() {
  assert_true( set_role_request_handler( ROLE_REQUEST_HANDLER, ROLE_REQUEST_USER_DATA ) );
  assert_int_equal( event_handlers.role_request_callback, ROLE_REQUEST_HANDLER );
  assert_int_equal( event_handlers.role_request_user_data, ROLE_REQUEST_USER_DATA );
}


static void
test_set_role_request_handler_if_not_initialized() {
  expect_assert_failure( set_role_request_handler( ROLE_REQUEST_HANDLER, ROLE_REQUEST_USER_DATA ) );
}


static void
test_set_role_request_handler_if_handler_is_NULL() {
  expect_assert_failure( set_role_request_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * set_get_async_request_handler() tests.
 ********************************************************************************/

static void
test_set_get_async_request_handler() {
  assert_true( set_get_async_request_handler( GET_ASYNC_REQUEST_HANDLER, GET_ASYNC_REQUEST_USER_DATA ) );
  assert_int_equal( event_handlers.get_async_request_callback, GET_ASYNC_REQUEST_HANDLER );
  assert_int_equal( event_handlers.get_async_request_user_data, GET_ASYNC_REQUEST_USER_DATA );
}


static void
test_set_get_async_request_handler_if_not_initialized() {
  expect_assert_failure( set_get_async_request_handler( GET_ASYNC_REQUEST_HANDLER, GET_ASYNC_REQUEST_USER_DATA ) );
}


static void
test_set_get_async_request_handler_if_handler_is_NULL() {
  expect_assert_failure( set_get_async_request_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * set_set_async_handler() tests.
 ********************************************************************************/

static void
test_set_set_async_handler() {
  assert_true( set_set_async_handler( SET_ASYNC_HANDLER, SET_ASYNC_USER_DATA ) );
  assert_int_equal( event_handlers.set_async_callback, SET_ASYNC_HANDLER );
  assert_int_equal( event_handlers.set_async_user_data, SET_ASYNC_USER_DATA );
}


static void
test_set_set_async_handler_if_not_initialized() {
  expect_assert_failure( set_set_async_handler( SET_ASYNC_HANDLER, SET_ASYNC_USER_DATA ) );
}


static void
test_set_set_async_handler_if_handler_is_NULL() {
  expect_assert_failure( set_set_async_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * set_meter_mod_handler() tests.
 ********************************************************************************/

static void
test_set_meter_mod_handler() {
  assert_true( set_meter_mod_handler( METER_MOD_HANDLER, METER_MOD_USER_DATA ) );
  assert_int_equal( event_handlers.meter_mod_callback, METER_MOD_HANDLER );
  assert_int_equal( event_handlers.meter_mod_user_data, METER_MOD_USER_DATA );
}


static void
test_set_meter_mod_handler_if_not_initialized() {
  expect_assert_failure( set_meter_mod_handler( METER_MOD_HANDLER, METER_MOD_USER_DATA ) );
}


static void
test_set_meter_mod_handler_if_handler_is_NULL() {
  expect_assert_failure( set_meter_mod_handler( NULL, NULL ) );
  assert_memory_equal( &event_handlers, &NULL_EVENT_HANDLERS, sizeof( event_handlers ) );
}


/********************************************************************************
 * handle_error() tests.
 ********************************************************************************/

static void
test_handle_error() {
  uint16_t type = 0x1234;
  uint16_t code = 0x1234;
  buffer *buffer, *data;
  
  data = alloc_buffer_with_length( 8 );
  append_back_buffer( data, 8 );
  memset( data->data, 'a', 8 );

  buffer = create_error( TRANSACTION_ID, type, code, data );
  
  expect_value( mock_error_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_error_handler, type32, ( uint32_t ) type );
  expect_value( mock_error_handler, code32, ( uint32_t ) code );
  expect_value( mock_error_handler, data->length, data->length );
  expect_memory( mock_error_handler, data->data, data->data, data->length );
  expect_memory( mock_error_handler, user_data, USER_DATA, USER_DATA_LEN );

  switch_set_error_handler( mock_error_handler, USER_DATA );
  handle_error( buffer );

  free_buffer( data );
  free_buffer( buffer );
}


static void
test_handle_error_if_handler_is_not_registered() {
  uint16_t type = 0x1234;
  uint16_t code = 0x1234;
  buffer *buffer, *data;
  
  data = alloc_buffer_with_length( 8 );
  append_back_buffer( data, 8 );
  memset( data->data, 'a', 8 );

  buffer = create_error( TRANSACTION_ID, type, code, data );

  // FIXME

  handle_error( buffer );

  free_buffer( data );
  free_buffer( buffer );
}


static void
test_handle_error_if_message_is_NULL() {
  switch_set_error_handler( mock_error_handler, USER_DATA );
  expect_assert_failure( handle_error( NULL ) );
}


/********************************************************************************
 * handle_error_experimenter() tests.
 ********************************************************************************/

static void
test_handle_error_experimenter() {
  uint16_t type = 0x1122;
  uint16_t exp_type = 0x3344;
  uint32_t experimenter = 0x55667788;
  buffer *buffer, *data;
  
  data = alloc_buffer_with_length( 32 );
  append_back_buffer( data, 32 );
  memset( data->data, 'a', 32 );

  buffer = create_error_experimenter( TRANSACTION_ID, type, exp_type, experimenter, data );
  
  expect_value( mock_experimenter_error_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_experimenter_error_handler, type32, ( uint32_t ) type );
  expect_value( mock_experimenter_error_handler, exp_type32, ( uint32_t ) exp_type );
  expect_value( mock_experimenter_error_handler, experimenter, experimenter );
  expect_value( mock_experimenter_error_handler, data->length, data->length );
  expect_memory( mock_experimenter_error_handler, data->data, data->data, data->length );
  expect_memory( mock_experimenter_error_handler, user_data, USER_DATA, USER_DATA_LEN );

  switch_set_experimenter_error_handler( mock_experimenter_error_handler, USER_DATA );
  handle_experimenter_error( buffer );

  free_buffer( data );
  free_buffer( buffer );
}


static void
test_handle_error_experimenter_if_handler_is_not_registered() {
  uint16_t type = 0x1122;
  uint16_t exp_type = 0x3344;
  uint32_t experimenter = 0x55667788;
  buffer *buffer, *data;
  
  data = alloc_buffer_with_length( 32 );
  append_back_buffer( data, 32 );
  memset( data->data, 'a', 32 );

  buffer = create_error_experimenter( TRANSACTION_ID, type, exp_type, experimenter, data );

  // FIXME

  handle_experimenter_error( buffer );

  free_buffer( data );
  free_buffer( buffer );
}


static void
test_handle_error_experimenter_if_message_is_NULL() {
  switch_set_experimenter_error_handler( mock_experimenter_error_handler, USER_DATA );
  expect_assert_failure( handle_experimenter_error( NULL ) );
}


/********************************************************************************
 * handle_experimenter() tests.
 ********************************************************************************/

static void
test_handle_experimenter() {
  uint32_t experimenter = 0x11223344;
  uint32_t exp_type = 0x55667788;
  buffer *buffer, *data;
  
  data = alloc_buffer_with_length( 32 );
  append_back_buffer( data, 32 );
  memset( data->data, 'a', 32 );

  buffer = create_experimenter( TRANSACTION_ID, experimenter, exp_type, data );
  
  expect_value( mock_experimenter_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_experimenter_handler, experimenter, experimenter );
  expect_value( mock_experimenter_handler, exp_type, exp_type );
  expect_value( mock_experimenter_handler, data->length, data->length );
  expect_memory( mock_experimenter_handler, data->data, data->data, data->length );
  expect_memory( mock_experimenter_handler, user_data, USER_DATA, USER_DATA_LEN );

  switch_set_experimenter_handler( mock_experimenter_handler, USER_DATA );
  handle_experimenter( buffer );
  
  free_buffer( data );
  free_buffer( buffer );
}


static void
test_handle_experimenter_if_handler_is_not_registered() {
  uint32_t experimenter = 0x11223344;
  uint32_t exp_type = 0x55667788;
  buffer *buffer, *data;
  
  data = alloc_buffer_with_length( 32 );
  append_back_buffer( data, 32 );
  memset( data->data, 'a', 32 );

  buffer = create_experimenter( TRANSACTION_ID, experimenter, exp_type, data );
  
  // FIXME
  
  handle_experimenter( buffer );

  free_buffer( data );
  free_buffer( buffer );
}


static void
test_handle_experimenter_if_message_is_NULL() {
  switch_set_experimenter_handler( mock_experimenter_handler, USER_DATA );
  expect_assert_failure( handle_experimenter( NULL ) );
}


/********************************************************************************
 * handle_packet_out() tests.
 ********************************************************************************/

static void
test_handle_packet_out() {
  size_t queue_len;
  uint32_t buffer_id = 0x11223344;
  uint32_t in_port = 0xAABBCCDD;
  openflow_actions *actions;
  struct ofp_action_output *queue[ 2 ];
  buffer *buffer, *data;

  queue_len = sizeof( struct ofp_action_output );
  queue[ 0 ] = xcalloc( 1, queue_len );
  queue[ 1 ] = xcalloc( 1, queue_len );

  queue[ 0 ]->type = OFPAT_OUTPUT;
  queue[ 0 ]->len = ( uint16_t ) queue_len;
  queue[ 0 ]->port = 0x1122;
  queue[ 0 ]->max_len = 0x11;
  queue[ 1 ]->type = OFPAT_OUTPUT;
  queue[ 1 ]->len = ( uint16_t ) queue_len;
  queue[ 1 ]->port = 0xAABB;
  queue[ 1 ]->max_len = 0xAA;
  
  actions = create_actions();
  actions->n_actions = 2;
  create_list( &actions->list );
  append_to_tail( &actions->list, queue[ 0 ] );
  append_to_tail( &actions->list, queue[ 1 ] );
  
  data = alloc_buffer_with_length( 64 );
  append_back_buffer( data, 64 );
  memset( data->data, 0x01, 64 );

  buffer = create_packet_out( TRANSACTION_ID, buffer_id, in_port, actions, data );

  expect_value( mock_packet_out_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_packet_out_handler, buffer_id, buffer_id );
  expect_value( mock_packet_out_handler, in_port, in_port );
  expect_memory( mock_packet_out_handler, action1, queue[ 0 ], queue_len );
  expect_memory( mock_packet_out_handler, action2, queue[ 1 ], queue_len );
  expect_value( mock_packet_out_handler, data->length, data->length );
  expect_memory( mock_packet_out_handler, data->data, data->data, data->length );
  expect_memory( mock_packet_out_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_packet_out_handler( mock_packet_out_handler, USER_DATA );
  handle_packet_out( buffer );

  delete_actions( actions );
  free_buffer( data );
  free_buffer( buffer );
}


static void
test_handle_packet_out_if_handler_is_not_registered() {
  uint16_t queue_len;
  uint32_t buffer_id = 0x11223344;
  uint32_t in_port = 0xAABBCCDD;
  openflow_actions *actions;
  struct ofp_action_output *queue[ 2 ];
  buffer *buffer, *data;

  queue_len = sizeof( struct ofp_action_output );
  queue[ 0 ] = xcalloc( 1, queue_len );
  queue[ 1 ] = xcalloc( 1, queue_len );

  queue[ 0 ]->type = OFPAT_OUTPUT;
  queue[ 0 ]->len = ( uint16_t ) queue_len;
  queue[ 0 ]->port = 0x1122;
  queue[ 0 ]->max_len = 0x11;
  queue[ 1 ]->type = OFPAT_OUTPUT;
  queue[ 1 ]->len = ( uint16_t ) queue_len;
  queue[ 1 ]->port = 0xAABB;
  queue[ 1 ]->max_len = 0xAA;

  actions = create_actions();
  actions->n_actions = 2;
  create_list( &actions->list );
  append_to_tail( &actions->list, queue[ 0 ] );
  append_to_tail( &actions->list, queue[ 1 ] );
  
  data = alloc_buffer_with_length( 64 );
  append_back_buffer( data, 64 );
  memset( data->data, 0x01, 64 );

  buffer = create_packet_out( TRANSACTION_ID, buffer_id, in_port, actions, data );
  
  // FIXME
  
  handle_packet_out( buffer );

  delete_actions( actions );
  free_buffer( data );
  free_buffer( buffer );
}


static void
test_handle_packet_out_if_message_is_NULL() {
  set_packet_out_handler( mock_packet_out_handler, USER_DATA );
  expect_assert_failure( handle_packet_out( NULL ) );
}


/********************************************************************************
 * handle_flow_mod() tests.
 ********************************************************************************/

static void
test_handle_flow_mod() {
  uint64_t cookie = 0x1122334455667788;
  uint64_t cookie_mask = 0x8899AABBCCDDEEFF;
  uint8_t table_id = 0x12;
  uint8_t command = 0x34;
  uint16_t idle_timeout = 0x9876;
  uint16_t hard_timeout = 0xFEDC;
  uint16_t priority = 0x5432;
  uint32_t buffer_id = 0x12345678;
  uint32_t out_port = 0x89ABCDEF;
  uint32_t out_group = 0xFFEEDDCC;
  uint16_t flags = 0xBA98;
  oxm_matches *match;
  size_t match1_len, match2_len;
  oxm_match_header *queue[ 2 ];
  uint32_t* value;
  openflow_instructions *instructions;
  size_t instructions_len;
  struct ofp_instruction_goto_table *inst[ 2 ];
  buffer *buffer;

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

  instructions_len = sizeof ( struct ofp_instruction_goto_table );
  inst[ 0 ] = xcalloc( 1, instructions_len );
  inst[ 0 ]->type = OFPIT_GOTO_TABLE;
  inst[ 0 ]->len = ( uint16_t ) instructions_len;
  inst[ 0 ]->table_id = 0xAB;

  inst[ 1 ] = xcalloc( 1, instructions_len );
  inst[ 1 ]->type = OFPIT_GOTO_TABLE;
  inst[ 1 ]->len = ( uint16_t ) instructions_len;
  inst[ 1 ]->table_id = 0xCD;

  instructions = create_instructions();
  instructions->n_instructions = 2;
  append_to_tail( &instructions->list, inst[ 0 ] );
  append_to_tail( &instructions->list, inst[ 1 ] );

  buffer = create_flow_mod( TRANSACTION_ID, cookie, cookie_mask, table_id, command, idle_timeout,
           hard_timeout, priority, buffer_id, out_port, out_group, flags, match, instructions );
  
  expect_value( mock_flow_mod_handler, transaction_id, TRANSACTION_ID );
  expect_memory( mock_flow_mod_handler, &cookie, &cookie, sizeof( uint64_t ) );
  expect_memory( mock_flow_mod_handler, &cookie_mask, &cookie_mask, sizeof( uint64_t) );
  expect_value( mock_flow_mod_handler, table_id32, ( uint32_t ) table_id );
  expect_value( mock_flow_mod_handler, command32, ( uint32_t ) command );
  expect_value( mock_flow_mod_handler, idle_timeout32, ( uint32_t ) idle_timeout );
  expect_value( mock_flow_mod_handler, hard_timeout32, ( uint32_t ) hard_timeout );
  expect_value( mock_flow_mod_handler, priority32, ( uint32_t ) priority );
  expect_value( mock_flow_mod_handler, buffer_id, buffer_id );
  expect_value( mock_flow_mod_handler, out_port, out_port );
  expect_value( mock_flow_mod_handler, out_group, out_group );
  expect_value( mock_flow_mod_handler, flags32, ( uint32_t ) flags );
  expect_memory( mock_flow_mod_handler, match1, queue[ 0 ], match1_len );
  expect_memory( mock_flow_mod_handler, match2, queue[ 1 ], match2_len );
  expect_memory( mock_flow_mod_handler, inst1, inst[ 0 ], instructions_len );
  expect_memory( mock_flow_mod_handler, inst2, inst[ 1 ], instructions_len );
  expect_memory( mock_flow_mod_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_flow_mod_handler( mock_flow_mod_handler, USER_DATA );
  handle_flow_mod( buffer );
  
  delete_oxm_matches(match);
  delete_instructions(instructions);
  free_buffer( buffer );
}


static void
test_handle_flow_mod_if_handler_is_not_registered() {
  uint64_t cookie = 0x1122334455667788;
  uint64_t cookie_mask = 0x8899AABBCCDDEEFF;
  uint8_t table_id = 0x12;
  uint8_t command = 0x34;
  uint16_t idle_timeout = 0x9876;
  uint16_t hard_timeout = 0xFEDC;
  uint16_t priority = 0x5432;
  uint32_t buffer_id = 0x12345678;
  uint32_t out_port = 0x89ABCDEF;
  uint32_t out_group = 0xFFEEDDCC;
  uint16_t flags = 0xBA98;
  oxm_matches *match;
  size_t match1_len, match2_len;
  oxm_match_header *queue[ 2 ];
  uint32_t* value;
  openflow_instructions *instructions;
  size_t instructions_len;
  struct ofp_instruction_goto_table *inst[ 2 ];
  buffer *buffer;

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

  instructions_len = sizeof ( struct ofp_instruction_goto_table );
  inst[ 0 ] = xcalloc( 1, instructions_len );
  inst[ 0 ]->type = OFPIT_GOTO_TABLE;
  inst[ 0 ]->len = ( uint16_t ) instructions_len;
  inst[ 0 ]->table_id = 0xAB;

  inst[ 1 ] = xcalloc( 1, instructions_len );
  inst[ 1 ]->type = OFPIT_GOTO_TABLE;
  inst[ 1 ]->len = ( uint16_t ) instructions_len;
  inst[ 1 ]->table_id = 0xCD;

  instructions = create_instructions();
  instructions->n_instructions = 2;
  append_to_tail( &instructions->list, inst[ 0 ] );
  append_to_tail( &instructions->list, inst[ 1 ] );

  buffer = create_flow_mod( TRANSACTION_ID, cookie, cookie_mask, table_id, command, idle_timeout,
           hard_timeout, priority, buffer_id, out_port, out_group, flags, match, instructions );
  
  // FIXME
  
  handle_flow_mod( buffer );
  
  delete_oxm_matches(match);
  delete_instructions(instructions);
  free_buffer( buffer );
}


static void
test_handle_flow_mod_if_message_is_NULL() {
  set_flow_mod_handler( mock_flow_mod_handler, USER_DATA );
  expect_assert_failure( handle_flow_mod( NULL ) );
}


/********************************************************************************
 * handle_group_mod() tests.
 ********************************************************************************/

static void
test_handle_group_mod() {
  uint16_t command = 0x1122;
  uint8_t type = 0x33;
  uint32_t group_id = 0x44556677;
  openflow_buckets *buckets;
  uint16_t bucket_len;
  struct ofp_bucket *bucket[ 2 ];
  buffer *buffer;
  struct ofp_action_output *actions;
  uint16_t offset;

  offset = offsetof( struct ofp_bucket, actions );
  bucket_len = ( uint16_t ) ( offset + sizeof( struct ofp_action_output ) );

  bucket[ 0 ] = xcalloc( 1, bucket_len );
  bucket[ 0 ]->len = bucket_len;
  bucket[ 0 ]->weight = 0x1122;
  bucket[ 0 ]->watch_port = 0xAABBCCDD;
  bucket[ 0 ]->watch_group = 0xFFEEDDCC;
  actions = ( struct ofp_action_output * ) ( bucket[ 0 ] + 1 );
  actions->type = OFPAT_OUTPUT;
  actions->len = sizeof( struct ofp_action_output );
  actions->port = 0x01020304;
  actions->max_len = 0xFACE;

  bucket[ 1 ] = xcalloc( 1, bucket_len );
  bucket[ 1 ]->len = bucket_len;
  bucket[ 1 ]->weight = 0x3344;
  bucket[ 1 ]->watch_port = 0xAACCBBDD;
  bucket[ 1 ]->watch_group = 0xFFDDEECC;
  actions = ( struct ofp_action_output * ) ( bucket[ 1 ] + 1 );
  actions->type = OFPAT_OUTPUT;
  actions->len = sizeof( struct ofp_action_output );
  actions->port = 0x05060708;
  actions->max_len = 0xCAFE;

  buckets = create_buckets();
  append_to_tail( &buckets->list, bucket[ 0 ] );
  append_to_tail( &buckets->list, bucket[ 1 ] );

  buffer = create_group_mod( TRANSACTION_ID, command, type, group_id, buckets );
  
  expect_value( mock_group_mod_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_group_mod_handler, command32, ( uint32_t ) command );
  expect_value( mock_group_mod_handler, type32, ( uint32_t ) type );
  expect_value( mock_group_mod_handler, group_id, group_id );
  expect_memory( mock_group_mod_handler, bucket1, bucket[ 0 ], bucket_len );
  expect_memory( mock_group_mod_handler, bucket2, bucket[ 1 ], bucket_len );
  expect_memory( mock_group_mod_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_group_mod_handler( mock_group_mod_handler, USER_DATA );
  handle_group_mod( buffer );

  free_buffer( buffer );
  delete_buckets( buckets );
}


static void
test_handle_group_mod_if_handler_is_not_registered() {
  uint16_t command = 0x1122;
  uint8_t type = 0x33;
  uint32_t group_id = 0x44556677;
  openflow_buckets *buckets;
  uint16_t bucket_len;
  struct ofp_bucket *bucket[ 2 ];
  buffer *buffer;
  struct ofp_action_output *actions;
  uint16_t offset;

  offset = offsetof( struct ofp_bucket, actions );
  bucket_len = ( uint16_t ) ( offset + sizeof( struct ofp_action_output ) );

  bucket[ 0 ] = xcalloc( 1, bucket_len );
  bucket[ 0 ]->len = bucket_len;
  bucket[ 0 ]->weight = 0x1122;
  bucket[ 0 ]->watch_port = 0xAABBCCDD;
  bucket[ 0 ]->watch_group = 0xFFEEDDCC;
  actions = ( struct ofp_action_output * ) ( bucket[ 0 ] + 1 );
  actions->type = OFPAT_OUTPUT;
  actions->len = sizeof( struct ofp_action_output );
  actions->port = 0x01020304;
  actions->max_len = 0xFACE;

  bucket[ 1 ] = xcalloc( 1, bucket_len );
  bucket[ 1 ]->len = bucket_len;
  bucket[ 1 ]->weight = 0x3344;
  bucket[ 1 ]->watch_port = 0xAACCBBDD;
  bucket[ 1 ]->watch_group = 0xFFDDEECC;
  actions = ( struct ofp_action_output * ) ( bucket[ 1 ] + 1 );
  actions->type = OFPAT_OUTPUT;
  actions->len = sizeof( struct ofp_action_output );
  actions->port = 0x05060708;
  actions->max_len = 0xCAFE;

  buckets = create_buckets();
  append_to_tail( &buckets->list, bucket[ 0 ] );
  append_to_tail( &buckets->list, bucket[ 1 ] );

  buffer = create_group_mod( TRANSACTION_ID, command, type, group_id, buckets );
    
  // FIXME
  
  handle_group_mod( buffer );

  free_buffer( buffer );
  delete_buckets( buckets );
}


static void
test_handle_group_mod_if_message_is_NULL() {
  set_group_mod_handler( mock_group_mod_handler, USER_DATA );
  expect_assert_failure( handle_group_mod( NULL ) );
}


/********************************************************************************
 * handle_port_mod() tests.
 ********************************************************************************/

static void
test_handle_port_mod() {
  uint32_t port_no = 0x12345678;
  uint8_t hw_addr[ OFP_ETH_ALEN ] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
  uint32_t config = 0x89ABCDEF;
  uint32_t mask = 0x99887766;
  uint32_t advertise = 0xFFEEDDCC;
  buffer *buffer;

  buffer = create_port_mod( TRANSACTION_ID, port_no, hw_addr, config, mask, advertise );

  expect_value( mock_port_mod_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_port_mod_handler, port_no, port_no );
  expect_memory( mock_port_mod_handler, hw_addr, hw_addr, sizeof( hw_addr ) );
  expect_value( mock_port_mod_handler, config, config );
  expect_value( mock_port_mod_handler, mask, mask );
  expect_value( mock_port_mod_handler, advertise, advertise );
  expect_memory( mock_port_mod_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_port_mod_handler( mock_port_mod_handler, USER_DATA );
  handle_port_mod( buffer );

  free_buffer( buffer );
}


static void
test_handle_port_mod_if_handler_is_not_registered() {
  uint32_t port_no = 0x12345678;
  uint8_t hw_addr[ OFP_ETH_ALEN ] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
  uint32_t config = 0x89ABCDEF;
  uint32_t mask = 0x99887766;
  uint32_t advertise = 0xFFEEDDCC;
  buffer *buffer;

  buffer = create_port_mod( TRANSACTION_ID, port_no, hw_addr, config, mask, advertise );
  
  // FIXME
  
  handle_port_mod( buffer );

  free_buffer( buffer );
}


static void
test_handle_port_mod_if_message_is_NULL() {
  set_port_mod_handler( mock_port_mod_handler, USER_DATA );
  expect_assert_failure( handle_port_mod( NULL ) );
}


/********************************************************************************
 * handle_table_mod() tests.
 ********************************************************************************/

static void
test_handle_table_mod() {
  uint8_t table_id = 0x12;
  uint32_t config = 0x12345678;
  buffer *buffer;

  buffer = create_table_mod( TRANSACTION_ID, table_id, config );

  expect_value( mock_table_mod_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_table_mod_handler, table_id32, ( uint32_t ) table_id );
  expect_value( mock_table_mod_handler, config, config );
  expect_memory( mock_table_mod_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_table_mod_handler( mock_table_mod_handler, USER_DATA );
  handle_table_mod( buffer );

  free_buffer( buffer );
}


static void
test_handle_table_mod_if_handler_is_not_registered() {
  uint8_t table_id = 0x12;
  uint32_t config = 0x12345678;
  buffer *buffer;

  buffer = create_table_mod( TRANSACTION_ID, table_id, config );

  // FIXME

  handle_table_mod( buffer );

  free_buffer( buffer );
}


static void
test_handle_table_mod_if_message_is_NULL() {
  set_table_mod_handler( mock_table_mod_handler, USER_DATA );
  expect_assert_failure( handle_table_mod( NULL ) );
}


/********************************************************************************
 * handle_multipart_request() tests.
 ********************************************************************************/
static void
test_handle_multipart_request() {
  uint16_t type = OFPMP_DESC;
  uint16_t length = ( uint16_t ) sizeof( struct ofp_multipart_request );
  uint16_t flags = 0xABCD;
  buffer *buffer;

  buffer = create_multipart_request( TRANSACTION_ID, type, length, flags );

  expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
  expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
  expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );
  expect_value( mock_multipart_request_handler, body, NULL );

  set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
  handle_multipart_request( buffer );

  free_buffer( buffer );
}


static void
test_handle_multipart_request_if_handler_is_not_registered() {
  uint16_t type = OFPMP_DESC;
  uint16_t length = ( uint16_t ) sizeof( struct ofp_multipart_request );
  uint16_t flags = 0xABCD;
  buffer *buffer;

  buffer = create_multipart_request( TRANSACTION_ID, type, length, flags );

  // FIXME

  handle_multipart_request( buffer );

  free_buffer( buffer );
}


static void
test_handle_multipart_request_if_type_is_OFPMP_DESC() {
  uint16_t type = OFPMP_DESC;
  uint16_t flags = OFPMPF_REQ_MORE;
  buffer *buffer;

  buffer = create_desc_multipart_request( TRANSACTION_ID, flags );

  expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
  expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_request_handler, body, NULL );
  expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
  handle_multipart_request( buffer );

  free_buffer( buffer );
}


static void
test_handle_multipart_request_if_type_is_OFPMP_FLOW() {
  uint16_t type = OFPMP_FLOW;
  uint16_t flags = OFPMPF_REQ_MORE;
  uint8_t table_id = 0x11;
  uint32_t out_port = 0x11223344;
  uint32_t out_group = 0x55667788;
  uint64_t cookie = 0x1111222233334444;
  uint64_t cookie_mask = 0xFFFFEEEEDDDDCCCC;
  oxm_matches *match;
  size_t match1_len, match2_len;
  oxm_match_header *queue[ 2 ];
  uint32_t* value;
  uint16_t body_len_tmp;
  uint32_t body_len;
  buffer *buffer;

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
  
  struct ofp_flow_stats_request *flow_stats_req;

  uint16_t ofp_match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields ) + get_oxm_matches_length( match ) );
  body_len_tmp = ( uint16_t ) ( ofp_match_len + PADLEN_TO_64( ofp_match_len ) );
  uint16_t expected_fs_len = ( uint16_t ) ( offsetof( struct ofp_flow_stats_request, match ) + body_len_tmp );
  flow_stats_req = xcalloc( 1, expected_fs_len );
  flow_stats_req->table_id = table_id;
  flow_stats_req->out_port = out_port;
  flow_stats_req->out_group = out_group;
  flow_stats_req->cookie = cookie;
  flow_stats_req->cookie_mask = cookie_mask;
  construct_ofp_match( &flow_stats_req->match, match );
  ntoh_match( &flow_stats_req->match, &flow_stats_req->match );
  body_len = ( uint32_t ) ( offsetof( struct ofp_flow_stats_request, match ) + body_len_tmp );

  buffer = create_flow_multipart_request( TRANSACTION_ID, flags, table_id, out_port, out_group, cookie, cookie_mask, match );

  expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
  expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_request_handler, body->length, body_len );
  expect_memory( mock_multipart_request_handler, body->data, flow_stats_req, body_len );
  expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
  handle_multipart_request( buffer );

  xfree( flow_stats_req );
  delete_oxm_matches(match);
  free_buffer( buffer );
}


static void
test_handle_multipart_request_if_type_is_OFPMP_AGGREGATE() {
  uint16_t type = OFPMP_AGGREGATE;
  uint16_t flags = OFPMPF_REQ_MORE;
  uint8_t table_id = 0xAB;
  uint32_t out_port = 0x11223344;
  uint32_t out_group = 0x55667788;
  uint64_t cookie = 0x1111222233334444;
  uint64_t cookie_mask = 0xFFFFEEEEDDDDCCCC;
  oxm_matches *match;
  size_t match1_len, match2_len;
  oxm_match_header *queue[ 2 ];
  uint32_t* value;
  uint32_t body_len;
  buffer *buffer;

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

  struct ofp_aggregate_stats_request *aggregte_stats_req;

  uint16_t ofp_match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields ) + get_oxm_matches_length( match ) );
  uint16_t body_len_tmp = ( uint16_t ) ( ofp_match_len + PADLEN_TO_64( ofp_match_len ) );
  uint16_t expected_fs_len = ( uint16_t ) ( offsetof( struct ofp_aggregate_stats_request, match ) + body_len_tmp );
  aggregte_stats_req = xcalloc( 1, expected_fs_len );
  aggregte_stats_req->table_id = table_id;
  aggregte_stats_req->out_port = out_port;
  aggregte_stats_req->out_group = out_group;
  aggregte_stats_req->cookie = cookie;
  aggregte_stats_req->cookie_mask = cookie_mask;
  construct_ofp_match( &aggregte_stats_req->match, match );
  ntoh_match( &aggregte_stats_req->match, &aggregte_stats_req->match );
  body_len = ( uint32_t ) ( offsetof( struct ofp_aggregate_stats_request, match ) + body_len_tmp );

  buffer = create_aggregate_multipart_request( TRANSACTION_ID, flags, table_id, out_port, out_group, cookie, cookie_mask, match );

  expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
  expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_request_handler, body->length, body_len );
  expect_memory( mock_multipart_request_handler, body->data, aggregte_stats_req, body_len );
  expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
  handle_multipart_request( buffer );

  xfree( aggregte_stats_req );
  delete_oxm_matches(match);
  free_buffer( buffer );
}


static void
test_handle_multipart_request_if_type_is_OFPMP_TABLE() {
  uint16_t type = OFPMP_TABLE;
  uint16_t flags = OFPMPF_REQ_MORE;
  buffer *buffer;

  buffer = create_table_multipart_request( TRANSACTION_ID, flags );

  expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
  expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_request_handler, body, NULL );
  expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
  handle_multipart_request( buffer );

  free_buffer( buffer );
}


static void
test_handle_multipart_request_if_type_is_OFPMP_PORT_STATS() {
  uint16_t type = OFPMP_PORT_STATS;
  uint16_t flags = OFPMPF_REQ_MORE;
  uint32_t port_no = 0x11223344;
  uint32_t body_len;
  buffer *buffer;

  struct ofp_port_stats_request *port_stats_req;
  struct ofp_port_stats_request port_stats_req_mod;
  memset(&port_stats_req_mod, 0, sizeof(port_stats_req_mod));

  buffer = create_port_multipart_request( TRANSACTION_ID, flags, port_no );
  port_stats_req = ( struct ofp_port_stats_request * ) ( ( char * ) buffer->data
                       + offsetof( struct ofp_multipart_request, body ) );
  port_stats_req_mod.port_no = ntohl( port_stats_req->port_no );
  memset( &port_stats_req_mod.pad, 0, sizeof( port_stats_req_mod.pad ) );
  body_len = ( uint32_t ) sizeof( struct ofp_port_stats_request );

  expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
  expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_request_handler, body->length, body_len );
  expect_memory( mock_multipart_request_handler, body->data, &port_stats_req_mod, body_len );
  expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
  handle_multipart_request( buffer );

  free_buffer( buffer );
}


static void
test_handle_multipart_request_if_type_is_OFPMP_QUEUE() {
  uint16_t type = OFPMP_QUEUE;
  uint16_t flags = OFPMPF_REQ_MORE;
  uint32_t port_no = 0x11223344;
  uint32_t queue_id = 0xAABBCCDD;
  uint32_t body_len;
  buffer *buffer;

  struct ofp_queue_stats_request *queue_stats_req;
  struct ofp_queue_stats_request queue_stats_req_mod;
  memset(&queue_stats_req_mod, 0, sizeof(queue_stats_req_mod));

  buffer = create_queue_multipart_request( TRANSACTION_ID, flags, port_no, queue_id );
  queue_stats_req = ( struct ofp_queue_stats_request * ) ( ( char * ) buffer->data
                        + offsetof( struct ofp_multipart_request, body ) );
  queue_stats_req_mod.port_no = ntohl( queue_stats_req->port_no );
  queue_stats_req_mod.queue_id = ntohl( queue_stats_req->queue_id );
  body_len = ( uint32_t ) sizeof( struct ofp_queue_stats_request );

  expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
  expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_request_handler, body->length, body_len );
  expect_memory( mock_multipart_request_handler, body->data, &queue_stats_req_mod, body_len );
  expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
  handle_multipart_request( buffer );

  free_buffer( buffer );
}


static void
test_handle_multipart_request_if_type_is_OFPMP_GROUP() {
  uint16_t type = OFPMP_GROUP;
  uint16_t flags = OFPMPF_REQ_MORE;
  uint32_t group_id = 0xAABBCCDD;
  uint32_t body_len;
  buffer *buffer;

  struct ofp_group_stats_request *group_stats_req;
  struct ofp_group_stats_request group_stats_req_mod;
  memset(&group_stats_req_mod, 0, sizeof(group_stats_req_mod));

  buffer = create_group_multipart_request( TRANSACTION_ID, flags, group_id );
  group_stats_req = ( struct ofp_group_stats_request * ) ( ( char * ) buffer->data
                        + offsetof( struct ofp_multipart_request, body ) );
  group_stats_req_mod.group_id = ntohl( group_stats_req->group_id );
  memset( &group_stats_req_mod.pad, 0, sizeof( group_stats_req_mod.pad ) );
  body_len = ( uint32_t ) sizeof( struct ofp_group_stats_request );

  expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
  expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_request_handler, body->length, body_len );
  expect_memory( mock_multipart_request_handler, body->data, &group_stats_req_mod, body_len );
  expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
  handle_multipart_request( buffer );

  free_buffer( buffer );
}


static void
test_handle_multipart_request_if_type_is_OFPMP_GROUP_DESC() {
  uint16_t type = OFPMP_GROUP_DESC;
  uint16_t flags = OFPMPF_REQ_MORE;
  buffer *buffer;

  buffer = create_group_desc_multipart_request( TRANSACTION_ID, flags );

  expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
  expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_request_handler, body, NULL );
  expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
  handle_multipart_request( buffer );

  free_buffer( buffer );
}


static void
test_handle_multipart_request_if_type_is_OFPMP_GROUP_FEATURES() {
  uint16_t type = OFPMP_GROUP_FEATURES;
  uint16_t flags = OFPMPF_REQ_MORE;
  buffer *buffer;

  buffer = create_group_features_multipart_request( TRANSACTION_ID, flags );

  expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
  expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_request_handler, body, NULL );
  expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
  handle_multipart_request( buffer );

  free_buffer( buffer );
}


static void
test_handle_multipart_request_if_type_is_OFPMP_METER() {
  uint16_t type = OFPMP_METER;
  uint16_t flags = OFPMPF_REQ_MORE;
  uint32_t meter_id = 0xAABBCCDD;
  uint32_t body_len;
  buffer *buffer;

  struct ofp_meter_multipart_request *meter_stats_req;
  struct ofp_meter_multipart_request meter_stats_req_mod;
  memset(&meter_stats_req_mod, 0, sizeof(meter_stats_req_mod));

  buffer = create_meter_multipart_request( TRANSACTION_ID, flags, meter_id );
  meter_stats_req = ( struct ofp_meter_multipart_request * ) ( ( char * ) buffer->data
                        + offsetof( struct ofp_multipart_request, body ) );
  meter_stats_req_mod.meter_id = ntohl( meter_stats_req->meter_id );
  memset( &meter_stats_req_mod.pad, 0, sizeof( meter_stats_req_mod.pad ) );
  body_len = ( uint32_t ) sizeof( struct ofp_meter_multipart_request );

  expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
  expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_request_handler, body->length, body_len );
  expect_memory( mock_multipart_request_handler, body->data, &meter_stats_req_mod, body_len );
  expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
  handle_multipart_request( buffer );

  free_buffer( buffer );
}


static void
test_handle_multipart_request_if_type_is_OFPMP_METER_CONFIG() {
  uint16_t type = OFPMP_METER_CONFIG;
  uint16_t flags = OFPMPF_REQ_MORE;
  uint32_t meter_id = 0xAABBCCDD;
  uint32_t body_len;
  buffer *buffer;

  struct ofp_meter_multipart_request *meter_stats_req;
  struct ofp_meter_multipart_request meter_stats_req_mod;
  memset(&meter_stats_req_mod, 0, sizeof(meter_stats_req_mod));

  buffer = create_meter_config_multipart_request( TRANSACTION_ID, flags, meter_id );
  meter_stats_req = ( struct ofp_meter_multipart_request * ) ( ( char * ) buffer->data
                        + offsetof( struct ofp_multipart_request, body ) );
  meter_stats_req_mod.meter_id = ntohl( meter_stats_req->meter_id );
  memset( &meter_stats_req_mod.pad, 0, sizeof( meter_stats_req_mod.pad ) );
  body_len = ( uint32_t ) sizeof( struct ofp_meter_multipart_request );

  expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
  expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_request_handler, body->length, body_len );
  expect_memory( mock_multipart_request_handler, body->data, &meter_stats_req_mod, body_len );
  expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
  handle_multipart_request( buffer );

  free_buffer( buffer );
}


static void
test_handle_multipart_request_if_type_is_OFPMP_METER_FEATURES() {
  uint16_t type = OFPMP_METER_FEATURES;
  uint16_t flags = OFPMPF_REQ_MORE;
  buffer *buffer;

  buffer = create_meter_features_multipart_request( TRANSACTION_ID, flags );

  expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
  expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_request_handler, body, NULL );
  expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
  handle_multipart_request( buffer );

  free_buffer( buffer );
}

static void
test_handle_multipart_request_if_type_is_OFPMP_TABLE_FEATURES() {
  uint16_t type = OFPMP_TABLE_FEATURES;
  uint16_t flags = OFPMPF_REQ_MORE;
  char name[ OFP_MAX_TABLE_NAME_LEN ] = "TableName";
  list_element *table_features_head;
  uint16_t table_features_len;
  struct ofp_table_features *table_features[ 2 ];
  uint32_t body_len;
  buffer *buffer;

  {
    table_features_len = ( uint16_t ) sizeof( struct ofp_table_features );

    table_features[ 0 ] = xcalloc( 1, table_features_len );
    table_features[ 0 ]->length = table_features_len;
    table_features[ 0 ]->table_id = 0x11;
    memset( table_features[ 0 ]->pad, 0, sizeof( table_features[ 0 ]->pad ) );
    memcpy( table_features[ 0 ]->name, name, OFP_MAX_TABLE_NAME_LEN );
    table_features[ 0 ]->metadata_match = 0x1111222233334444;
    table_features[ 0 ]->metadata_write = 0xAAAABBBBCCCCDDDD;
    table_features[ 0 ]->config = 0x99887766;
    table_features[ 0 ]->max_entries = 0xFFEEDDCC;
    
    table_features[ 1 ] = xcalloc( 1, table_features_len );
    table_features[ 1 ]->length = table_features_len;
    table_features[ 1 ]->table_id = 0x22;
    memset( table_features[ 1 ]->pad, 0, sizeof( table_features[ 1 ]->pad ) );
    memcpy( table_features[ 1 ]->name, name, OFP_MAX_TABLE_NAME_LEN );
    table_features[ 1 ]->metadata_match = 0x5555666677778888;
    table_features[ 1 ]->metadata_write = 0xCCCCDDDDEEEEFFFF;
    table_features[ 1 ]->config = 0x55443322;
    table_features[ 1 ]->max_entries = 0xBBAA9988;
    
    create_list( &table_features_head );
    append_to_tail( &table_features_head, table_features[ 0 ] );
    append_to_tail( &table_features_head, table_features[ 1 ] );

    struct ofp_table_features *table_features_stats_req;
    table_features_stats_req = xcalloc( 1, ( uint16_t ) ( table_features_len * 2 ) );
    memcpy( table_features_stats_req, table_features[0], table_features_len );
    memcpy( ( char * ) table_features_stats_req + table_features_len, table_features[1], table_features_len );

    buffer = create_table_features_multipart_request( TRANSACTION_ID, flags, table_features_head );

    body_len = ( uint32_t ) ( table_features_len * 2 );

    expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
    expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_request_handler, body->length, body_len );
    expect_memory( mock_multipart_request_handler, body->data, table_features_stats_req, body_len );
    expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
    handle_multipart_request( buffer );

    xfree( table_features_stats_req );
    delete_list( table_features_head );
    xfree( table_features[ 0 ] );
    xfree( table_features[ 1 ] );
    free_buffer( buffer );
  }

  {
    buffer = create_table_features_multipart_request( TRANSACTION_ID, flags, NULL );

    expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
    expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_request_handler, body, NULL );
    expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
    handle_multipart_request( buffer );

    free_buffer( buffer );
  }
}


static void
test_handle_multipart_request_if_type_is_OFPMP_PORT_DESC() {
  uint16_t type = OFPMP_PORT_DESC;
  uint16_t flags = OFPMPF_REQ_MORE;
  buffer *buffer;

  buffer = create_port_desc_multipart_request( TRANSACTION_ID, flags );

  expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
  expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_request_handler, body, NULL );
  expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
  handle_multipart_request( buffer );

  free_buffer( buffer );
}


static void
test_handle_multipart_request_if_type_is_OFPMP_EXPERIMENTER() {
  uint16_t type = OFPMP_EXPERIMENTER;
  uint16_t flags = OFPMPF_REQ_MORE;
  uint32_t experimenter = 0x11223344;
  uint32_t exp_type = 0xAABBCCDD;
  uint16_t body_len;
  buffer *buffer, *data;

  data = alloc_buffer_with_length( 32 );
  append_back_buffer( data, 32 );
  memset( data->data, 'a', 32 );

  uint16_t expected_len = ( uint16_t ) ( sizeof( struct ofp_experimenter_multipart_header ) + data->length );
  struct ofp_experimenter_multipart_header *experimenter_stats_req;
  experimenter_stats_req = xcalloc( 1, expected_len );
  experimenter_stats_req->experimenter = experimenter;
  experimenter_stats_req->exp_type = exp_type;
  memcpy( experimenter_stats_req + 1, data->data, data->length );

  body_len = ( uint16_t ) ( sizeof( struct ofp_experimenter_multipart_header ) + data->length );

  buffer = create_experimenter_multipart_request( TRANSACTION_ID, flags, experimenter, exp_type, data );

  expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
  expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_multipart_request_handler, body->length, body_len );
  expect_memory( mock_multipart_request_handler, body->data, experimenter_stats_req, body_len );
  expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
  handle_multipart_request( buffer );

  xfree( experimenter_stats_req );
  free_buffer( data );
  free_buffer( buffer );
}


static void
test_handle_multipart_request_with_undefined_type() {
  uint16_t type = 99;
  uint16_t length = ( uint16_t ) sizeof( struct ofp_multipart_request );
  uint16_t flags = 0xABCD;
  buffer *buffer;

  buffer = create_multipart_request( TRANSACTION_ID, type, length, flags );

  expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
  expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
  expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );
  expect_value( mock_multipart_request_handler, body, NULL );

  set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
  handle_multipart_request( buffer );
  free_buffer( buffer );
}


static void
test_handle_multipart_request_if_message_is_NULL() {
  set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
  expect_assert_failure( handle_multipart_request( NULL ) );
}


/********************************************************************************
 * handle_queue_get_config_request() tests.
 ********************************************************************************/

static void
test_handle_queue_get_config_request() {
  uint32_t port = 0x12345678;
  buffer *buffer;

  buffer = create_queue_get_config_request( TRANSACTION_ID, port );

  expect_value( mock_queue_get_config_request_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_queue_get_config_request_handler, port, port );
  expect_memory( mock_queue_get_config_request_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_queue_get_config_request_handler( mock_queue_get_config_request_handler, USER_DATA );
  handle_queue_get_config_request( buffer );

  free_buffer( buffer );
}


static void
test_handle_queue_get_config_request_if_handler_is_not_registered() {
  uint32_t port = 0x12345678;
  buffer *buffer;

  buffer = create_queue_get_config_request( TRANSACTION_ID, port );
  
  // FIXME
  
  handle_queue_get_config_request( buffer );

  free_buffer( buffer );
}


static void
test_handle_queue_get_config_request_if_message_is_NULL() {
  set_queue_get_config_request_handler( mock_queue_get_config_request_handler, USER_DATA );
  expect_assert_failure( handle_queue_get_config_request( NULL ) );
}


/********************************************************************************
 * handle_role_request() tests.
 ********************************************************************************/

static void
test_handle_role_request() {
  uint32_t role = 0x12345678;
  uint64_t generation_id = 0x1122334455667788;
  buffer *buffer;

  buffer = create_role_request( TRANSACTION_ID, role, generation_id );

  expect_value( mock_role_request_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_role_request_handler, role, role );
  expect_memory( mock_role_request_handler, &generation_id, &generation_id, sizeof( uint64_t) );
  expect_memory( mock_role_request_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_role_request_handler( mock_role_request_handler, USER_DATA );
  handle_role_request( buffer );

  free_buffer( buffer );
}


static void
test_handle_role_request_if_handler_is_not_registered() {
  uint32_t role = 0x12345678;
  uint64_t generation_id = 0x1122334455667788;
  buffer *buffer;

  buffer = create_role_request( TRANSACTION_ID, role, generation_id );
  
  // FIXME
  
  handle_role_request( buffer );

  free_buffer( buffer );
}


static void
test_handle_role_request_if_message_is_NULL() {
  set_role_request_handler( mock_role_request_handler, USER_DATA );
  expect_assert_failure( handle_role_request( NULL ) );
}


/********************************************************************************
 * handle_get_async_request() tests.
 ********************************************************************************/

static void
test_handle_get_async_request() {
  buffer *buffer;

  buffer = create_get_async_request( TRANSACTION_ID );
  
  expect_value( mock_get_async_request_handler, transaction_id, TRANSACTION_ID );
  expect_memory( mock_get_async_request_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_get_async_request_handler( mock_get_async_request_handler, USER_DATA );
  handle_get_async_request( buffer );

  free_buffer( buffer );
}


static void
test_handle_get_async_request_if_handler_is_not_registered() {
  buffer *buffer;

  buffer = create_get_async_request( TRANSACTION_ID );
  
  // FIXME
  
  handle_get_async_request( buffer );

  free_buffer( buffer );
}


static void
test_handle_get_async_request_if_message_is_NULL() {
  set_get_async_request_handler( mock_get_async_request_handler, USER_DATA );
  expect_assert_failure( handle_get_async_request( NULL ) );
}


/********************************************************************************
 * handle_set_async() tests.
 ********************************************************************************/

static void
test_handle_set_async() {
  uint32_t packet_in_mask[ 2 ] = { 0x12345678, 0x9ABCDEF0 };
  uint32_t port_status_mask[ 2 ] = { 0x11223344, 0x55667788 };
  uint32_t flow_removed_mask[ 2 ] = { 0x99AABBCC, 0xDDEEFF00 };
  buffer *buffer;

  buffer = create_set_async( TRANSACTION_ID, packet_in_mask, port_status_mask, flow_removed_mask );
  
  expect_value( mock_set_async_handler, transaction_id, TRANSACTION_ID );
  expect_memory( mock_set_async_handler, packet_in_mask, packet_in_mask, (sizeof( uint32_t ) * 2) );
  expect_memory( mock_set_async_handler, port_status_mask, port_status_mask, (sizeof( uint32_t ) * 2) );
  expect_memory( mock_set_async_handler, flow_removed_mask, flow_removed_mask, (sizeof( uint32_t ) * 2) );
  expect_memory( mock_set_async_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_set_async_handler( mock_set_async_handler, USER_DATA );
  handle_set_async( buffer );

  free_buffer( buffer );
}


static void
test_handle_set_async_if_handler_is_not_registered() {
  uint32_t packet_in_mask[ 2 ] = { 0x12345678, 0x9ABCDEF0 };
  uint32_t port_status_mask[ 2 ] = { 0x11223344, 0x55667788 };
  uint32_t flow_removed_mask[ 2 ] = { 0x99AABBCC, 0xDDEEFF00 };
  buffer *buffer;

  buffer = create_set_async( TRANSACTION_ID, packet_in_mask, port_status_mask, flow_removed_mask );
  
  // FIXME
  
  handle_set_async( buffer );

  free_buffer( buffer );
}


static void
test_handle_set_async_if_message_is_NULL() {
  set_set_async_handler( mock_set_async_handler, USER_DATA );
  expect_assert_failure( handle_set_async( NULL ) );
}


/********************************************************************************
 * handle_meter_mod() tests.
 ********************************************************************************/

static void
test_handle_meter_mod() {
  uint16_t command = 0x1122;
  uint8_t flags = 0x33;
  uint32_t meter_id = 0x44556677;
  list_element *bands;
  uint16_t band_len;
  struct ofp_meter_band_drop *band[ 2 ];
  buffer *buffer;

  band_len = ( uint16_t ) sizeof( struct ofp_meter_band_drop );

  band[ 0 ] = xcalloc( 1, band_len );
  band[ 0 ]->type = OFPMBT_DROP;
  band[ 0 ]->len = band_len;
  band[ 0 ]->rate = 0x11223344;
  band[ 0 ]->burst_size = 0x55667788;

  band[ 1 ] = xcalloc( 1, band_len );
  band[ 1 ]->type = OFPMBT_DROP;
  band[ 1 ]->len = band_len;
  band[ 1 ]->rate = 0xAABBCCDD;
  band[ 1 ]->burst_size = 0xCCDDEEFF;

  create_list( &bands );
  append_to_tail( &bands, band[ 0 ] );
  append_to_tail( &bands, band[ 1 ] );

  buffer = create_meter_mod( TRANSACTION_ID, command, flags, meter_id, bands );
  
  expect_value( mock_meter_mod_handler, transaction_id, TRANSACTION_ID );
  expect_value( mock_meter_mod_handler, command32, ( uint32_t ) command );
  expect_value( mock_meter_mod_handler, flags32, ( uint32_t ) flags );
  expect_value( mock_meter_mod_handler, meter_id, meter_id );
  expect_memory( mock_meter_mod_handler, bands1, band[ 0 ], band_len );
  expect_memory( mock_meter_mod_handler, bands2, band[ 1 ], band_len );
  expect_memory( mock_meter_mod_handler, user_data, USER_DATA, USER_DATA_LEN );

  set_meter_mod_handler( mock_meter_mod_handler, USER_DATA );
  handle_meter_mod( buffer );

  delete_list( bands );
  xfree( band[ 0 ] );
  xfree( band[ 1 ] );
  free_buffer( buffer );
}


static void
test_handle_meter_mod_if_handler_is_not_registered() {
  uint16_t command = 0x1122;
  uint8_t flags = 0x33;
  uint32_t meter_id = 0x44556677;
  list_element *bands;
  uint16_t band_len;
  struct ofp_meter_band_drop *band[ 2 ];
  buffer *buffer;

  band_len = ( uint16_t ) sizeof( struct ofp_meter_band_drop );

  band[ 0 ] = xcalloc( 1, band_len );
  band[ 0 ]->type = OFPMBT_DROP;
  band[ 0 ]->len = band_len;
  band[ 0 ]->rate = 0x11223344;
  band[ 0 ]->burst_size = 0x55667788;

  band[ 1 ] = xcalloc( 1, band_len );
  band[ 1 ]->type = OFPMBT_DROP;
  band[ 1 ]->len = band_len;
  band[ 1 ]->rate = 0xAABBCCDD;
  band[ 1 ]->burst_size = 0xCCDDEEFF;

  create_list( &bands );
  append_to_tail( &bands, band[ 0 ] );
  append_to_tail( &bands, band[ 1 ] );

  buffer = create_meter_mod( TRANSACTION_ID, command, flags, meter_id, bands );
  
  // FIXME
  
  handle_meter_mod( buffer );

  delete_list( bands );
  xfree( band[ 0 ] );
  xfree( band[ 1 ] );
  free_buffer( buffer );
}


static void
test_handle_meter_mod_if_message_is_NULL() {
  set_meter_mod_handler( mock_meter_mod_handler, USER_DATA );
  expect_assert_failure( handle_meter_mod( NULL ) );
}


/********************************************************************************
 * handle_openflow_message() tests.
 ********************************************************************************/

static void
test_handle_openflow_message() {
  {
    uint16_t type = 0x1234;
    uint16_t code = 0x1234;
    buffer *buffer, *data;

    data = alloc_buffer_with_length( 8 );
    append_back_buffer( data, 8 );
    memset( data->data, 'a', 8 );

    buffer = create_error( TRANSACTION_ID, type, code, data );

    expect_value( mock_error_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_error_handler, type32, ( uint32_t ) type );
    expect_value( mock_error_handler, code32, ( uint32_t ) code );
    expect_value( mock_error_handler, data->length, data->length );
    expect_memory( mock_error_handler, data->data, data->data, data->length );
    expect_memory( mock_error_handler, user_data, USER_DATA, USER_DATA_LEN );

    switch_set_error_handler( mock_error_handler, USER_DATA );
    handle_openflow_message( buffer );

    free_buffer( data );
    free_buffer( buffer );
  }
  {
    uint16_t type = OFPET_EXPERIMENTER;

    uint16_t exp_type = 0x3344;
    uint32_t experimenter = 0x55667788;
    buffer *buffer, *data;
    
    data = alloc_buffer_with_length( 32 );
    append_back_buffer( data, 32 );
    memset( data->data, 'a', 32 );

    buffer = create_error_experimenter( TRANSACTION_ID, type, exp_type, experimenter, data );
    
    expect_value( mock_experimenter_error_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_experimenter_error_handler, type32, ( uint32_t ) type );
    expect_value( mock_experimenter_error_handler, exp_type32, ( uint32_t ) exp_type );
    expect_value( mock_experimenter_error_handler, experimenter, experimenter );
    expect_value( mock_experimenter_error_handler, data->length, data->length );
    expect_memory( mock_experimenter_error_handler, data->data, data->data, data->length );
    expect_memory( mock_experimenter_error_handler, user_data, USER_DATA, USER_DATA_LEN );

    switch_set_experimenter_error_handler( mock_experimenter_error_handler, USER_DATA );
    handle_openflow_message( buffer );

    free_buffer( data );
    free_buffer( buffer );
  }
  {
    uint32_t experimenter = 0x11223344;
    uint32_t exp_type = 0x55667788;
    buffer *buffer, *data;

    data = alloc_buffer_with_length( 32 );
    append_back_buffer( data, 32 );
    memset( data->data, 'a', 32 );

    buffer = create_experimenter( TRANSACTION_ID, experimenter, exp_type, data );

    expect_value( mock_experimenter_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_experimenter_handler, experimenter, experimenter );
    expect_value( mock_experimenter_handler, exp_type, exp_type );
    expect_value( mock_experimenter_handler, data->length, data->length );
    expect_memory( mock_experimenter_handler, data->data, data->data, data->length );
    expect_memory( mock_experimenter_handler, user_data, USER_DATA, USER_DATA_LEN );

    switch_set_experimenter_handler( mock_experimenter_handler, USER_DATA );
    handle_openflow_message( buffer );

    free_buffer( data );
    free_buffer( buffer );
  }
  {
    size_t queue_len;
    uint32_t buffer_id = 0x11223344;
    uint32_t in_port = 0xAABBCCDD;
    openflow_actions *actions;
    struct ofp_action_output *queue[ 2 ];
    buffer *buffer, *data;

    queue_len = sizeof( struct ofp_action_output );
    queue[ 0 ] = xcalloc( 1, queue_len );
    queue[ 1 ] = xcalloc( 1, queue_len );

    queue[ 0 ]->type = OFPAT_OUTPUT;
    queue[ 0 ]->len = ( uint16_t ) queue_len;
    queue[ 0 ]->port = 0x1122;
    queue[ 0 ]->max_len = 0x11;
    queue[ 1 ]->type = OFPAT_OUTPUT;
    queue[ 1 ]->len = ( uint16_t ) queue_len;
    queue[ 1 ]->port = 0xAABB;
    queue[ 1 ]->max_len = 0xAA;
    
    actions = create_actions();
    actions->n_actions = 2;
    create_list( &actions->list );
    append_to_tail( &actions->list, queue[ 0 ] );
    append_to_tail( &actions->list, queue[ 1 ] );
    
    data = alloc_buffer_with_length( 64 );
    append_back_buffer( data, 64 );
    memset( data->data, 0x01, 64 );

    buffer = create_packet_out( TRANSACTION_ID, buffer_id, in_port, actions, data );

    expect_value( mock_packet_out_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_packet_out_handler, buffer_id, buffer_id );
    expect_value( mock_packet_out_handler, in_port, in_port );
    expect_memory( mock_packet_out_handler, action1, queue[ 0 ], queue_len );
    expect_memory( mock_packet_out_handler, action2, queue[ 1 ], queue_len );
    expect_value( mock_packet_out_handler, data->length, data->length );
    expect_memory( mock_packet_out_handler, data->data, data->data, data->length );
    expect_memory( mock_packet_out_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_packet_out_handler( mock_packet_out_handler, USER_DATA );
    handle_openflow_message( buffer );

    delete_actions( actions );
    free_buffer( data );
    free_buffer( buffer );
  }
  {
    uint64_t cookie = 0x1122334455667788;
    uint64_t cookie_mask = 0x8899AABBCCDDEEFF;
    uint8_t table_id = 0x12;
    uint8_t command = OFPFC_ADD;
    uint16_t idle_timeout = 0x9876;
    uint16_t hard_timeout = 0xFEDC;
    uint16_t priority = 0x5432;
    uint32_t buffer_id = 0x12345678;
    uint32_t out_port = 0x89ABCDEF;
    uint32_t out_group = 0xFFEEDDCC;
    uint16_t flags = 0;
    oxm_matches *match;
    size_t match1_len, match2_len;
    oxm_match_header *queue[ 2 ];
    uint32_t* value;
    openflow_instructions *instructions;
    size_t instructions_len;
    struct ofp_instruction_goto_table *inst[ 2 ];
    buffer *buffer;

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

    instructions_len = sizeof ( struct ofp_instruction_goto_table );
    inst[ 0 ] = xcalloc( 1, instructions_len );
    inst[ 0 ]->type = OFPIT_GOTO_TABLE;
    inst[ 0 ]->len = ( uint16_t ) instructions_len;
    inst[ 0 ]->table_id = 0xAB;

    inst[ 1 ] = xcalloc( 1, instructions_len );
    inst[ 1 ]->type = OFPIT_GOTO_TABLE;
    inst[ 1 ]->len = ( uint16_t ) instructions_len;
    inst[ 1 ]->table_id = 0xCD;

    instructions = create_instructions();
    instructions->n_instructions = 2;
    append_to_tail( &instructions->list, inst[ 0 ] );
    append_to_tail( &instructions->list, inst[ 1 ] );

    buffer = create_flow_mod( TRANSACTION_ID, cookie, cookie_mask, table_id, command, idle_timeout,
             hard_timeout, priority, buffer_id, out_port, out_group, flags, match, instructions );
    
    expect_value( mock_flow_mod_handler, transaction_id, TRANSACTION_ID );
    expect_memory( mock_flow_mod_handler, &cookie, &cookie, sizeof( uint64_t ) );
    expect_memory( mock_flow_mod_handler, &cookie_mask, &cookie_mask, sizeof( uint64_t) );
    expect_value( mock_flow_mod_handler, table_id32, ( uint32_t ) table_id );
    expect_value( mock_flow_mod_handler, command32, ( uint32_t ) command );
    expect_value( mock_flow_mod_handler, idle_timeout32, ( uint32_t ) idle_timeout );
    expect_value( mock_flow_mod_handler, hard_timeout32, ( uint32_t ) hard_timeout );
    expect_value( mock_flow_mod_handler, priority32, ( uint32_t ) priority );
    expect_value( mock_flow_mod_handler, buffer_id, buffer_id );
    expect_value( mock_flow_mod_handler, out_port, out_port );
    expect_value( mock_flow_mod_handler, out_group, out_group );
    expect_value( mock_flow_mod_handler, flags32, ( uint32_t ) flags );
    expect_memory( mock_flow_mod_handler, match1, queue[ 0 ], match1_len );
    expect_memory( mock_flow_mod_handler, match2, queue[ 1 ], match2_len );
    expect_memory( mock_flow_mod_handler, inst1, inst[ 0 ], instructions_len );
    expect_memory( mock_flow_mod_handler, inst2, inst[ 1 ], instructions_len );
    expect_memory( mock_flow_mod_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_flow_mod_handler( mock_flow_mod_handler, USER_DATA );
    handle_openflow_message( buffer );
    
    delete_oxm_matches(match);
    delete_instructions(instructions);
    free_buffer( buffer );
  }
  {
    uint16_t command = OFPGC_DELETE;
    uint8_t type = OFPGT_FF;
    uint32_t group_id = 0x44556677;
    openflow_buckets *buckets;
    uint16_t bucket_len;
    struct ofp_bucket *bucket[ 2 ];
    buffer *buffer;
    struct ofp_action_output *actions;
    uint16_t offset;

    offset = offsetof( struct ofp_bucket, actions );
    bucket_len = ( uint16_t ) ( offset + sizeof( struct ofp_action_output ) );

    bucket[ 0 ] = xcalloc( 1, bucket_len );
    bucket[ 0 ]->len = bucket_len;
    bucket[ 0 ]->weight = 0x1122;
    bucket[ 0 ]->watch_port = 0xAABBCCDD;
    bucket[ 0 ]->watch_group = 0xFFEEDDCC;
    actions = ( struct ofp_action_output * ) ( bucket[ 0 ] + 1 );
    actions->type = OFPAT_OUTPUT;
    actions->len = sizeof( struct ofp_action_output );
    actions->port = 0x01020304;
    actions->max_len = 0xFACE;

    bucket[ 1 ] = xcalloc( 1, bucket_len );
    bucket[ 1 ]->len = bucket_len;
    bucket[ 1 ]->weight = 0x3344;
    bucket[ 1 ]->watch_port = 0xAACCBBDD;
    bucket[ 1 ]->watch_group = 0xFFDDEECC;
    actions = ( struct ofp_action_output * ) ( bucket[ 1 ] + 1 );
    actions->type = OFPAT_OUTPUT;
    actions->len = sizeof( struct ofp_action_output );
    actions->port = 0x05060708;
    actions->max_len = 0xCAFE;

    buckets = create_buckets();
    append_to_tail( &buckets->list, bucket[ 0 ] );
    append_to_tail( &buckets->list, bucket[ 1 ] );

    buffer = create_group_mod( TRANSACTION_ID, command, type, group_id, buckets );
    
    expect_value( mock_group_mod_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_group_mod_handler, command32, ( uint32_t ) command );
    expect_value( mock_group_mod_handler, type32, ( uint32_t ) type );
    expect_value( mock_group_mod_handler, group_id, group_id );
    expect_memory( mock_group_mod_handler, bucket1, bucket[ 0 ], bucket_len );
    expect_memory( mock_group_mod_handler, bucket2, bucket[ 1 ], bucket_len );
    expect_memory( mock_group_mod_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_group_mod_handler( mock_group_mod_handler, USER_DATA );
    handle_openflow_message( buffer );

    free_buffer( buffer );
    delete_buckets( buckets );
  }
  {
    uint32_t port_no = 0x12345678;
    uint8_t hw_addr[ OFP_ETH_ALEN ] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    uint32_t config = OFPPC_NO_PACKET_IN;
    uint32_t mask = OFPPC_NO_PACKET_IN;
    uint32_t advertise = OFPPF_PAUSE_ASYM;
    buffer *buffer;

    buffer = create_port_mod( TRANSACTION_ID, port_no, hw_addr, config, mask, advertise );

    expect_value( mock_port_mod_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_port_mod_handler, port_no, port_no );
    expect_memory( mock_port_mod_handler, hw_addr, hw_addr, sizeof( hw_addr ) );
    expect_value( mock_port_mod_handler, config, config );
    expect_value( mock_port_mod_handler, mask, mask );
    expect_value( mock_port_mod_handler, advertise, advertise );
    expect_memory( mock_port_mod_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_port_mod_handler( mock_port_mod_handler, USER_DATA );
    handle_openflow_message( buffer );

    free_buffer( buffer );
  }
  {
    uint8_t table_id = 0x12;
    uint32_t config = 0x12345678;
    buffer *buffer;

    buffer = create_table_mod( TRANSACTION_ID, table_id, config );

    expect_value( mock_table_mod_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_table_mod_handler, table_id32, ( uint32_t ) table_id );
    expect_value( mock_table_mod_handler, config, config );
    expect_memory( mock_table_mod_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_table_mod_handler( mock_table_mod_handler, USER_DATA );
    handle_openflow_message( buffer );

    free_buffer( buffer );
  }
  {
    uint16_t type = OFPMP_DESC;
    uint16_t flags = 0;
    buffer *buffer;

    buffer = create_desc_multipart_request( TRANSACTION_ID, flags );

    expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
    expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_request_handler, body, NULL );
    expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
    handle_openflow_message( buffer );

    free_buffer( buffer );
  }
  {
    uint16_t type = OFPMP_FLOW;
    uint16_t flags = 0;
    uint8_t table_id = 0x11;
    uint32_t out_port = 0x11223344;
    uint32_t out_group = 0x55667788;
    uint64_t cookie = 0x1111222233334444;
    uint64_t cookie_mask = 0xFFFFEEEEDDDDCCCC;
    oxm_matches *match;
    size_t match1_len, match2_len;
    oxm_match_header *queue[ 2 ];
    uint32_t* value;
    uint16_t body_len_tmp;
    uint32_t body_len;
    buffer *buffer;

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
    
    struct ofp_flow_stats_request *flow_stats_req;

    uint16_t ofp_match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields ) + get_oxm_matches_length( match ) );
    body_len_tmp = ( uint16_t ) ( ofp_match_len + PADLEN_TO_64( ofp_match_len ) );
    uint16_t expected_fs_len = ( uint16_t ) ( offsetof( struct ofp_flow_stats_request, match ) + body_len_tmp );
    flow_stats_req = xcalloc( 1, expected_fs_len );
    flow_stats_req->table_id = table_id;
    flow_stats_req->out_port = out_port;
    flow_stats_req->out_group = out_group;
    flow_stats_req->cookie = cookie;
    flow_stats_req->cookie_mask = cookie_mask;
    construct_ofp_match( &flow_stats_req->match, match );
    ntoh_match( &flow_stats_req->match, &flow_stats_req->match );
    body_len = ( uint32_t ) ( offsetof( struct ofp_flow_stats_request, match ) + body_len_tmp );

    buffer = create_flow_multipart_request( TRANSACTION_ID, flags, table_id, out_port, out_group, cookie, cookie_mask, match );

    expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
    expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_request_handler, body->length, body_len );
    expect_memory( mock_multipart_request_handler, body->data, flow_stats_req, body_len );
    expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
    handle_openflow_message( buffer );

    xfree( flow_stats_req );
    delete_oxm_matches(match);
    free_buffer( buffer );
  }
  {
    uint16_t type = OFPMP_AGGREGATE;
    uint16_t flags = 0;
    uint8_t table_id = 0xAB;
    uint32_t out_port = 0x11223344;
    uint32_t out_group = 0x55667788;
    uint64_t cookie = 0x1111222233334444;
    uint64_t cookie_mask = 0xFFFFEEEEDDDDCCCC;
    oxm_matches *match;
    size_t match1_len, match2_len;
    oxm_match_header *queue[ 2 ];
    uint32_t* value;
    uint32_t body_len;
    buffer *buffer;

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

    struct ofp_aggregate_stats_request *aggregte_stats_req;

    uint16_t ofp_match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields ) + get_oxm_matches_length( match ) );
    uint16_t body_len_tmp = ( uint16_t ) ( ofp_match_len + PADLEN_TO_64( ofp_match_len ) );
    uint16_t expected_fs_len = ( uint16_t ) ( offsetof( struct ofp_aggregate_stats_request, match ) + body_len_tmp );
    aggregte_stats_req = xcalloc( 1, expected_fs_len );
    aggregte_stats_req->table_id = table_id;
    aggregte_stats_req->out_port = out_port;
    aggregte_stats_req->out_group = out_group;
    aggregte_stats_req->cookie = cookie;
    aggregte_stats_req->cookie_mask = cookie_mask;
    construct_ofp_match( &aggregte_stats_req->match, match );
    ntoh_match( &aggregte_stats_req->match, &aggregte_stats_req->match );
    body_len = ( uint32_t ) ( offsetof( struct ofp_aggregate_stats_request, match ) + body_len_tmp );

    buffer = create_aggregate_multipart_request( TRANSACTION_ID, flags, table_id, out_port, out_group, cookie, cookie_mask, match );

    expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
    expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_request_handler, body->length, body_len );
    expect_memory( mock_multipart_request_handler, body->data, aggregte_stats_req, body_len );
    expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
    handle_openflow_message( buffer );

    xfree( aggregte_stats_req );
    delete_oxm_matches(match);
    free_buffer( buffer );
  }
  {
    uint16_t type = OFPMP_TABLE;
    uint16_t flags = 0;
    buffer *buffer;

    buffer = create_table_multipart_request( TRANSACTION_ID, flags );

    expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
    expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_request_handler, body, NULL );
    expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
    handle_openflow_message( buffer );

    free_buffer( buffer );
  }
  {
    uint16_t type = OFPMP_PORT_STATS;
    uint16_t flags = 0;
    uint32_t port_no = 0x11223344;
    uint32_t body_len;
    buffer *buffer;

    struct ofp_port_stats_request *port_stats_req;
    struct ofp_port_stats_request port_stats_req_mod;
    memset(&port_stats_req_mod, 0, sizeof(port_stats_req_mod));

    buffer = create_port_multipart_request( TRANSACTION_ID, flags, port_no );
    port_stats_req = ( struct ofp_port_stats_request * ) ( ( char * ) buffer->data
                         + offsetof( struct ofp_multipart_request, body ) );
    port_stats_req_mod.port_no = ntohl( port_stats_req->port_no );
    memset( &port_stats_req_mod.pad, 0, sizeof( port_stats_req_mod.pad ) );
    body_len = ( uint32_t ) sizeof( struct ofp_port_stats_request );

    expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
    expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_request_handler, body->length, body_len );
    expect_memory( mock_multipart_request_handler, body->data, &port_stats_req_mod, body_len );
    expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
    handle_openflow_message( buffer );

    free_buffer( buffer );
  }
  {
    uint16_t type = OFPMP_QUEUE;
    uint16_t flags = 0;
    uint32_t port_no = 0x11223344;
    uint32_t queue_id = 0xAABBCCDD;
    uint32_t body_len;
    buffer *buffer;

    struct ofp_queue_stats_request *queue_stats_req;
    struct ofp_queue_stats_request queue_stats_req_mod;
    memset(&queue_stats_req_mod, 0, sizeof(queue_stats_req_mod));

    buffer = create_queue_multipart_request( TRANSACTION_ID, flags, port_no, queue_id );
    queue_stats_req = ( struct ofp_queue_stats_request * ) ( ( char * ) buffer->data
                          + offsetof( struct ofp_multipart_request, body ) );
    queue_stats_req_mod.port_no = ntohl( queue_stats_req->port_no );
    queue_stats_req_mod.queue_id = ntohl( queue_stats_req->queue_id );
    body_len = ( uint32_t ) sizeof( struct ofp_queue_stats_request );

    expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
    expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_request_handler, body->length, body_len );
    expect_memory( mock_multipart_request_handler, body->data, &queue_stats_req_mod, body_len );
    expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
    handle_openflow_message( buffer );

    free_buffer( buffer );
  }
  {
    uint16_t type = OFPMP_GROUP;
    uint16_t flags = 0;
    uint32_t group_id = 0xAABBCCDD;
    uint32_t body_len;
    buffer *buffer;

    struct ofp_group_stats_request *group_stats_req;
    struct ofp_group_stats_request group_stats_req_mod;
    memset(&group_stats_req_mod, 0, sizeof(group_stats_req_mod));

    buffer = create_group_multipart_request( TRANSACTION_ID, flags, group_id );
    group_stats_req = ( struct ofp_group_stats_request * ) ( ( char * ) buffer->data
                          + offsetof( struct ofp_multipart_request, body ) );
    group_stats_req_mod.group_id = ntohl( group_stats_req->group_id );
    memset( &group_stats_req_mod.pad, 0, sizeof( group_stats_req_mod.pad ) );
    body_len = ( uint32_t ) sizeof( struct ofp_group_stats_request );

    expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
    expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_request_handler, body->length, body_len );
    expect_memory( mock_multipart_request_handler, body->data, &group_stats_req_mod, body_len );
    expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
    handle_openflow_message( buffer );

    free_buffer( buffer );
  }
  {
    uint16_t type = OFPMP_GROUP_DESC;
    uint16_t flags = 0;
    buffer *buffer;

    buffer = create_group_desc_multipart_request( TRANSACTION_ID, flags );

    expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
    expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_request_handler, body, NULL );
    expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
    handle_openflow_message( buffer );

    free_buffer( buffer );
  }
  {
    uint16_t type = OFPMP_GROUP_FEATURES;
    uint16_t flags = 0;
    buffer *buffer;

    buffer = create_group_features_multipart_request( TRANSACTION_ID, flags );

    expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
    expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_request_handler, body, NULL );
    expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
    handle_openflow_message( buffer );

    free_buffer( buffer );
  }
  {
    uint16_t type = OFPMP_METER;
    uint16_t flags = 0;
    uint32_t meter_id = 0xAABBCCDD;
    uint32_t body_len;
    buffer *buffer;

    struct ofp_meter_multipart_request *meter_stats_req;
    struct ofp_meter_multipart_request meter_stats_req_mod;
    memset(&meter_stats_req_mod, 0, sizeof(meter_stats_req_mod));

    buffer = create_meter_multipart_request( TRANSACTION_ID, flags, meter_id );
    meter_stats_req = ( struct ofp_meter_multipart_request * ) ( ( char * ) buffer->data
                        + offsetof( struct ofp_multipart_request, body ) );
    meter_stats_req_mod.meter_id = ntohl( meter_stats_req->meter_id );
    memset( &meter_stats_req_mod.pad, 0, sizeof( meter_stats_req_mod.pad ) );
    body_len = ( uint32_t ) sizeof( struct ofp_meter_multipart_request );

    expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
    expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_request_handler, body->length, body_len );
    expect_memory( mock_multipart_request_handler, body->data, &meter_stats_req_mod, body_len );
    expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
    handle_openflow_message( buffer );

    free_buffer( buffer );
  }
  {
    uint16_t type = OFPMP_METER_CONFIG;
    uint16_t flags = 0;
    uint32_t meter_id = 0xAABBCCDD;
    uint32_t body_len;
    buffer *buffer;

    struct ofp_meter_multipart_request *meter_stats_req;
    struct ofp_meter_multipart_request meter_stats_req_mod;
    memset(&meter_stats_req_mod, 0, sizeof(meter_stats_req_mod));

    buffer = create_meter_config_multipart_request( TRANSACTION_ID, flags, meter_id );
    meter_stats_req = ( struct ofp_meter_multipart_request * ) ( ( char * ) buffer->data
                          + offsetof( struct ofp_multipart_request, body ) );
    meter_stats_req_mod.meter_id = ntohl( meter_stats_req->meter_id );
    memset( &meter_stats_req_mod.pad, 0, sizeof( meter_stats_req_mod.pad ) );
    body_len = ( uint32_t ) sizeof( struct ofp_meter_multipart_request );

    expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
    expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_request_handler, body->length, body_len );
    expect_memory( mock_multipart_request_handler, body->data, &meter_stats_req_mod, body_len );
    expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
    handle_openflow_message( buffer );

    free_buffer( buffer );
  }
  {
    uint16_t type = OFPMP_METER_FEATURES;
    uint16_t flags = 0;
    buffer *buffer;

    buffer = create_meter_features_multipart_request( TRANSACTION_ID, flags );

    expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
    expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_request_handler, body, NULL );
    expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
    handle_openflow_message( buffer );

    free_buffer( buffer );
  }
  {
    uint16_t type = OFPMP_TABLE_FEATURES;
    uint16_t flags = 0;
    char name[ OFP_MAX_TABLE_NAME_LEN ] = "TableName";
    list_element *table_features_head;
    uint16_t table_features_len;
    struct ofp_table_features *table_features[ 2 ];
    uint32_t body_len;
    buffer *buffer;
    
    table_features_len = ( uint16_t ) sizeof( struct ofp_table_features );

    table_features[ 0 ] = xcalloc( 1, table_features_len );
    table_features[ 0 ]->length = table_features_len;
    table_features[ 0 ]->table_id = 0x11;
    memset( table_features[ 0 ]->pad, 0, sizeof( table_features[ 0 ]->pad ) );
    memcpy( table_features[ 0 ]->name, name, OFP_MAX_TABLE_NAME_LEN );
    table_features[ 0 ]->metadata_match = 0x1111222233334444;
    table_features[ 0 ]->metadata_write = 0xAAAABBBBCCCCDDDD;
    table_features[ 0 ]->config = 0x99887766;
    table_features[ 0 ]->max_entries = 0xFFEEDDCC;
    
    table_features[ 1 ] = xcalloc( 1, table_features_len );
    table_features[ 1 ]->length = table_features_len;
    table_features[ 1 ]->table_id = 0x22;
    memset( table_features[ 1 ]->pad, 0, sizeof( table_features[ 1 ]->pad ) );
    memcpy( table_features[ 1 ]->name, name, OFP_MAX_TABLE_NAME_LEN );
    table_features[ 1 ]->metadata_match = 0x5555666677778888;
    table_features[ 1 ]->metadata_write = 0xCCCCDDDDEEEEFFFF;
    table_features[ 1 ]->config = 0x55443322;
    table_features[ 1 ]->max_entries = 0xBBAA9988;
    
    create_list( &table_features_head );
    append_to_tail( &table_features_head, table_features[ 0 ] );
    append_to_tail( &table_features_head, table_features[ 1 ] );

    struct ofp_table_features *table_features_stats_req;
    table_features_stats_req = xcalloc( 1, ( uint16_t ) ( table_features_len * 2 ) );
    memcpy( table_features_stats_req, table_features[0], table_features_len );
    memcpy( ( char * ) table_features_stats_req + table_features_len, table_features[1], table_features_len );

    buffer = create_table_features_multipart_request( TRANSACTION_ID, flags, table_features_head );

    body_len = ( uint32_t ) ( table_features_len * 2 );

    expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
    expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_request_handler, body->length, body_len );
    expect_memory( mock_multipart_request_handler, body->data, table_features_stats_req, body_len );
    expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
    handle_openflow_message( buffer );

    xfree( table_features_stats_req );
    delete_list( table_features_head );
    xfree( table_features[ 0 ] );
    xfree( table_features[ 1 ] );
    free_buffer( buffer );
  }
  {
    uint16_t type = OFPMP_TABLE_FEATURES;
    uint16_t flags = 0;
    buffer *buffer;

    buffer = create_table_features_multipart_request( TRANSACTION_ID, flags, NULL );

    expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
    expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_request_handler, body, NULL );
    expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
    handle_openflow_message( buffer );

    free_buffer( buffer );
  }
  {
    uint16_t type = OFPMP_PORT_DESC;
    uint16_t flags = 0;
    buffer *buffer;

    buffer = create_port_desc_multipart_request( TRANSACTION_ID, flags );

    expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
    expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_request_handler, body, NULL );
    expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
    handle_openflow_message( buffer );

    free_buffer( buffer );
  }
  {
    uint16_t type = OFPMP_EXPERIMENTER;
    uint16_t flags = 0;
    uint32_t experimenter = 0x11223344;
    uint32_t exp_type = 0xAABBCCDD;
    uint16_t body_len;
    buffer *buffer, *data;

    data = alloc_buffer_with_length( 32 );
    append_back_buffer( data, 32 );
    memset( data->data, 'a', 32 );

    uint16_t expected_len = ( uint16_t ) ( sizeof( struct ofp_experimenter_multipart_header ) + data->length );
    struct ofp_experimenter_multipart_header *experimenter_stats_req;
    experimenter_stats_req = xcalloc( 1, expected_len );
    experimenter_stats_req->experimenter = experimenter;
    experimenter_stats_req->exp_type = exp_type;
    memcpy( experimenter_stats_req + 1, data->data, data->length );

    body_len = ( ( uint16_t ) ( sizeof( struct ofp_experimenter_multipart_header ) + data->length ) );

    buffer = create_experimenter_multipart_request( TRANSACTION_ID, flags, experimenter, exp_type, data );

    expect_value( mock_multipart_request_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_multipart_request_handler, type32, ( uint32_t ) type );
    expect_value( mock_multipart_request_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_multipart_request_handler, body->length, body_len );
    expect_memory( mock_multipart_request_handler, body->data, experimenter_stats_req, ( uint32_t ) body_len );
    expect_memory( mock_multipart_request_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_multipart_request_handler( mock_multipart_request_handler, USER_DATA );
    handle_openflow_message( buffer );

    xfree( experimenter_stats_req );
    free_buffer( data );
    free_buffer( buffer );
  }
  {
    uint32_t port = 0x12345678;
    buffer *buffer;

    buffer = create_queue_get_config_request( TRANSACTION_ID, port );

    expect_value( mock_queue_get_config_request_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_queue_get_config_request_handler, port, port );
    expect_memory( mock_queue_get_config_request_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_queue_get_config_request_handler( mock_queue_get_config_request_handler, USER_DATA );
    handle_openflow_message( buffer );

    free_buffer( buffer );
  }
  {
    uint32_t role = OFPCR_ROLE_SLAVE;
    uint64_t generation_id = 0x1122334455667788;
    buffer *buffer;

    buffer = create_role_request( TRANSACTION_ID, role, generation_id );

    expect_value( mock_role_request_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_role_request_handler, role, role );
    expect_memory( mock_role_request_handler, &generation_id, &generation_id, sizeof( uint64_t) );
    expect_memory( mock_role_request_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_role_request_handler( mock_role_request_handler, USER_DATA );
    handle_openflow_message( buffer );

    free_buffer( buffer );
  }
  {
    buffer *buffer;

    buffer = create_get_async_request( TRANSACTION_ID );
    
    expect_value( mock_get_async_request_handler, transaction_id, TRANSACTION_ID );
    expect_memory( mock_get_async_request_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_get_async_request_handler( mock_get_async_request_handler, USER_DATA );
    handle_openflow_message( buffer );

    free_buffer( buffer );
  }
  {
    uint32_t packet_in_mask[2] = { OFPR_ACTION, OFPR_INVALID_TTL };
    uint32_t port_status_mask[2] = { OFPPR_DELETE, OFPPR_MODIFY };
    uint32_t flow_removed_mask[2] = { OFPRR_DELETE, OFPRR_GROUP_DELETE };
    buffer *buffer;

    buffer = create_set_async( TRANSACTION_ID, packet_in_mask, port_status_mask, flow_removed_mask );
    
    expect_value( mock_set_async_handler, transaction_id, TRANSACTION_ID );
    expect_memory( mock_set_async_handler, packet_in_mask, packet_in_mask, (sizeof( uint32_t ) * 2) );
    expect_memory( mock_set_async_handler, port_status_mask, port_status_mask, (sizeof( uint32_t ) * 2) );
    expect_memory( mock_set_async_handler, flow_removed_mask, flow_removed_mask, (sizeof( uint32_t ) * 2) );
    expect_memory( mock_set_async_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_set_async_handler( mock_set_async_handler, USER_DATA );
    handle_openflow_message( buffer );

    free_buffer( buffer );
  }
  {
    uint16_t command = OFPMC_DELETE;
    uint8_t flags = OFPMF_STATS;
    uint32_t meter_id = 0x44556677;
    list_element *bands;
    uint16_t band_len;
    struct ofp_meter_band_drop *band[ 2 ];
    buffer *buffer;

    band_len = ( uint16_t ) sizeof( struct ofp_meter_band_drop );

    band[ 0 ] = xcalloc( 1, band_len );
    band[ 0 ]->type = OFPMBT_DROP;
    band[ 0 ]->len = band_len;
    band[ 0 ]->rate = 0x11223344;
    band[ 0 ]->burst_size = 0x55667788;

    band[ 1 ] = xcalloc( 1, band_len );
    band[ 1 ]->type = OFPMBT_DROP;
    band[ 1 ]->len = band_len;
    band[ 1 ]->rate = 0xAABBCCDD;
    band[ 1 ]->burst_size = 0xCCDDEEFF;

    create_list( &bands );
    append_to_tail( &bands, band[ 0 ] );
    append_to_tail( &bands, band[ 1 ] );

    buffer = create_meter_mod( TRANSACTION_ID, command, flags, meter_id, bands );
    
    expect_value( mock_meter_mod_handler, transaction_id, TRANSACTION_ID );
    expect_value( mock_meter_mod_handler, command32, ( uint32_t ) command );
    expect_value( mock_meter_mod_handler, flags32, ( uint32_t ) flags );
    expect_value( mock_meter_mod_handler, meter_id, meter_id );
    expect_memory( mock_meter_mod_handler, bands1, band[ 0 ], band_len );
    expect_memory( mock_meter_mod_handler, bands2, band[ 1 ], band_len );
    expect_memory( mock_meter_mod_handler, user_data, USER_DATA, USER_DATA_LEN );

    set_meter_mod_handler( mock_meter_mod_handler, USER_DATA );
    handle_openflow_message( buffer );

    delete_list( bands );
    xfree( band[ 0 ] );
    xfree( band[ 1 ] );
    free_buffer( buffer );
  }
}


static void
test_handle_openflow_message_with_malformed_message() {
  buffer *buffer;
  struct ofp_header *header;

  buffer = create_hello( TRANSACTION_ID, NULL );
  header = buffer->data;
  header->length = htons( UINT16_MAX );

  assert_false( handle_openflow_message( buffer ) );

  free_buffer( buffer );
}


static void
test_handle_openflow_message_if_message_is_NULL() {
  expect_assert_failure( handle_openflow_message( NULL ) );
}


static void
test_handle_openflow_message_if_unhandled_message_type() {
  buffer *buffer;
  struct ofp_header *header;

  buffer = create_hello( TRANSACTION_ID, NULL );
  header = buffer->data;
  header->type = 0xFF;

  assert_false( handle_openflow_message( buffer ) );

  free_buffer( buffer );
}


/********************************************************************************
 * send_error_message() tests.
 ********************************************************************************/

static void
test_send_error_message() {
  uint32_t transaction_id = 0x12345678;

  assert_true( send_error_message( transaction_id, OFPET_HELLO_FAILED, OFPHFC_INCOMPATIBLE ) );
  assert_true( send_error_message( transaction_id, OFPET_HELLO_FAILED, OFPHFC_EPERM ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_REQUEST, OFPBRC_BAD_MULTIPART ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_REQUEST, OFPBRC_BAD_EXP_TYPE ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_REQUEST, OFPBRC_EPERM ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_REQUEST, OFPBRC_BUFFER_EMPTY ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_REQUEST, OFPBRC_BUFFER_UNKNOWN ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_REQUEST, OFPBRC_BAD_TABLE_ID ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_REQUEST, OFPBRC_IS_SLAVE ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_REQUEST, OFPBRC_BAD_PORT ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_REQUEST, OFPBRC_BAD_PACKET ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_REQUEST, OFPBRC_MULTIPART_BUFFER_OVERFLOW ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_ACTION, OFPBAC_BAD_TYPE ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_ACTION, OFPBAC_BAD_LEN ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_ACTION, OFPBAC_BAD_EXPERIMENTER ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_ACTION, OFPBAC_BAD_EXP_TYPE ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_ACTION, OFPBAC_EPERM ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_ACTION, OFPBAC_TOO_MANY ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_ACTION, OFPBAC_BAD_QUEUE ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_ACTION, OFPBAC_BAD_OUT_GROUP ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_ACTION, OFPBAC_MATCH_INCONSISTENT ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_ACTION, OFPBAC_UNSUPPORTED_ORDER ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_ACTION, OFPBAC_BAD_TAG ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_ACTION, OFPBAC_BAD_SET_TYPE ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_ACTION, OFPBAC_BAD_SET_LEN ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_ACTION, OFPBAC_BAD_SET_ARGUMENT ) );
  assert_true( send_error_message( transaction_id, OFPET_FLOW_MOD_FAILED, OFPFMFC_UNKNOWN ) );
  assert_true( send_error_message( transaction_id, OFPET_FLOW_MOD_FAILED, OFPFMFC_TABLE_FULL ) );
  assert_true( send_error_message( transaction_id, OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_TABLE_ID ) );
  assert_true( send_error_message( transaction_id, OFPET_FLOW_MOD_FAILED, OFPFMFC_OVERLAP ) );
  assert_true( send_error_message( transaction_id, OFPET_FLOW_MOD_FAILED, OFPFMFC_EPERM ) );
  assert_true( send_error_message( transaction_id, OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_TIMEOUT ) );
  assert_true( send_error_message( transaction_id, OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_COMMAND ) );
  assert_true( send_error_message( transaction_id, OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_FLAGS ) );
  assert_true( send_error_message( transaction_id, OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_PORT ) );
  assert_true( send_error_message( transaction_id, OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_HW_ADDR ) );
  assert_true( send_error_message( transaction_id, OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_CONFIG ) );
  assert_true( send_error_message( transaction_id, OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_ADVERTISE ) );
  assert_true( send_error_message( transaction_id, OFPET_PORT_MOD_FAILED, OFPPMFC_EPERM ) );
  assert_true( send_error_message( transaction_id, OFPET_QUEUE_OP_FAILED, OFPQOFC_BAD_PORT ) );
  assert_true( send_error_message( transaction_id, OFPET_QUEUE_OP_FAILED, OFPQOFC_BAD_QUEUE ) );
  assert_true( send_error_message( transaction_id, OFPET_QUEUE_OP_FAILED, OFPQOFC_EPERM ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_INSTRUCTION, OFPBIC_UNKNOWN_INST ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_INSTRUCTION, OFPBIC_UNSUP_INST ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_TABLE_ID ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_INSTRUCTION, OFPBIC_UNSUP_METADATA ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_INSTRUCTION, OFPBIC_UNSUP_METADATA_MASK ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_EXPERIMENTER ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_EXP_TYPE ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_INSTRUCTION, OFPBIC_EPERM ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_MATCH, OFPBMC_BAD_TYPE ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_MATCH, OFPBMC_BAD_LEN ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_MATCH, OFPBMC_BAD_TAG ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_MATCH, OFPBMC_BAD_DL_ADDR_MASK ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_MATCH, OFPBMC_BAD_NW_ADDR_MASK ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_MATCH, OFPBMC_BAD_WILDCARDS ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_MATCH, OFPBMC_BAD_FIELD ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_MATCH, OFPBMC_BAD_MASK ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_MATCH, OFPBMC_BAD_PREREQ ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_MATCH, OFPBMC_DUP_FIELD ) );
  assert_true( send_error_message( transaction_id, OFPET_BAD_MATCH, OFPBMC_EPERM ) );
  assert_true( send_error_message( transaction_id, OFPET_GROUP_MOD_FAILED, OFPGMFC_GROUP_EXISTS ) );
  assert_true( send_error_message( transaction_id, OFPET_GROUP_MOD_FAILED, OFPGMFC_INVALID_GROUP ) );
  assert_true( send_error_message( transaction_id, OFPET_GROUP_MOD_FAILED, OFPGMFC_WEIGHT_UNSUPPORTED ) );
  assert_true( send_error_message( transaction_id, OFPET_GROUP_MOD_FAILED, OFPGMFC_OUT_OF_GROUPS ) );
  assert_true( send_error_message( transaction_id, OFPET_GROUP_MOD_FAILED, OFPGMFC_OUT_OF_BUCKETS ) );
  assert_true( send_error_message( transaction_id, OFPET_GROUP_MOD_FAILED, OFPGMFC_CHAINING_UNSUPPORTED ) );
  assert_true( send_error_message( transaction_id, OFPET_GROUP_MOD_FAILED, OFPGMFC_WATCH_UNSUPPORTED ) );
  assert_true( send_error_message( transaction_id, OFPET_GROUP_MOD_FAILED, OFPGMFC_LOOP ) );
  assert_true( send_error_message( transaction_id, OFPET_GROUP_MOD_FAILED, OFPGMFC_UNKNOWN_GROUP ) );
  assert_true( send_error_message( transaction_id, OFPET_GROUP_MOD_FAILED, OFPGMFC_CHAINED_GROUP ) );
  assert_true( send_error_message( transaction_id, OFPET_GROUP_MOD_FAILED, OFPGMFC_BAD_TYPE ) );
  assert_true( send_error_message( transaction_id, OFPET_GROUP_MOD_FAILED, OFPGMFC_BAD_COMMAND ) );
  assert_true( send_error_message( transaction_id, OFPET_GROUP_MOD_FAILED, OFPGMFC_BAD_BUCKET ) );
  assert_true( send_error_message( transaction_id, OFPET_GROUP_MOD_FAILED, OFPGMFC_BAD_WATCH ) );
  assert_true( send_error_message( transaction_id, OFPET_GROUP_MOD_FAILED, OFPGMFC_EPERM ) );
  assert_true( send_error_message( transaction_id, OFPET_TABLE_MOD_FAILED, OFPTMFC_BAD_TABLE ) );
  assert_true( send_error_message( transaction_id, OFPET_TABLE_MOD_FAILED, OFPTMFC_BAD_CONFIG ) );
  assert_true( send_error_message( transaction_id, OFPET_TABLE_MOD_FAILED, OFPTMFC_EPERM ) );
  assert_true( send_error_message( transaction_id, OFPET_SWITCH_CONFIG_FAILED, OFPSCFC_BAD_FLAGS ) );
  assert_true( send_error_message( transaction_id, OFPET_SWITCH_CONFIG_FAILED, OFPSCFC_BAD_LEN ) );
  assert_true( send_error_message( transaction_id, OFPET_SWITCH_CONFIG_FAILED, OFPSCFC_EPERM ) );
  assert_true( send_error_message( transaction_id, OFPET_ROLE_REQUEST_FAILED, OFPRRFC_STALE ) );
  assert_true( send_error_message( transaction_id, OFPET_ROLE_REQUEST_FAILED, OFPRRFC_UNSUP ) );
  assert_true( send_error_message( transaction_id, OFPET_ROLE_REQUEST_FAILED, OFPRRFC_BAD_ROLE ) );
  assert_true( send_error_message( transaction_id, OFPET_METER_MOD_FAILED, OFPMMFC_UNKNOWN ) );
  assert_true( send_error_message( transaction_id, OFPET_METER_MOD_FAILED, OFPMMFC_METER_EXISTS ) );
  assert_true( send_error_message( transaction_id, OFPET_METER_MOD_FAILED, OFPMMFC_INVALID_METER ) );
  assert_true( send_error_message( transaction_id, OFPET_METER_MOD_FAILED, OFPMMFC_UNKNOWN_METER ) );
  assert_true( send_error_message( transaction_id, OFPET_METER_MOD_FAILED, OFPMMFC_BAD_COMMAND ) );
  assert_true( send_error_message( transaction_id, OFPET_METER_MOD_FAILED, OFPMMFC_BAD_FLAGS ) );
  assert_true( send_error_message( transaction_id, OFPET_METER_MOD_FAILED, OFPMMFC_BAD_RATE ) );
  assert_true( send_error_message( transaction_id, OFPET_METER_MOD_FAILED, OFPMMFC_BAD_BURST ) );
  assert_true( send_error_message( transaction_id, OFPET_METER_MOD_FAILED, OFPMMFC_BAD_BAND ) );
  assert_true( send_error_message( transaction_id, OFPET_METER_MOD_FAILED, OFPMMFC_BAD_BAND_VALUE ) );
  assert_true( send_error_message( transaction_id, OFPET_METER_MOD_FAILED, OFPMMFC_OUT_OF_METERS ) );
  assert_true( send_error_message( transaction_id, OFPET_METER_MOD_FAILED, OFPMMFC_OUT_OF_BANDS ) );
  assert_true( send_error_message( transaction_id, OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_TABLE ) );
  assert_true( send_error_message( transaction_id, OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_METADATA ) );
  assert_true( send_error_message( transaction_id, OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_TYPE ) );
  assert_true( send_error_message( transaction_id, OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_LEN ) );
  assert_true( send_error_message( transaction_id, OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_ARGUMENT ) );
  assert_true( send_error_message( transaction_id, OFPET_TABLE_FEATURES_FAILED, OFPTFFC_EPERM ) );
}


/********************************************************************************
 * Run tests.
 ********************************************************************************/

int
main() {
  const UnitTest tests[] = {
    // error handler tests.
    unit_test_setup_teardown( test_switch_set_error_handler, init, cleanup ),
    unit_test_setup_teardown( test_switch_set_error_handler_if_not_initialized, noinit, cleanup ),
    unit_test_setup_teardown( test_switch_set_error_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_error, init, cleanup ),
    unit_test_setup_teardown( test_handle_error_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_error_if_message_is_NULL, init, cleanup ),

    // experimenter error handler tests.
    unit_test_setup_teardown( test_switch_set_experimenter_error_handler, init, cleanup ),
    unit_test_setup_teardown( test_switch_set_experimenter_error_handler_if_not_initialized, noinit, cleanup ),
    unit_test_setup_teardown( test_switch_set_experimenter_error_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_error_experimenter, init, cleanup ),
    unit_test_setup_teardown( test_handle_error_experimenter_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_error_experimenter_if_message_is_NULL, init, cleanup ),

    // experimenter handler tests.
    unit_test_setup_teardown( test_switch_set_experimenter_handler, init, cleanup ),
    unit_test_setup_teardown( test_switch_set_experimenter_handler_if_not_initialized, noinit, cleanup ),
    unit_test_setup_teardown( test_switch_set_experimenter_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_experimenter, init, cleanup ),
    unit_test_setup_teardown( test_handle_experimenter_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_experimenter_if_message_is_NULL, init, cleanup ),

    // packet-out handler tests.
    unit_test_setup_teardown( test_handle_packet_out, init, cleanup ),
    unit_test_setup_teardown( test_handle_packet_out_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_packet_out_if_message_is_NULL, init, cleanup ),

    // flow-mod handler tests.
    unit_test_setup_teardown( test_handle_flow_mod, init, cleanup ),
    unit_test_setup_teardown( test_handle_flow_mod_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_flow_mod_if_message_is_NULL, init, cleanup ),

    // port-mod handler tests.
    unit_test_setup_teardown( test_handle_port_mod, init, cleanup ),
    unit_test_setup_teardown( test_handle_port_mod_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_port_mod_if_message_is_NULL, init, cleanup ),

    unit_test_setup_teardown( test_handle_queue_get_config_request, init, cleanup ),
    unit_test_setup_teardown( test_handle_queue_get_config_request_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_queue_get_config_request_if_message_is_NULL, init, cleanup ),

    // group-mod handler tests.
    unit_test_setup_teardown( test_set_group_mod_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_group_mod_handler_if_not_initialized, noinit, cleanup ),
    unit_test_setup_teardown( test_set_group_mod_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_group_mod, init, cleanup ),
    unit_test_setup_teardown( test_handle_group_mod_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_group_mod_if_message_is_NULL, init, cleanup ),

    // table-mod handler tests.
    unit_test_setup_teardown( test_set_table_mod_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_table_mod_handler_if_not_initialized, noinit, cleanup ),
    unit_test_setup_teardown( test_set_table_mod_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_table_mod, init, cleanup ),
    unit_test_setup_teardown( test_handle_table_mod_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_table_mod_if_message_is_NULL, init, cleanup ),

    // multipart request handler tests.
    unit_test_setup_teardown( test_set_multipart_request_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_multipart_request_handler_if_not_initialized, noinit, cleanup ),
    unit_test_setup_teardown( test_set_multipart_request_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_request, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_request_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_request_if_type_is_OFPMP_DESC, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_request_if_type_is_OFPMP_FLOW, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_request_if_type_is_OFPMP_AGGREGATE, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_request_if_type_is_OFPMP_TABLE, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_request_if_type_is_OFPMP_PORT_STATS, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_request_if_type_is_OFPMP_QUEUE, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_request_if_type_is_OFPMP_GROUP, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_request_if_type_is_OFPMP_GROUP_DESC, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_request_if_type_is_OFPMP_GROUP_FEATURES, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_request_if_type_is_OFPMP_METER, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_request_if_type_is_OFPMP_METER_CONFIG, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_request_if_type_is_OFPMP_METER_FEATURES, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_request_if_type_is_OFPMP_TABLE_FEATURES, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_request_if_type_is_OFPMP_PORT_DESC, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_request_if_type_is_OFPMP_EXPERIMENTER, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_request_with_undefined_type, init, cleanup ),
    unit_test_setup_teardown( test_handle_multipart_request_if_message_is_NULL, init, cleanup ),

    // role request handler tests.
    unit_test_setup_teardown( test_set_role_request_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_role_request_handler_if_not_initialized, noinit, cleanup ),
    unit_test_setup_teardown( test_set_role_request_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_role_request, init, cleanup ),
    unit_test_setup_teardown( test_handle_role_request_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_role_request_if_message_is_NULL, init, cleanup ),

    // get async request handler tests.
    unit_test_setup_teardown( test_set_get_async_request_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_get_async_request_handler_if_not_initialized, noinit, cleanup ),
    unit_test_setup_teardown( test_set_get_async_request_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_get_async_request, init, cleanup ),
    unit_test_setup_teardown( test_handle_get_async_request_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_get_async_request_if_message_is_NULL, init, cleanup ),

    // set async handler tests.
    unit_test_setup_teardown( test_set_set_async_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_set_async_handler_if_not_initialized, noinit, cleanup ),
    unit_test_setup_teardown( test_set_set_async_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_set_async, init, cleanup ),
    unit_test_setup_teardown( test_handle_set_async_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_set_async_if_message_is_NULL, init, cleanup ),

    // meter mod handler tests.
    unit_test_setup_teardown( test_set_meter_mod_handler, init, cleanup ),
    unit_test_setup_teardown( test_set_meter_mod_handler_if_not_initialized, noinit, cleanup ),
    unit_test_setup_teardown( test_set_meter_mod_handler_if_handler_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_meter_mod, init, cleanup ),
    unit_test_setup_teardown( test_handle_meter_mod_if_handler_is_not_registered, init, cleanup ),
    unit_test_setup_teardown( test_handle_meter_mod_if_message_is_NULL, init, cleanup ),

    // handle_openflow_message() tests.
    unit_test_setup_teardown( test_handle_openflow_message, init, cleanup ),
    unit_test_setup_teardown( test_handle_openflow_message_with_malformed_message, init, cleanup ),
    unit_test_setup_teardown( test_handle_openflow_message_if_message_is_NULL, init, cleanup ),
    unit_test_setup_teardown( test_handle_openflow_message_if_unhandled_message_type, init, cleanup ),

    // send_error_message() tests.
    unit_test_setup_teardown( test_send_error_message, init, cleanup ),
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
