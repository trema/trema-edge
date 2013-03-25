/*
 * Unit tests for packetin_filter_interface.[ch]
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


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "trema.h"
#include "trema_private.h"
#include "trema_wrapper.h"
#include "cmockery_trema.h"


/********************************************************************************
 * Mock functions.
 ********************************************************************************/

typedef struct {
  void *callback;
  void *user_data;
} handler_data;


static pid_t ( *original_getpid ) ( void );
static void ( *original_warn )( const char *format, ... );
static void ( *original_error )( const char *format, ... );
static bool ( *original_add_message_replied_callback ) ( const char *service_name,
                                                         void ( *callback )( uint16_t tag, void *data, size_t len, void *user_data ) );
static bool ( *original_delete_message_replied_callback) ( const char *service_name,
                                                         void ( *callback )( uint16_t tag, void *data, size_t len, void *user_data ) );
static bool ( *original_send_request_message ) ( const char *to_service_name, const char *from_service_name,
                                                 const uint16_t tag, const void *data, size_t len, void *user_data );

static void ( *handle_reply ) ( uint16_t tag, void *data, size_t length, void *user_data ) = NULL;

static void *HANDLER = ( void * ) 0x12345678;
static void *USER_DATA = ( void * ) 0x87654321;
static oxm_matches *MATCH = NULL;
static uint16_t PRIORITY = OFP_HIGH_PRIORITY / 2;
static char SERVICE_NAME[] = "send_message_to_here";
static char CLIENT_SERVICE_NAME[] = "packetin_filter.1234";


static pid_t
mock_getpid( void ) {
  return 1234;
}


static void
mock_warn( const char *format, ... ) {
  va_list args;
  va_start( args, format );
  char message[ 1000 ];
  vsprintf( message, format, args );
  va_end( args );

  check_expected( message );
}


static void
mock_error( const char *format, ... ) {
  va_list args;
  va_start( args, format );
  char message[ 1000 ];
  vsprintf( message, format, args );
  va_end( args );

  check_expected( message );
}


static bool
mock_add_message_replied_callback( const char *service_name,
                                   void ( *callback )( uint16_t tag, void *data, size_t len, void *user_data ) ) {
  check_expected( service_name );
  assert_true( callback != NULL );
  handle_reply = callback;

  return ( bool ) mock();
}


static bool
mock_delete_message_replied_callback( const char *service_name,
                                      void ( *callback )( uint16_t tag, void *data, size_t len, void *user_data ) ) {
  check_expected( service_name );
  assert_true( callback != NULL );
  handle_reply = NULL;

  return ( bool ) mock();
}


static bool
mock_send_request_message( const char *to_service_name, const char *from_service_name,
                           const uint16_t tag, const void *data, size_t len, void *user_data ) {
  uint32_t tag32 = tag;
  handler_data *hd = user_data;

  check_expected( to_service_name );
  check_expected( from_service_name );
  check_expected( tag32 );
  check_expected( data );
  check_expected( len );
  check_expected( hd->callback );
  check_expected( hd->user_data );

  if ( hd != NULL ) {
    xfree( hd );
  }

  return ( bool ) mock();
}


static void
mock_add_packetin_filter_handler( int status, void *user_data ) {
  check_expected( status );
  check_expected( user_data );
}


static void
mock_delete_packetin_filter_handler( int status, int n_deleted, void *user_data ) {
  check_expected( status );
  check_expected( n_deleted );
  check_expected( user_data );
}


static void
mock_dump_packetin_filter_handler( int status, int n_entries, packetin_filter_entry *entries, void *user_data ) {
  check_expected( status );
  check_expected( n_entries );
  check_expected( entries );
  check_expected( user_data );
}


/********************************************************************************
 * Setup and teardown functions.
 ********************************************************************************/

static void
alloc_MATCH() {
  uint8_t dst_mac[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
  uint8_t src_mac[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
  uint8_t nomask[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  MATCH = create_oxm_matches();
  append_oxm_match_in_port( MATCH, 1 );
  append_oxm_match_eth_dst( MATCH, dst_mac, nomask );
  append_oxm_match_eth_src( MATCH, src_mac, nomask );
  append_oxm_match_vlan_vid( MATCH, 1, 0 );
  append_oxm_match_vlan_pcp( MATCH, 1 );
  append_oxm_match_eth_type( MATCH, 0x0800 );
  append_oxm_match_ip_proto( MATCH, 0x6 );
  append_oxm_match_ipv4_src( MATCH, 0x0a090807, 0x00000000 );
  append_oxm_match_ipv4_dst( MATCH, 0x0a090807, 0x00000000 );
  append_oxm_match_tcp_src( MATCH, 1024 );
  append_oxm_match_tcp_dst( MATCH, 2048 );
}


static void
free_MATCH() {
  delete_oxm_matches( MATCH );
}


static void
setup() {
  original_getpid = trema_getpid;
  trema_getpid = mock_getpid;
  original_warn = warn;
  warn = mock_warn;
  original_error = error;
  error = mock_error;
  original_add_message_replied_callback = add_message_replied_callback;
  add_message_replied_callback = mock_add_message_replied_callback;
  original_delete_message_replied_callback = delete_message_replied_callback;
  delete_message_replied_callback = mock_delete_message_replied_callback;
  original_send_request_message = send_request_message;
  send_request_message = mock_send_request_message;
  alloc_MATCH();
}


static void
setup_and_init() {
  setup();
  expect_string( mock_add_message_replied_callback, service_name, CLIENT_SERVICE_NAME );
  will_return( mock_add_message_replied_callback, true );
  init_packetin_filter_interface();
}


static void
teardown() {
  free_MATCH();
  trema_getpid = original_getpid;
  error = original_error;
  warn = original_warn;
  add_message_replied_callback = original_add_message_replied_callback;
  delete_message_replied_callback = original_delete_message_replied_callback;
  send_request_message = original_send_request_message;
}


static void
finalize_and_teardown() {
  expect_string( mock_delete_message_replied_callback, service_name, CLIENT_SERVICE_NAME );
  will_return( mock_delete_message_replied_callback, true );
  finalize_packetin_filter_interface();
  teardown();
}


/********************************************************************************
 * init_packetin_filter_interface() tests.
 ********************************************************************************/

static void
test_init_packetin_filter_interface_succeeds() {
  expect_string( mock_add_message_replied_callback, service_name, CLIENT_SERVICE_NAME );
  will_return( mock_add_message_replied_callback, true );

  assert_true( init_packetin_filter_interface() );
}


static void
test_init_packetin_filter_interface_fails_if_already_initialized() {
  expect_string( mock_add_message_replied_callback, service_name, CLIENT_SERVICE_NAME );
  will_return( mock_add_message_replied_callback, true );
  init_packetin_filter_interface();

  assert_false( init_packetin_filter_interface() );
}


/********************************************************************************
 * finalize_packetin_filter_interface() tests.
 ********************************************************************************/

static void
test_finalize_packetin_filter_interface_succeeds() {
  expect_string( mock_add_message_replied_callback, service_name, CLIENT_SERVICE_NAME );
  will_return( mock_add_message_replied_callback, true );
  init_packetin_filter_interface();

  expect_string( mock_delete_message_replied_callback, service_name, CLIENT_SERVICE_NAME );
  will_return( mock_delete_message_replied_callback, true );

  assert_true( finalize_packetin_filter_interface() );
}


static void
test_finalize_packetin_filter_interface_fails_if_not_initialized() {
  assert_false( finalize_packetin_filter_interface() );
}


/********************************************************************************
 * add_packetin_filter() tests.
 ********************************************************************************/

static void
test_add_packetin_filter_succeeds() {
  uint16_t match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields ) + get_oxm_matches_length( MATCH ) );
  uint16_t match_pad_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );
  uint16_t entry_len = ( uint16_t ) ( offsetof( packetin_filter_entry, match ) + match_pad_len );
  uint16_t req_len = ( uint16_t ) ( offsetof( add_packetin_filter_request, entry ) + entry_len );
  add_packetin_filter_request *expected_data = xcalloc( 1, req_len );
  memset( expected_data, 0, req_len );
  expected_data->length = htons( req_len );
  expected_data->entry.length = htons( entry_len );
  expected_data->entry.priority = htons( PRIORITY );
  strncpy( expected_data->entry.service_name, SERVICE_NAME, sizeof( expected_data->entry.service_name ) );
  construct_ofp_match( &expected_data->entry.match, MATCH );

  expect_string( mock_send_request_message, to_service_name, PACKETIN_FILTER_MANAGEMENT_SERVICE );
  expect_string( mock_send_request_message, from_service_name, CLIENT_SERVICE_NAME );
  expect_value( mock_send_request_message, tag32, MESSENGER_ADD_PACKETIN_FILTER_REQUEST );
  expect_memory( mock_send_request_message, data, expected_data, req_len );
  expect_value( mock_send_request_message, len, req_len );
  expect_value( mock_send_request_message, hd->callback, HANDLER );
  expect_value( mock_send_request_message, hd->user_data, USER_DATA );
  will_return( mock_send_request_message, true );

  assert_true( add_packetin_filter( MATCH, PRIORITY, SERVICE_NAME, HANDLER, USER_DATA ) );

  xfree( expected_data );
}


static void
test_add_packetin_filter_succeeds_if_not_initialized() {
  uint16_t match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields ) + get_oxm_matches_length( MATCH ) );
  uint16_t match_pad_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );
  uint16_t entry_len = ( uint16_t ) ( offsetof( packetin_filter_entry, match ) + match_pad_len );
  uint16_t req_len = ( uint16_t ) ( offsetof( add_packetin_filter_request, entry ) + entry_len );
  add_packetin_filter_request *expected_data = xcalloc( 1, req_len );
  memset( expected_data, 0, req_len );
  expected_data->length = htons( req_len );
  expected_data->entry.length = htons( entry_len );
  expected_data->entry.priority = htons( PRIORITY );
  strncpy( expected_data->entry.service_name, SERVICE_NAME, sizeof( expected_data->entry.service_name ) );
  construct_ofp_match( &expected_data->entry.match, MATCH );

  expect_string( mock_add_message_replied_callback, service_name, CLIENT_SERVICE_NAME );
  will_return( mock_add_message_replied_callback, true );
  expect_string( mock_send_request_message, to_service_name, PACKETIN_FILTER_MANAGEMENT_SERVICE );
  expect_string( mock_send_request_message, from_service_name, CLIENT_SERVICE_NAME );
  expect_value( mock_send_request_message, tag32, MESSENGER_ADD_PACKETIN_FILTER_REQUEST );
  expect_memory( mock_send_request_message, data, expected_data, req_len );
  expect_value( mock_send_request_message, len, req_len );
  expect_value( mock_send_request_message, hd->callback, HANDLER );
  expect_value( mock_send_request_message, hd->user_data, USER_DATA );
  will_return( mock_send_request_message, true );

  assert_true( add_packetin_filter( MATCH, PRIORITY, SERVICE_NAME, HANDLER, USER_DATA ) );

  xfree( expected_data );
}


static void
test_add_packetin_filter_fails_if_service_name_is_NULL() {
  expect_string( mock_error, message, "Service name must be specified." );

  assert_false( add_packetin_filter( MATCH, PRIORITY, NULL, HANDLER, USER_DATA ) );
}


static void
test_add_packetin_filter_fails_if_service_name_is_zero_length() {
  char service_name[] = "";
  expect_string( mock_error, message, "Service name must be specified." );

  assert_false( add_packetin_filter( MATCH, PRIORITY, service_name, HANDLER, USER_DATA ) );
}



/********************************************************************************
 * delete_packetin_filter() tests.
 ********************************************************************************/

static void
test_delete_packetin_filter_succeeds_with_PACKETIN_FILTER_FLAG_MATCH_STRICT() {
  uint8_t flags = PACKETIN_FILTER_FLAG_MATCH_STRICT;

  uint16_t match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields ) + get_oxm_matches_length( MATCH ) );
  uint16_t match_pad_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );
  uint16_t entry_len = ( uint16_t ) ( offsetof( packetin_filter_entry, match ) + match_pad_len );
  uint16_t req_len = ( uint16_t ) ( offsetof( delete_packetin_filter_request, criteria ) + entry_len );
  delete_packetin_filter_request *expected_data = xcalloc( 1, req_len );
  memset( expected_data, 0, req_len );
  expected_data->length = htons( req_len );
  expected_data->flags = flags;
  expected_data->criteria.length = htons( entry_len );
  expected_data->criteria.priority = htons( PRIORITY );
  strncpy( expected_data->criteria.service_name, SERVICE_NAME, sizeof( expected_data->criteria.service_name ) );
  construct_ofp_match( &expected_data->criteria.match, MATCH );

  expect_string( mock_send_request_message, to_service_name, PACKETIN_FILTER_MANAGEMENT_SERVICE );
  expect_string( mock_send_request_message, from_service_name, CLIENT_SERVICE_NAME );
  expect_value( mock_send_request_message, tag32, MESSENGER_DELETE_PACKETIN_FILTER_REQUEST );
  expect_memory( mock_send_request_message, data, expected_data, req_len );
  expect_value( mock_send_request_message, len, req_len );
  expect_value( mock_send_request_message, hd->callback, HANDLER );
  expect_value( mock_send_request_message, hd->user_data, USER_DATA );
  will_return( mock_send_request_message, true );

  assert_true( delete_packetin_filter( MATCH, PRIORITY, SERVICE_NAME, flags, HANDLER, USER_DATA ) );

  xfree( expected_data );
}


static void
test_delete_packetin_filter_succeeds_with_PACKETIN_FILTER_FLAG_MATCH_LOOSE() {
  uint8_t flags = PACKETIN_FILTER_FLAG_MATCH_LOOSE;

  uint16_t match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields ) + get_oxm_matches_length( MATCH ) );
  uint16_t match_pad_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );
  uint16_t entry_len = ( uint16_t ) ( offsetof( packetin_filter_entry, match ) + match_pad_len );
  uint16_t req_len = ( uint16_t ) ( offsetof( delete_packetin_filter_request, criteria ) + entry_len );
  delete_packetin_filter_request *expected_data = xcalloc( 1, req_len );
  memset( expected_data, 0, req_len );
  expected_data->length = htons( req_len );
  expected_data->flags = flags;
  expected_data->criteria.length = htons( entry_len );
  expected_data->criteria.priority = htons( PRIORITY );
  strncpy( expected_data->criteria.service_name, SERVICE_NAME, sizeof( expected_data->criteria.service_name ) );
  construct_ofp_match( &expected_data->criteria.match, MATCH );

  expect_string( mock_send_request_message, to_service_name, PACKETIN_FILTER_MANAGEMENT_SERVICE );
  expect_string( mock_send_request_message, from_service_name, CLIENT_SERVICE_NAME );
  expect_value( mock_send_request_message, tag32, MESSENGER_DELETE_PACKETIN_FILTER_REQUEST );
  expect_memory( mock_send_request_message, data, expected_data, req_len );
  expect_value( mock_send_request_message, len, req_len );
  expect_value( mock_send_request_message, hd->callback, HANDLER );
  expect_value( mock_send_request_message, hd->user_data, USER_DATA );
  will_return( mock_send_request_message, true );

  assert_true( delete_packetin_filter( MATCH, PRIORITY, SERVICE_NAME, flags, HANDLER, USER_DATA ) );

  xfree( expected_data );
}


static void
test_delete_packetin_filter_succeeds_if_not_initialized() {
  uint8_t flags = PACKETIN_FILTER_FLAG_MATCH_STRICT;

  uint16_t match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields ) + get_oxm_matches_length( MATCH ) );
  uint16_t match_pad_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );
  uint16_t entry_len = ( uint16_t ) ( offsetof( packetin_filter_entry, match ) + match_pad_len );
  uint16_t req_len = ( uint16_t ) ( offsetof( delete_packetin_filter_request, criteria ) + entry_len );
  delete_packetin_filter_request *expected_data = xcalloc( 1, req_len );
  memset( expected_data, 0, req_len );
  expected_data->length = htons( req_len );
  expected_data->flags = flags;
  expected_data->criteria.length = htons( entry_len );
  expected_data->criteria.priority = htons( PRIORITY );
  strncpy( expected_data->criteria.service_name, SERVICE_NAME, sizeof( expected_data->criteria.service_name ) );
  construct_ofp_match( &expected_data->criteria.match, MATCH );

  expect_string( mock_add_message_replied_callback, service_name, CLIENT_SERVICE_NAME );
  will_return( mock_add_message_replied_callback, true );
  expect_string( mock_send_request_message, to_service_name, PACKETIN_FILTER_MANAGEMENT_SERVICE );
  expect_string( mock_send_request_message, from_service_name, CLIENT_SERVICE_NAME );
  expect_value( mock_send_request_message, tag32, MESSENGER_DELETE_PACKETIN_FILTER_REQUEST );
  expect_memory( mock_send_request_message, data, expected_data, req_len );
  expect_value( mock_send_request_message, len, req_len );
  expect_value( mock_send_request_message, hd->callback, HANDLER );
  expect_value( mock_send_request_message, hd->user_data, USER_DATA );
  will_return( mock_send_request_message, true );

  assert_true( delete_packetin_filter( MATCH, PRIORITY, SERVICE_NAME, flags, HANDLER, USER_DATA ) );

  xfree( expected_data );
}


/********************************************************************************
 * dump_packetin_filter() tests.
 ********************************************************************************/

static void
test_dump_packetin_filter_succeeds_with_PACKETIN_FILTER_FLAG_MATCH_STRICT() {
  uint8_t flags = PACKETIN_FILTER_FLAG_MATCH_STRICT;

  uint16_t match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields ) + get_oxm_matches_length( MATCH ) );
  uint16_t match_pad_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );
  uint16_t entry_len = ( uint16_t ) ( offsetof( packetin_filter_entry, match ) + match_pad_len );
  uint16_t req_len = ( uint16_t ) ( offsetof( delete_packetin_filter_request, criteria ) + entry_len );
  dump_packetin_filter_request *expected_data = xcalloc( 1, req_len );
  expected_data->length = htons( req_len );
  expected_data->flags = flags;
  expected_data->criteria.length = htons( entry_len );
  expected_data->criteria.priority = htons( PRIORITY );
  strcpy( expected_data->criteria.service_name, SERVICE_NAME );
  construct_ofp_match( &expected_data->criteria.match, MATCH );

  expect_string( mock_send_request_message, to_service_name, PACKETIN_FILTER_MANAGEMENT_SERVICE );
  expect_string( mock_send_request_message, from_service_name, CLIENT_SERVICE_NAME );
  expect_value( mock_send_request_message, tag32, MESSENGER_DUMP_PACKETIN_FILTER_REQUEST );
  expect_memory( mock_send_request_message, data, expected_data, req_len );
  expect_value( mock_send_request_message, len, req_len );
  expect_value( mock_send_request_message, hd->callback, HANDLER );
  expect_value( mock_send_request_message, hd->user_data, USER_DATA );
  will_return( mock_send_request_message, true );

  assert_true( dump_packetin_filter( MATCH, PRIORITY, SERVICE_NAME, flags, HANDLER, USER_DATA ) );

  xfree( expected_data );
}


static void
test_dump_packetin_filter_succeeds_with_PACKETIN_FILTER_FLAG_MATCH_LOOSE() {
  uint8_t flags = PACKETIN_FILTER_FLAG_MATCH_LOOSE;

  uint16_t match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields ) + get_oxm_matches_length( MATCH ) );
  uint16_t match_pad_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );
  uint16_t entry_len = ( uint16_t ) ( offsetof( packetin_filter_entry, match ) + match_pad_len );
  uint16_t req_len = ( uint16_t ) ( offsetof( delete_packetin_filter_request, criteria ) + entry_len );
  dump_packetin_filter_request *expected_data = xcalloc( 1, req_len );
  expected_data->length = htons( req_len );
  expected_data->flags = flags;
  expected_data->criteria.length = htons( entry_len );
  expected_data->criteria.priority = htons( PRIORITY );
  strcpy( expected_data->criteria.service_name, SERVICE_NAME );
  construct_ofp_match( &expected_data->criteria.match, MATCH );

  expect_string( mock_send_request_message, to_service_name, PACKETIN_FILTER_MANAGEMENT_SERVICE );
  expect_string( mock_send_request_message, from_service_name, CLIENT_SERVICE_NAME );
  expect_value( mock_send_request_message, tag32, MESSENGER_DUMP_PACKETIN_FILTER_REQUEST );
  expect_memory( mock_send_request_message, data, expected_data, req_len );
  expect_value( mock_send_request_message, len, req_len );
  expect_value( mock_send_request_message, hd->callback, HANDLER );
  expect_value( mock_send_request_message, hd->user_data, USER_DATA );
  will_return( mock_send_request_message, true );

  assert_true( dump_packetin_filter( MATCH, PRIORITY, SERVICE_NAME, flags, HANDLER, USER_DATA ) );

  xfree( expected_data );
}


static void
test_dump_packetin_filter_succeeds_if_not_initialized() {
  uint8_t flags = PACKETIN_FILTER_FLAG_MATCH_STRICT;

  uint16_t match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields ) + get_oxm_matches_length( MATCH ) );
  uint16_t match_pad_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );
  uint16_t entry_len = ( uint16_t ) ( offsetof( packetin_filter_entry, match ) + match_pad_len );
  uint16_t req_len = ( uint16_t ) ( offsetof( delete_packetin_filter_request, criteria ) + entry_len );
  dump_packetin_filter_request *expected_data = xcalloc( 1, req_len );
  expected_data->length = htons( req_len );
  expected_data->flags = flags;
  expected_data->criteria.length = htons( entry_len );
  expected_data->criteria.priority = htons( PRIORITY );
  strcpy( expected_data->criteria.service_name, SERVICE_NAME );
  construct_ofp_match( &expected_data->criteria.match, MATCH );

  expect_string( mock_add_message_replied_callback, service_name, CLIENT_SERVICE_NAME );
  will_return( mock_add_message_replied_callback, true );
  expect_string( mock_send_request_message, to_service_name, PACKETIN_FILTER_MANAGEMENT_SERVICE );
  expect_string( mock_send_request_message, from_service_name, CLIENT_SERVICE_NAME );
  expect_value( mock_send_request_message, tag32, MESSENGER_DUMP_PACKETIN_FILTER_REQUEST );
  expect_memory( mock_send_request_message, data, expected_data, req_len );
  expect_value( mock_send_request_message, len, req_len );
  expect_value( mock_send_request_message, hd->callback, HANDLER );
  expect_value( mock_send_request_message, hd->user_data, USER_DATA );
  will_return( mock_send_request_message, true );

  assert_true( dump_packetin_filter( MATCH, PRIORITY, SERVICE_NAME, flags, HANDLER, USER_DATA ) );

  xfree( expected_data );
}


/********************************************************************************
 * handle_reply() tests.
 ********************************************************************************/

static void
test_handle_reply_succeeds_with_add_packetin_filter_reply() {
  add_packetin_filter_reply reply;
  memset( &reply, 0, sizeof( add_packetin_filter_reply ) );
  reply.status = PACKETIN_FILTER_OPERATION_SUCCEEDED;
  handler_data *user_data = xmalloc( sizeof( handler_data ) );
  user_data->callback = mock_add_packetin_filter_handler;
  user_data->user_data = USER_DATA;

  expect_value( mock_add_packetin_filter_handler, status, PACKETIN_FILTER_OPERATION_SUCCEEDED );
  expect_value( mock_add_packetin_filter_handler, user_data, USER_DATA );

  handle_reply( MESSENGER_ADD_PACKETIN_FILTER_REPLY, &reply, sizeof( add_packetin_filter_reply ), user_data );
}


static void
test_handle_reply_fails_with_too_short_add_packetin_filter_reply() {
  add_packetin_filter_reply reply;
  memset( &reply, 0, sizeof( add_packetin_filter_reply ) );
  reply.status = PACKETIN_FILTER_OPERATION_SUCCEEDED;
  handler_data user_data;
  user_data.callback = HANDLER;
  user_data.user_data = USER_DATA;
  size_t reply_length = sizeof( add_packetin_filter_reply ) - 1;

  expect_string( mock_error, message, "Invalid add packetin filter reply ( length = 0 )." );

  handle_reply( MESSENGER_ADD_PACKETIN_FILTER_REPLY, &reply, reply_length, &user_data );
}


static void
test_handle_reply_fails_with_too_long_add_packetin_filter_reply() {
  add_packetin_filter_reply reply;
  memset( &reply, 0, sizeof( add_packetin_filter_reply ) );
  reply.status = PACKETIN_FILTER_OPERATION_SUCCEEDED;
  handler_data user_data;
  user_data.callback = HANDLER;
  user_data.user_data = USER_DATA;
  size_t reply_length = sizeof( add_packetin_filter_reply ) + 1;

  expect_string( mock_error, message, "Invalid add packetin filter reply ( length = 2 )." );

  handle_reply( MESSENGER_ADD_PACKETIN_FILTER_REPLY, &reply, reply_length, &user_data );
}


static void
test_handle_reply_succeeds_with_delete_packetin_filter_reply() {
  delete_packetin_filter_reply reply;
  memset( &reply, 0, sizeof( delete_packetin_filter_reply ) );
  reply.status = PACKETIN_FILTER_OPERATION_SUCCEEDED;
  int n_deleted = 128;
  reply.n_deleted = htonl( ( uint32_t ) n_deleted );
  handler_data *user_data = xmalloc( sizeof( handler_data ) );
  user_data->callback = mock_delete_packetin_filter_handler;
  user_data->user_data = USER_DATA;

  expect_value( mock_delete_packetin_filter_handler, status, PACKETIN_FILTER_OPERATION_SUCCEEDED );
  expect_value( mock_delete_packetin_filter_handler, n_deleted, n_deleted );
  expect_value( mock_delete_packetin_filter_handler, user_data, USER_DATA );

  handle_reply( MESSENGER_DELETE_PACKETIN_FILTER_REPLY, &reply, sizeof( delete_packetin_filter_reply ), user_data );
}


static void
test_handle_reply_fails_with_too_short_delete_packetin_filter_reply() {
  delete_packetin_filter_reply reply;
  memset( &reply, 0, sizeof( delete_packetin_filter_reply ) );
  reply.status = PACKETIN_FILTER_OPERATION_SUCCEEDED;
  reply.n_deleted = htonl( 128 );
  handler_data user_data;
  user_data.callback = HANDLER;
  user_data.user_data = USER_DATA;
  size_t reply_length = sizeof( delete_packetin_filter_reply ) - 1;

  expect_string( mock_error, message, "Invalid delete packetin filter reply ( length = 4 )." );

  handle_reply( MESSENGER_DELETE_PACKETIN_FILTER_REPLY, &reply, reply_length, &user_data );
}


static void
test_handle_reply_fails_with_too_long_delete_packetin_filter_reply() {
  delete_packetin_filter_reply reply;
  memset( &reply, 0, sizeof( delete_packetin_filter_reply ) );
  reply.status = PACKETIN_FILTER_OPERATION_SUCCEEDED;
  reply.n_deleted = htonl( 128 );
  handler_data user_data;
  user_data.callback = HANDLER;
  user_data.user_data = USER_DATA;
  size_t reply_length = sizeof( delete_packetin_filter_reply ) + 1;

  expect_string( mock_error, message, "Invalid delete packetin filter reply ( length = 6 )." );

  handle_reply( MESSENGER_DELETE_PACKETIN_FILTER_REPLY, &reply, reply_length, &user_data );
}


static void
test_handle_reply_succeeds_with_dump_packetin_filter_reply() {
  int n_entries = 16;

  uint16_t match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields ) + get_oxm_matches_length( MATCH ) );
  uint16_t match_pad_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );
  uint16_t entry_len = ( uint16_t ) ( offsetof( packetin_filter_entry, match ) + match_pad_len );
  size_t entries_length = entry_len * ( size_t ) n_entries;
  size_t reply_length = offsetof( dump_packetin_filter_reply, entries ) + entries_length;
  dump_packetin_filter_reply *reply = xmalloc( reply_length );
  memset( reply, 0, reply_length );
  reply->length = ( uint16_t ) reply_length;
  reply->status = PACKETIN_FILTER_OPERATION_SUCCEEDED;
  reply->n_entries = htonl( ( uint32_t ) n_entries );
  packetin_filter_entry *expected_entries = xmalloc( entries_length );
  for ( int i = 0; i < n_entries; i++ ) {
    packetin_filter_entry *entry = ( packetin_filter_entry * ) ( ( char * ) reply->entries + entry_len * i );
    entry->length = htons( entry_len );
    construct_ofp_match( &entry->match, MATCH );
    entry->priority = htons( PRIORITY );
    memcpy( entry->service_name, SERVICE_NAME, sizeof( entry->service_name ) );
    packetin_filter_entry *expected_entry = ( packetin_filter_entry * ) ( ( char * ) expected_entries + entry_len * i );
    expected_entry->length = entry_len;
    expected_entry->priority = PRIORITY;
    memset( expected_entry->pad, 0, sizeof( expected_entry->pad ) );
    memcpy( expected_entry->service_name, SERVICE_NAME, sizeof( expected_entry->service_name ) );
    construct_ofp_match( &expected_entry->match, MATCH );
    ntoh_match( &expected_entry->match, &expected_entry->match );
  }
  handler_data *user_data = xmalloc( sizeof( handler_data ) );
  user_data->callback = mock_dump_packetin_filter_handler;
  user_data->user_data = USER_DATA;

  expect_value( mock_dump_packetin_filter_handler, status, PACKETIN_FILTER_OPERATION_SUCCEEDED );
  expect_value( mock_dump_packetin_filter_handler, n_entries, n_entries );
  expect_memory( mock_dump_packetin_filter_handler, entries, expected_entries, entries_length );
  expect_value( mock_dump_packetin_filter_handler, user_data, USER_DATA );

  handle_reply( MESSENGER_DUMP_PACKETIN_FILTER_REPLY, reply, reply_length, user_data );

  xfree( reply );
  xfree( expected_entries );
}


static void
test_handle_reply_fails_with_too_short_dump_packetin_filter_reply() {
  dump_packetin_filter_reply reply;
  memset( &reply, 0, sizeof( dump_packetin_filter_reply ) );
  reply.status = PACKETIN_FILTER_OPERATION_SUCCEEDED;
  reply.n_entries = htonl( 128 );
  handler_data user_data;
  user_data.callback = HANDLER;
  user_data.user_data = USER_DATA;
  size_t reply_length = offsetof( dump_packetin_filter_reply, entries ) - 1;

  expect_string( mock_error, message, "Invalid dump packetin filter reply ( length = 7 )." );

  handle_reply( MESSENGER_DUMP_PACKETIN_FILTER_REPLY, &reply, reply_length, &user_data );
}


static void
test_handle_reply_fails_with_invalid_dump_packetin_filter_reply() {
  dump_packetin_filter_reply reply;
  memset( &reply, 0, sizeof( dump_packetin_filter_reply ) );
  reply.status = PACKETIN_FILTER_OPERATION_SUCCEEDED;
  reply.n_entries = htonl( 1 );
  handler_data user_data;
  user_data.callback = HANDLER;
  user_data.user_data = USER_DATA;
  size_t reply_length = offsetof( dump_packetin_filter_reply, entries ) + 1;

  expect_string( mock_error, message, "Invalid dump packetin filter reply ( length = 9 )." );

  handle_reply( MESSENGER_DUMP_PACKETIN_FILTER_REPLY, &reply, reply_length, &user_data );
}


static void
test_handle_reply_fails_with_undefined_reply_type() {
  uint16_t tag = MESSENGER_DUMP_PACKETIN_FILTER_REPLY + 1;
  uint64_t reply;
  size_t reply_length = sizeof( reply );
  handler_data user_data;
  user_data.callback = HANDLER;
  user_data.user_data = USER_DATA;

  expect_string( mock_warn, message, "Undefined reply tag ( tag = 0x16, length = 8 )." );

  handle_reply( tag, &reply, reply_length, &user_data );
}


/********************************************************************************
 * Run tests.
 ********************************************************************************/

int
main() {
  const UnitTest tests[] = {
    // init_packetin_filter_interface() tests.
    unit_test_setup_teardown( test_init_packetin_filter_interface_succeeds, setup, finalize_and_teardown ),
    unit_test_setup_teardown( test_init_packetin_filter_interface_fails_if_already_initialized, setup, finalize_and_teardown ),

    // finalize_packetin_filter_interface() tests.
    unit_test_setup_teardown( test_finalize_packetin_filter_interface_succeeds, setup, teardown ),
    unit_test_setup_teardown( test_finalize_packetin_filter_interface_fails_if_not_initialized, setup, teardown ),

    // add_packetin_filter() tests.
    unit_test_setup_teardown( test_add_packetin_filter_succeeds, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_add_packetin_filter_succeeds_if_not_initialized, setup, finalize_and_teardown ),
    unit_test_setup_teardown( test_add_packetin_filter_fails_if_service_name_is_NULL, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_add_packetin_filter_fails_if_service_name_is_zero_length, setup_and_init, finalize_and_teardown ),

    // delete_packetin_filter() tests.
    unit_test_setup_teardown( test_delete_packetin_filter_succeeds_with_PACKETIN_FILTER_FLAG_MATCH_STRICT, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_delete_packetin_filter_succeeds_with_PACKETIN_FILTER_FLAG_MATCH_LOOSE, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_delete_packetin_filter_succeeds_if_not_initialized, setup, finalize_and_teardown ),

    // dump_packetin_filter() tests.
    unit_test_setup_teardown( test_dump_packetin_filter_succeeds_with_PACKETIN_FILTER_FLAG_MATCH_STRICT, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_dump_packetin_filter_succeeds_with_PACKETIN_FILTER_FLAG_MATCH_LOOSE, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_dump_packetin_filter_succeeds_if_not_initialized, setup, finalize_and_teardown ),

    // handle_reply() tests.
    unit_test_setup_teardown( test_handle_reply_succeeds_with_add_packetin_filter_reply, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_handle_reply_fails_with_too_short_add_packetin_filter_reply, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_handle_reply_fails_with_too_long_add_packetin_filter_reply, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_handle_reply_succeeds_with_delete_packetin_filter_reply, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_handle_reply_fails_with_too_short_delete_packetin_filter_reply, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_handle_reply_fails_with_too_long_delete_packetin_filter_reply, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_handle_reply_succeeds_with_dump_packetin_filter_reply, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_handle_reply_fails_with_too_short_dump_packetin_filter_reply, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_handle_reply_fails_with_invalid_dump_packetin_filter_reply, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_handle_reply_fails_with_undefined_reply_type, setup_and_init, finalize_and_teardown ),
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
