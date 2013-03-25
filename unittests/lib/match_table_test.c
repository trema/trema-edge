/*
 * Unit tests for match table.
 *
 * Author: Kazushi SUGYO
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


#include <net/ethernet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "checks.h"
#include "cmockery_trema.h"
#include "ether.h"
#include "log.h"
#include "match_table.h"
#include "linked_list.h"
#include "utility.h"
#include "wrapper.h"


typedef struct match_table {
  list_element *wildcards_table;
  pthread_mutex_t *mutex;
} match_table;


extern match_table *_match_table_head;


/*************************************************************************
 * Helper.
 *************************************************************************/

// Setup and teardown function.

#define XFREE( x ) ({ void *p = ( x ); assert_true( p != NULL ); xfree( p ); })

static void ( *original_die )( const char *format, ... );

static void
mock_die( const char *format, ... ) {
  UNUSED( format );
  mock_assert( false, "mock_die", __FILE__, __LINE__ ); } // Hoaxes gcov.


static void
setup() {
  original_die = die;
  die = mock_die;
}


static void
teardown() {
  die = original_die;
}


static void
setup_and_init() {
  setup();
  init_match_table();
}


static void
finalize_and_teardown() {
  finalize_match_table();
  teardown();
}


#define HIGH_PRIORITY 0xffff
#define LOW_PRIORITY 0x0
#define DEFAULT_PRIORITY OFP_DEFAULT_PRIORITY

// Exact entry helper.

static void
set_alice_match_entry( oxm_matches *match ) {
  append_oxm_match_eth_type( match, ETHERTYPE_IP );
  append_oxm_match_ipv4_src( match, 0x0a000101, 0 );
  append_oxm_match_ipv4_dst( match, 0x0a000202, 0 );
}


static void
set_bob_match_entry( oxm_matches *match ) {
  append_oxm_match_eth_type( match, ETHERTYPE_IP );
  append_oxm_match_ipv4_src( match, 0x0a000202, 0 );
  append_oxm_match_ipv4_dst( match, 0x0a000101, 0 );
}


static void
set_carol_match_entry( oxm_matches *match ) {
  append_oxm_match_eth_type( match, ETHERTYPE_IP );
  append_oxm_match_ipv4_src( match, 0x0a000303, 0 );
  append_oxm_match_ipv4_dst( match, 0xffffffff, 0 );
}

#define ALICE_MATCH_SERVICE_NAME "service-name-alice"
#define BOB_MATCH_SERVICE_NAME "service-name-bob"
#define CAROL_MATCH_SERVICE_NAME "service-name-carol"
#define CAROL_MATCH_OTHER_SERVICE_NAME "other-service-name-carol"

#define USER_DATA "user-data"


// Wildcards entry helper.

static void
set_any_wildcards_entry( oxm_matches *match ) {
  ( void ) match;
}


static void
set_lldp_wildcards_entry( oxm_matches *match ) {
  append_oxm_match_eth_type( match, ETH_ETHTYPE_LLDP );
}


static void
set_alice_wildcards_entry( oxm_matches *match ) {
  append_oxm_match_eth_type( match, ETHERTYPE_IP );
  append_oxm_match_ipv4_src( match, 0x0a000101, 0 );
}


static void
set_bob_wildcards_entry( oxm_matches *match ) {
  append_oxm_match_eth_type( match, ETHERTYPE_IP );
  append_oxm_match_ipv4_src( match, 0x0a000202, 0 );
}


static void
set_carol_wildcards_entry( oxm_matches *match ) {
  append_oxm_match_eth_type( match, ETHERTYPE_IP );
  append_oxm_match_ipv4_src( match, 0x0a000303, 0 );
}


#define ANY_MATCH_SERVICE_NAME "service-name-any"
#define LLDP_MATCH_SERVICE_NAME "service-name-lldp"


/*************************************************************************
 * init and finalize tests.
 *************************************************************************/

static void
test_init_and_finalize_match_table_succeeds() {
  assert_true( _match_table_head == NULL );
  init_match_table();
  assert_true( _match_table_head != NULL );
  finalize_match_table();
  assert_true( _match_table_head == NULL );
}


static void
test_init_match_table_dies_if_already_initialized() {
  init_match_table();
  assert_true( _match_table_head != NULL );
  expect_assert_failure( init_match_table() );
  finalize_match_table();
}


static void
test_finalize_match_table_dies_if_not_initialized() {
  assert_true( _match_table_head == NULL );
  expect_assert_failure( finalize_match_table() );
}


static void
test_insert_match_entry_dies_if_not_initialized() {
  assert_true( _match_table_head == NULL );
  oxm_matches *alice = create_oxm_matches();
  set_alice_match_entry( alice );
  void *data =  xstrdup( ALICE_MATCH_SERVICE_NAME );
  expect_assert_failure( insert_match_entry( alice, DEFAULT_PRIORITY, data ) );
  XFREE( data );
  delete_oxm_matches( alice );
}


static void
test_lookup_match_strict_entry_dies_if_not_initialized() {
  assert_true( _match_table_head == NULL );
  oxm_matches *alice = create_oxm_matches();
  set_alice_match_entry( alice );
  expect_assert_failure( lookup_match_strict_entry( alice, DEFAULT_PRIORITY ) );
  delete_oxm_matches( alice );
}


static void
test_lookup_match_entry_dies_if_not_initialized() {
  assert_true( _match_table_head == NULL );
  oxm_matches *alice = create_oxm_matches();
  set_alice_match_entry( alice );
  expect_assert_failure( lookup_match_entry( alice ) );
  delete_oxm_matches( alice );
}


static void
test_update_match_entry_dies_if_not_initialized() {
  assert_true( _match_table_head == NULL );
  oxm_matches *alice = create_oxm_matches();
  set_alice_match_entry( alice );
  void *data =  xstrdup( ALICE_MATCH_SERVICE_NAME );
  expect_assert_failure( update_match_entry( alice, DEFAULT_PRIORITY, data ) );
  XFREE( data );
  delete_oxm_matches( alice );
}


static void
test_delete_match_strict_entry_dies_if_not_initialized() {
  assert_true( _match_table_head == NULL );
  oxm_matches *alice = create_oxm_matches();
  set_alice_match_entry( alice );
  expect_assert_failure( delete_match_strict_entry( alice, DEFAULT_PRIORITY ) );
  delete_oxm_matches( alice );
}


static void
test_foreach_match_entry_dies_if_not_initialized_helper( oxm_matches *match, uint16_t priority, void *data, void *user_data ) {
  UNUSED( match );
  UNUSED( priority );
  UNUSED( data );
  UNUSED( user_data );
  assert_true( false );
}


static void
test_foreach_match_entry_dies_if_not_initialized() {
  assert_true( _match_table_head == NULL );
  expect_assert_failure( foreach_match_table( test_foreach_match_entry_dies_if_not_initialized_helper, NULL ) );
}


/*************************************************************************
 * insert, lookup and delete entry tests.
 *************************************************************************/

// insert, lookup and delete wildcards entry tests.

static void
test_insert_wildcards_entry_into_empty_table_succeeds() {
  oxm_matches *alice = create_oxm_matches();
  set_alice_match_entry( alice );
  oxm_matches *alice_wildcards = create_oxm_matches();
  set_alice_wildcards_entry( alice_wildcards );
  assert_true( insert_match_entry( alice_wildcards, DEFAULT_PRIORITY, xstrdup( ALICE_MATCH_SERVICE_NAME ) ) );

  oxm_matches *bob = create_oxm_matches();
  set_bob_match_entry( bob );

  void *data0 = lookup_match_strict_entry( alice_wildcards, DEFAULT_PRIORITY );
  assert_true( data0 != NULL );
  assert_string_equal( ( char * ) data0, ALICE_MATCH_SERVICE_NAME );
  void *data1 = lookup_match_entry( alice );
  assert_true( data1 != NULL );
  assert_string_equal( ( char * ) data1, ALICE_MATCH_SERVICE_NAME );
  assert_true( data0 == data1 );
  assert_true( lookup_match_entry( bob ) == NULL );
  void *data2 = delete_match_strict_entry( alice_wildcards, DEFAULT_PRIORITY );
  assert_true( data2 != NULL );
  assert_string_equal( ( char * ) data2, ALICE_MATCH_SERVICE_NAME );
  assert_true( data1 == data2 );
  XFREE( data2 );

  delete_oxm_matches( alice );
  delete_oxm_matches( alice_wildcards );
  delete_oxm_matches( bob );
}


static void
test_insert_wildcards_entry_into_not_empty_exact_table_succeeds() {
  oxm_matches *alice_wildcards = create_oxm_matches();
  set_alice_wildcards_entry( alice_wildcards );
  assert_true( insert_match_entry( alice_wildcards, DEFAULT_PRIORITY, xstrdup( ALICE_MATCH_SERVICE_NAME ) ) );

  oxm_matches *bob = create_oxm_matches();
  set_bob_match_entry( bob );
  oxm_matches *bob_wildcards = create_oxm_matches();
  set_bob_wildcards_entry( bob_wildcards );
  assert_true( insert_match_entry( bob_wildcards, DEFAULT_PRIORITY + 1, xstrdup( BOB_MATCH_SERVICE_NAME ) ) );

  void *data0 = lookup_match_strict_entry( bob_wildcards, DEFAULT_PRIORITY + 1 );
  assert_true( data0 != NULL );
  assert_string_equal( ( char * ) data0, BOB_MATCH_SERVICE_NAME );
  void *data1 = lookup_match_entry( bob );
  assert_true( data1 != NULL );
  assert_string_equal( ( char * ) data1, BOB_MATCH_SERVICE_NAME );
  assert_true( data0 == data1 );

  oxm_matches *carol = create_oxm_matches();
  set_carol_match_entry( carol );
  oxm_matches *carol_wildcards = create_oxm_matches();
  set_carol_wildcards_entry( carol_wildcards );
  assert_true( insert_match_entry( carol_wildcards, DEFAULT_PRIORITY - 1, xstrdup( CAROL_MATCH_SERVICE_NAME ) ) );

  data0 = lookup_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY - 1 );
  assert_true( data0 != NULL );
  assert_string_equal( ( char * ) data0, CAROL_MATCH_SERVICE_NAME );
  data1 = lookup_match_entry( carol );
  assert_true( data1 != NULL );
  assert_string_equal( ( char * ) data1, CAROL_MATCH_SERVICE_NAME );
  assert_true( data0 == data1 );

  XFREE( delete_match_strict_entry( alice_wildcards, DEFAULT_PRIORITY ) );
  XFREE( delete_match_strict_entry( bob_wildcards, DEFAULT_PRIORITY + 1 ) );
  XFREE( delete_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY - 1 ) );

  delete_oxm_matches( alice_wildcards );
  delete_oxm_matches( bob );
  delete_oxm_matches( bob_wildcards );
  delete_oxm_matches( carol );
  delete_oxm_matches( carol_wildcards );
}


static void
test_insert_existing_same_priority_wildcards_entry_succeeds() {
  oxm_matches *alice = create_oxm_matches();
  set_alice_match_entry( alice );
  oxm_matches *alice_wildcards = create_oxm_matches();
  set_alice_wildcards_entry( alice_wildcards );
  assert_true( insert_match_entry( alice_wildcards, DEFAULT_PRIORITY, xstrdup( ALICE_MATCH_SERVICE_NAME ) ) );

  oxm_matches *bob = create_oxm_matches();
  set_bob_match_entry( bob );
  oxm_matches *bob_wildcards = create_oxm_matches();
  set_bob_wildcards_entry( bob_wildcards );
  assert_true( insert_match_entry( bob_wildcards, DEFAULT_PRIORITY, xstrdup( BOB_MATCH_SERVICE_NAME ) ) );

  void *data0 = lookup_match_strict_entry( bob_wildcards, DEFAULT_PRIORITY );
  assert_true( data0 != NULL );
  assert_string_equal( ( char * ) data0, BOB_MATCH_SERVICE_NAME );
  void *data1 = lookup_match_entry( bob );
  assert_true( data1 != NULL );
  assert_string_equal( ( char * ) data1, BOB_MATCH_SERVICE_NAME );
  assert_true( data0 == data1 );

  oxm_matches *any_wildcards = create_oxm_matches();
  set_any_wildcards_entry( any_wildcards );
  assert_true( insert_match_entry( any_wildcards, DEFAULT_PRIORITY, xstrdup( ANY_MATCH_SERVICE_NAME ) ) );

  oxm_matches *carol = create_oxm_matches();
  set_carol_match_entry( carol );
  oxm_matches *carol_wildcards = create_oxm_matches();
  set_carol_wildcards_entry( carol_wildcards );
  assert_true( insert_match_entry( carol_wildcards, DEFAULT_PRIORITY, xstrdup( CAROL_MATCH_SERVICE_NAME ) ) );

  data0 = lookup_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY );
  assert_true( data0 != NULL );
  assert_string_equal( ( char * ) data0, CAROL_MATCH_SERVICE_NAME );
  data1 = lookup_match_entry( carol );
  assert_true( data1 != NULL );
  assert_string_equal( ( char * ) data1, ANY_MATCH_SERVICE_NAME );
  assert_true( data0 != data1 );

  data1 = lookup_match_entry( alice );
  assert_true( data1 != NULL );
  assert_string_equal( ( char * ) data1, ALICE_MATCH_SERVICE_NAME );
  data1 = lookup_match_entry( bob );
  assert_true( data1 != NULL );
  assert_string_equal( ( char * ) data1, BOB_MATCH_SERVICE_NAME );

  XFREE( delete_match_strict_entry( alice_wildcards, DEFAULT_PRIORITY ) );
  XFREE( delete_match_strict_entry( bob_wildcards, DEFAULT_PRIORITY ) );
  XFREE( delete_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY ) );
  XFREE( delete_match_strict_entry( any_wildcards, DEFAULT_PRIORITY ) );

  delete_oxm_matches( alice );
  delete_oxm_matches( alice_wildcards );
  delete_oxm_matches( bob );
  delete_oxm_matches( bob_wildcards );
  delete_oxm_matches( carol );
  delete_oxm_matches( carol_wildcards );
  delete_oxm_matches( any_wildcards );
}


static void
test_insert_existing_same_match_same_priority_wildcards_entry_fails() {
  oxm_matches *carol = create_oxm_matches();
  set_carol_match_entry( carol );
  oxm_matches *carol_wildcards = create_oxm_matches();
  set_carol_wildcards_entry( carol_wildcards );
  assert_true( insert_match_entry( carol_wildcards, DEFAULT_PRIORITY, xstrdup( CAROL_MATCH_SERVICE_NAME ) ) );
  assert_true( !insert_match_entry( carol_wildcards, DEFAULT_PRIORITY, xstrdup( CAROL_MATCH_OTHER_SERVICE_NAME ) ) );

  void *data = lookup_match_entry( carol );
  assert_true( data != NULL );
  assert_string_equal( ( char * ) data, CAROL_MATCH_SERVICE_NAME );
  XFREE( delete_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY ) );

  delete_oxm_matches( carol );
  delete_oxm_matches( carol_wildcards );
}


static void
test_insert_different_priority_wildcards_entry_succeeds() {
  oxm_matches *carol = create_oxm_matches();
  set_carol_match_entry( carol );
  oxm_matches *carol_wildcards = create_oxm_matches();
  set_carol_wildcards_entry( carol_wildcards );
  assert_true( insert_match_entry( carol_wildcards, DEFAULT_PRIORITY, xstrdup( CAROL_MATCH_SERVICE_NAME ) ) );

  assert_true( insert_match_entry( carol_wildcards, DEFAULT_PRIORITY + 1, xstrdup( CAROL_MATCH_OTHER_SERVICE_NAME ) ) );

  void *data = lookup_match_entry( carol );
  assert_true( data != NULL );
  assert_string_equal( ( char * ) data, CAROL_MATCH_OTHER_SERVICE_NAME );
  XFREE( delete_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY ) );
  XFREE( delete_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY + 1 ) );

  delete_oxm_matches( carol );
  delete_oxm_matches( carol_wildcards );
}


static void
test_insert_highest_priority_wildcards_entry_succeeds() {
  oxm_matches *alice = create_oxm_matches();
  set_alice_match_entry( alice );
  oxm_matches *alice_wildcards = create_oxm_matches();
  set_alice_wildcards_entry( alice_wildcards );
  assert_true( insert_match_entry( alice_wildcards, DEFAULT_PRIORITY, xstrdup( ALICE_MATCH_SERVICE_NAME ) ) );

  oxm_matches *bob_wildcards = create_oxm_matches();
  set_bob_wildcards_entry( bob_wildcards );
  assert_true( insert_match_entry( bob_wildcards, HIGH_PRIORITY, xstrdup( BOB_MATCH_SERVICE_NAME ) ) );

  void *data0 = lookup_match_strict_entry( alice_wildcards, DEFAULT_PRIORITY );
  assert_true( data0 != NULL );
  assert_string_equal( ( char * ) data0, ALICE_MATCH_SERVICE_NAME );
  void *data1 = lookup_match_entry( alice );
  assert_true( data1 != NULL );
  assert_string_equal( ( char * ) data1, ALICE_MATCH_SERVICE_NAME );
  assert_true( data0 == data1 );

  oxm_matches *lldp_wildcards = create_oxm_matches();
  set_lldp_wildcards_entry( lldp_wildcards );
  assert_true( insert_match_entry( lldp_wildcards, HIGH_PRIORITY, xstrdup( LLDP_MATCH_SERVICE_NAME ) ) );

  data0 = lookup_match_strict_entry( alice_wildcards, DEFAULT_PRIORITY );
  assert_true( data0 != NULL );
  assert_string_equal( ( char * ) data0, ALICE_MATCH_SERVICE_NAME );
  data1 = lookup_match_entry( alice );
  assert_true( data1 != NULL );
  assert_string_equal( ( char * ) data1, ALICE_MATCH_SERVICE_NAME );
  assert_true( data0 == data1 );

  oxm_matches *any_wildcards = create_oxm_matches();
  set_any_wildcards_entry( any_wildcards );
  assert_true( insert_match_entry( any_wildcards, HIGH_PRIORITY, xstrdup( ANY_MATCH_SERVICE_NAME ) ) );

  data0 = lookup_match_strict_entry( alice_wildcards, DEFAULT_PRIORITY );
  assert_true( data0 != NULL );
  assert_string_equal( ( char * ) data0, ALICE_MATCH_SERVICE_NAME );
  data1 = lookup_match_entry( alice );
  assert_true( data1 != NULL );
  assert_string_equal( ( char * ) data1, ANY_MATCH_SERVICE_NAME );
  assert_true( data0 != data1 );

  XFREE( delete_match_strict_entry( alice_wildcards, DEFAULT_PRIORITY ) );
  XFREE( delete_match_strict_entry( bob_wildcards, HIGH_PRIORITY ) );
  XFREE( delete_match_strict_entry( lldp_wildcards, HIGH_PRIORITY ) );
  XFREE( delete_match_strict_entry( any_wildcards, HIGH_PRIORITY ) );

  delete_oxm_matches( alice );
  delete_oxm_matches( alice_wildcards );
  delete_oxm_matches( bob_wildcards );
  delete_oxm_matches( lldp_wildcards );
  delete_oxm_matches( any_wildcards );
}


static void
test_insert_lowest_priority_wildcards_entry_succeeds() {
  oxm_matches *alice = create_oxm_matches();
  set_alice_match_entry( alice );
  oxm_matches *alice_wildcards = create_oxm_matches();
  set_alice_wildcards_entry( alice_wildcards );
  assert_true( insert_match_entry( alice_wildcards, DEFAULT_PRIORITY, xstrdup( ALICE_MATCH_SERVICE_NAME ) ) );

  oxm_matches *bob_wildcards = create_oxm_matches();
  set_bob_wildcards_entry( bob_wildcards );
  assert_true( insert_match_entry( bob_wildcards, LOW_PRIORITY, xstrdup( BOB_MATCH_SERVICE_NAME ) ) );

  void *data0 = lookup_match_strict_entry( alice_wildcards, DEFAULT_PRIORITY );
  assert_true( data0 != NULL );
  assert_string_equal( ( char * ) data0, ALICE_MATCH_SERVICE_NAME );
  void *data1 = lookup_match_entry( alice );
  assert_true( data1 != NULL );
  assert_string_equal( ( char * ) data1, ALICE_MATCH_SERVICE_NAME );
  assert_true( data0 == data1 );

  oxm_matches *lldp_wildcards = create_oxm_matches();
  set_lldp_wildcards_entry( lldp_wildcards );
  assert_true( insert_match_entry( lldp_wildcards, LOW_PRIORITY, xstrdup( LLDP_MATCH_SERVICE_NAME ) ) );

  data0 = lookup_match_strict_entry( alice_wildcards, DEFAULT_PRIORITY );
  assert_true( data0 != NULL );
  assert_string_equal( ( char * ) data0, ALICE_MATCH_SERVICE_NAME );
  data1 = lookup_match_entry( alice );
  assert_true( data1 != NULL );
  assert_string_equal( ( char * ) data1, ALICE_MATCH_SERVICE_NAME );
  assert_true( data0 == data1 );

  oxm_matches *any_wildcards = create_oxm_matches();
  set_any_wildcards_entry( any_wildcards );
  assert_true( insert_match_entry( any_wildcards, LOW_PRIORITY, xstrdup( ANY_MATCH_SERVICE_NAME ) ) );

  data0 = lookup_match_strict_entry( alice_wildcards, DEFAULT_PRIORITY );
  assert_true( data0 != NULL );
  assert_string_equal( ( char * ) data0, ALICE_MATCH_SERVICE_NAME );
  data1 = lookup_match_entry( alice );
  assert_true( data1 != NULL );
  assert_string_equal( ( char * ) data1, ALICE_MATCH_SERVICE_NAME );
  assert_true( data0 == data1 );

  XFREE( delete_match_strict_entry( alice_wildcards, DEFAULT_PRIORITY ) );
  XFREE( delete_match_strict_entry( bob_wildcards, LOW_PRIORITY ) );
  XFREE( delete_match_strict_entry( lldp_wildcards, LOW_PRIORITY ) );
  XFREE( delete_match_strict_entry( any_wildcards, LOW_PRIORITY ) );

  delete_oxm_matches( alice );
  delete_oxm_matches( alice_wildcards );
  delete_oxm_matches( bob_wildcards );
  delete_oxm_matches( lldp_wildcards );
  delete_oxm_matches( any_wildcards );
}


static void
test_reinsert_of_deleted_wildcards_entry_succeeds() {
  oxm_matches *carol = create_oxm_matches();
  set_carol_match_entry( carol );
  oxm_matches *carol_wildcards = create_oxm_matches();
  set_carol_wildcards_entry( carol_wildcards );
  assert_true( insert_match_entry( carol_wildcards, DEFAULT_PRIORITY, xstrdup( CAROL_MATCH_SERVICE_NAME ) ) );
  XFREE( delete_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY ) );
  void *data = lookup_match_strict_entry( carol, DEFAULT_PRIORITY );
  assert_true( data == NULL );
  data = lookup_match_entry( carol );
  assert_true( data == NULL );
  assert_true( insert_match_entry( carol_wildcards, DEFAULT_PRIORITY, xstrdup( CAROL_MATCH_OTHER_SERVICE_NAME ) ) );

  data = lookup_match_entry( carol );
  assert_true( data != NULL );
  assert_string_equal( ( char * ) data, CAROL_MATCH_OTHER_SERVICE_NAME );
  XFREE( delete_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY ) );

  delete_oxm_matches( carol );
  delete_oxm_matches( carol_wildcards );
}


static void
test_reinsert_of_deleted_highest_priority_wildcards_entry_succeeds() {
  oxm_matches *carol = create_oxm_matches();
  set_carol_match_entry( carol );
  oxm_matches *carol_wildcards = create_oxm_matches();
  set_carol_wildcards_entry( carol_wildcards );
  assert_true( insert_match_entry( carol_wildcards, HIGH_PRIORITY, xstrdup( CAROL_MATCH_SERVICE_NAME ) ) );
  XFREE( delete_match_strict_entry( carol_wildcards, HIGH_PRIORITY ) );
  void *data = lookup_match_strict_entry( carol, HIGH_PRIORITY );
  assert_true( data == NULL );
  data = lookup_match_entry( carol );
  assert_true( data == NULL );
  assert_true( insert_match_entry( carol_wildcards, HIGH_PRIORITY, xstrdup( CAROL_MATCH_OTHER_SERVICE_NAME ) ) );

  data = lookup_match_entry( carol );
  assert_true( data != NULL );
  assert_string_equal( ( char * ) data, CAROL_MATCH_OTHER_SERVICE_NAME );
  XFREE( delete_match_strict_entry( carol_wildcards, HIGH_PRIORITY ) );

  delete_oxm_matches( carol );
  delete_oxm_matches( carol_wildcards );
}


static void
test_reinsert_of_deleted_lowhest_priority_wildcards_entry_succeeds() {
  oxm_matches *carol = create_oxm_matches();
  set_carol_match_entry( carol );
  oxm_matches *carol_wildcards = create_oxm_matches();
  set_carol_wildcards_entry( carol_wildcards );
  assert_true( insert_match_entry( carol_wildcards, LOW_PRIORITY, xstrdup( CAROL_MATCH_SERVICE_NAME ) ) );
  XFREE( delete_match_strict_entry( carol_wildcards, LOW_PRIORITY ) );
  void *data = lookup_match_strict_entry( carol, LOW_PRIORITY );
  assert_true( data == NULL );
  data = lookup_match_entry( carol );
  assert_true( data == NULL );
  assert_true( insert_match_entry( carol_wildcards, LOW_PRIORITY, xstrdup( CAROL_MATCH_OTHER_SERVICE_NAME ) ) );

  data = lookup_match_entry( carol );
  assert_true( data != NULL );
  assert_string_equal( ( char * ) data, CAROL_MATCH_OTHER_SERVICE_NAME );
  XFREE( delete_match_strict_entry( carol_wildcards, LOW_PRIORITY ) );

  delete_oxm_matches( carol );
  delete_oxm_matches( carol_wildcards );
}


/*************************************************************************
 * update, lookup and delete entry tests.
 *************************************************************************/

// update, lookup and delete wildcards entry tests.

static void
test_update_exact_wildcards_succeeds() {
  oxm_matches *carol = create_oxm_matches();
  set_carol_match_entry( carol );
  oxm_matches *carol_wildcards = create_oxm_matches();
  set_carol_wildcards_entry( carol_wildcards );
  assert_true( insert_match_entry( carol_wildcards, DEFAULT_PRIORITY, xstrdup( CAROL_MATCH_SERVICE_NAME ) ) );
  void *data = lookup_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY );
  assert_true( data != NULL );
  assert_string_equal( ( char * ) data, CAROL_MATCH_SERVICE_NAME );
  data = lookup_match_entry( carol );
  assert_true( data != NULL );
  assert_string_equal( ( char * ) data, CAROL_MATCH_SERVICE_NAME );

  assert_true( update_match_entry( carol_wildcards, DEFAULT_PRIORITY, xstrdup( CAROL_MATCH_OTHER_SERVICE_NAME ) ) );

  data = lookup_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY );
  assert_true( data != NULL );
  assert_string_equal( ( char * ) data, CAROL_MATCH_OTHER_SERVICE_NAME );
  data = lookup_match_entry( carol );
  assert_true( data != NULL );
  assert_string_equal( ( char * ) data, CAROL_MATCH_OTHER_SERVICE_NAME );

  assert_true( update_match_entry( carol_wildcards, DEFAULT_PRIORITY, xstrdup( CAROL_MATCH_SERVICE_NAME ) ) );

  data = lookup_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY );
  assert_true( data != NULL );
  assert_string_equal( ( char * ) data, CAROL_MATCH_SERVICE_NAME );
  data = lookup_match_entry( carol );
  assert_true( data != NULL );
  assert_string_equal( ( char * ) data, CAROL_MATCH_SERVICE_NAME );

  XFREE( delete_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY ) );

  delete_oxm_matches( carol );
  delete_oxm_matches( carol_wildcards );
}


static void
test_update_nonexistent_wildcards_entry_fails() {
  oxm_matches *carol = create_oxm_matches();
  set_carol_match_entry( carol );
  oxm_matches *carol_wildcards = create_oxm_matches();
  set_carol_wildcards_entry( carol_wildcards );
  assert_true( !update_match_entry( carol_wildcards, DEFAULT_PRIORITY, xstrdup( CAROL_MATCH_OTHER_SERVICE_NAME ) ) );

  oxm_matches *alice_wildcards = create_oxm_matches();
  set_alice_match_entry( alice_wildcards );
  assert_true( insert_match_entry( alice_wildcards, DEFAULT_PRIORITY, xstrdup( ALICE_MATCH_SERVICE_NAME ) ) );

  assert_true( !update_match_entry( carol_wildcards, DEFAULT_PRIORITY, xstrdup( CAROL_MATCH_OTHER_SERVICE_NAME ) ) );

  void *data = lookup_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY );
  assert_true( data == NULL );
  data = lookup_match_entry( carol );
  assert_true( data == NULL );

  XFREE( delete_match_strict_entry( alice_wildcards, DEFAULT_PRIORITY ) );

  delete_oxm_matches( carol );
  delete_oxm_matches( carol_wildcards );
  delete_oxm_matches( alice_wildcards );
}


static void
test_update_of_deleted_wildcards_entry_fails() {
  oxm_matches *carol = create_oxm_matches();
  set_carol_match_entry( carol );
  oxm_matches *carol_wildcards = create_oxm_matches();
  set_carol_wildcards_entry( carol_wildcards );
  assert_true( insert_match_entry( carol_wildcards, DEFAULT_PRIORITY, xstrdup( CAROL_MATCH_SERVICE_NAME ) ) );
  XFREE( delete_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY ) );

  assert_true( !update_match_entry( carol_wildcards, DEFAULT_PRIORITY, xstrdup( CAROL_MATCH_OTHER_SERVICE_NAME ) ) );

  void *data = lookup_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY );
  assert_true( data == NULL );
  data = lookup_match_entry( carol );
  assert_true( data == NULL );

  delete_oxm_matches( carol );
  delete_oxm_matches( carol_wildcards );
}


static void
test_update_different_priority_wildcards_entry_fails() {
  oxm_matches *carol = create_oxm_matches();
  set_carol_match_entry( carol );
  oxm_matches *carol_wildcards = create_oxm_matches();
  set_carol_wildcards_entry( carol_wildcards );
  assert_true( insert_match_entry( carol_wildcards, DEFAULT_PRIORITY, xstrdup( CAROL_MATCH_SERVICE_NAME ) ) );

  assert_true( !update_match_entry( carol_wildcards, DEFAULT_PRIORITY + 1, xstrdup( CAROL_MATCH_OTHER_SERVICE_NAME ) ) );

  XFREE( delete_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY ) );

  delete_oxm_matches( carol );
  delete_oxm_matches( carol_wildcards );}


/*************************************************************************
 * delete entry tests.
 *************************************************************************/

// delete wildcards entry tests.

static void
test_delete_nonexistent_wildcards_entry_fails() {
  oxm_matches *carol = create_oxm_matches();
  set_carol_match_entry( carol );
  oxm_matches *carol_wildcards = create_oxm_matches();
  set_carol_wildcards_entry( carol_wildcards );
  assert_true( delete_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY ) == NULL );

  oxm_matches *alice_wildcards = create_oxm_matches();
  set_alice_match_entry( alice_wildcards );
  assert_true( insert_match_entry( alice_wildcards, DEFAULT_PRIORITY, xstrdup( ALICE_MATCH_SERVICE_NAME ) ) );

  assert_true( delete_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY ) == NULL );

  XFREE( delete_match_strict_entry( alice_wildcards, DEFAULT_PRIORITY ) );

  delete_oxm_matches( carol );
  delete_oxm_matches( carol_wildcards );
  delete_oxm_matches( alice_wildcards );
}


static void
test_delete_of_deleted_wildcards_entry_fails() {
  oxm_matches *carol = create_oxm_matches();
  set_carol_match_entry( carol );
  oxm_matches *carol_wildcards = create_oxm_matches();
  set_carol_wildcards_entry( carol_wildcards );
  assert_true( insert_match_entry( carol_wildcards, DEFAULT_PRIORITY, xstrdup( CAROL_MATCH_SERVICE_NAME ) ) );
  XFREE( delete_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY ) );

  assert_true( delete_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY ) == NULL );

  delete_oxm_matches( carol );
  delete_oxm_matches( carol_wildcards );
}


static void
test_delete_different_priority_wildcards_entry_fails() {
  oxm_matches *carol = create_oxm_matches();
  set_carol_match_entry( carol );
  oxm_matches *carol_wildcards = create_oxm_matches();
  set_carol_wildcards_entry( carol_wildcards );
  assert_true( insert_match_entry( carol_wildcards, DEFAULT_PRIORITY, xstrdup( CAROL_MATCH_SERVICE_NAME ) ) );

  assert_true( delete_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY + 1 ) == NULL );

  XFREE( delete_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY ) );

  delete_oxm_matches( carol );
  delete_oxm_matches( carol_wildcards );
}


/*************************************************************************
 * foreach entry tests.
 *************************************************************************/

static void
test_foreach_match_entry_dies_if_function_is_null() {
  expect_assert_failure( foreach_match_table( NULL, NULL ) );
}


static void
test_foreach_entry_if_empty_table_helper( oxm_matches *match, uint16_t priority, void *data, void *user_data ) {
  UNUSED( match );
  UNUSED( priority );
  UNUSED( data );
  UNUSED( user_data );
  assert_true( false );
}


static void
test_foreach_entry_if_empty_table() {
  foreach_match_table( test_foreach_entry_if_empty_table_helper, NULL );
}


static int count = 0;


static void
add_all_exact_entry() {
  oxm_matches *alice = create_oxm_matches();
  set_alice_match_entry( alice );
  assert_true( insert_match_entry( alice, HIGH_PRIORITY, xstrdup( ALICE_MATCH_SERVICE_NAME ) ) );
  oxm_matches *bob = create_oxm_matches();
  set_bob_match_entry( bob );
  assert_true( insert_match_entry( bob, HIGH_PRIORITY, xstrdup( BOB_MATCH_SERVICE_NAME ) ) );
  oxm_matches *carol = create_oxm_matches();
  set_carol_match_entry( carol );
  assert_true( insert_match_entry( carol, HIGH_PRIORITY, xstrdup( CAROL_MATCH_SERVICE_NAME ) ) );
  assert_true( update_match_entry( carol, HIGH_PRIORITY, xstrdup( CAROL_MATCH_OTHER_SERVICE_NAME ) ) );

  delete_oxm_matches( alice );
  delete_oxm_matches( bob );
  delete_oxm_matches( carol );
}


static void
test_foreach_entry_if_wildcards_table_only_helper( oxm_matches *match, uint16_t priority, void *data, void *user_data ) {
  oxm_matches *alice_wildcards = create_oxm_matches();
  set_alice_wildcards_entry( alice_wildcards );
  oxm_matches *bob_wildcards = create_oxm_matches();
  set_bob_wildcards_entry( bob_wildcards );
  oxm_matches *carol_wildcards = create_oxm_matches();
  set_carol_wildcards_entry( carol_wildcards );
  oxm_matches *any_wildcards = create_oxm_matches();
  set_any_wildcards_entry( any_wildcards );
  oxm_matches *lldp_wildcards = create_oxm_matches();
  set_lldp_wildcards_entry( lldp_wildcards );


  switch ( ++count ) {
    case 2:
      assert_string_equal( ( char * ) data, ALICE_MATCH_SERVICE_NAME );
      assert_true( priority == DEFAULT_PRIORITY );
      assert_true( compare_oxm_match_strict( match, alice_wildcards ) );
      break;
    case 3:
      assert_string_equal( ( char * ) data, BOB_MATCH_SERVICE_NAME );
      assert_true( priority == DEFAULT_PRIORITY );
      assert_true( compare_oxm_match_strict( match, bob_wildcards ) );
      break;
    case 4:
      assert_string_equal( ( char * ) data, CAROL_MATCH_OTHER_SERVICE_NAME );
      assert_true( priority == DEFAULT_PRIORITY );
      assert_true( compare_oxm_match_strict( match, carol_wildcards ) );
      break;
    case 5:
      assert_string_equal( ( char * ) data, ANY_MATCH_SERVICE_NAME );
      assert_true( priority == LOW_PRIORITY );
      assert_true( compare_oxm_match_strict( match, any_wildcards ) );
      break;
    case 1:
      assert_string_equal( ( char * ) data, LLDP_MATCH_SERVICE_NAME );
      assert_true( priority == HIGH_PRIORITY );
      assert_true( compare_oxm_match_strict( match, lldp_wildcards ) );
      break;
    default:
      assert_true( false );
      break;
  }
  assert_string_equal( ( char * ) user_data, USER_DATA );

  delete_oxm_matches( alice_wildcards );
  delete_oxm_matches( bob_wildcards );
  delete_oxm_matches( carol_wildcards );
  delete_oxm_matches( any_wildcards );
  delete_oxm_matches( lldp_wildcards );
}


static void
add_all_wildcards_entry() {
  oxm_matches *alice_wildcards = create_oxm_matches();
  set_alice_wildcards_entry( alice_wildcards );
  assert_true( insert_match_entry( alice_wildcards, DEFAULT_PRIORITY, xstrdup( ALICE_MATCH_SERVICE_NAME ) ) );
  oxm_matches *bob_wildcards = create_oxm_matches();
  set_bob_wildcards_entry( bob_wildcards );
  assert_true( insert_match_entry( bob_wildcards, DEFAULT_PRIORITY, xstrdup( BOB_MATCH_SERVICE_NAME ) ) );
  oxm_matches *carol_wildcards = create_oxm_matches();
  set_carol_wildcards_entry( carol_wildcards );
  assert_true( insert_match_entry( carol_wildcards, DEFAULT_PRIORITY, xstrdup( CAROL_MATCH_SERVICE_NAME ) ) );
  oxm_matches *any_wildcards = create_oxm_matches();
  set_any_wildcards_entry( any_wildcards );
  assert_true( insert_match_entry( any_wildcards, LOW_PRIORITY, xstrdup( ANY_MATCH_SERVICE_NAME ) ) );
  oxm_matches *lldp_wildcards = create_oxm_matches();
  set_lldp_wildcards_entry( lldp_wildcards );
  assert_true( insert_match_entry( lldp_wildcards, HIGH_PRIORITY, xstrdup( LLDP_MATCH_SERVICE_NAME ) ) );
  assert_true( update_match_entry( carol_wildcards, DEFAULT_PRIORITY, xstrdup( CAROL_MATCH_OTHER_SERVICE_NAME ) ) );

  delete_oxm_matches( alice_wildcards );
  delete_oxm_matches( bob_wildcards );
  delete_oxm_matches( carol_wildcards );
  delete_oxm_matches( any_wildcards );
  delete_oxm_matches( lldp_wildcards );
}


static void
delete_all_wildcards_entry() {
  oxm_matches *alice_wildcards = create_oxm_matches();
  set_alice_wildcards_entry( alice_wildcards );
  XFREE( delete_match_strict_entry( alice_wildcards, DEFAULT_PRIORITY ) );
  oxm_matches *bob_wildcards = create_oxm_matches();
  set_bob_wildcards_entry( bob_wildcards );
  XFREE( delete_match_strict_entry( bob_wildcards, DEFAULT_PRIORITY ) );
  oxm_matches *carol_wildcards = create_oxm_matches();
  set_carol_wildcards_entry( carol_wildcards );
  XFREE( delete_match_strict_entry( carol_wildcards, DEFAULT_PRIORITY ) );
  oxm_matches *any_wildcards = create_oxm_matches();
  set_any_wildcards_entry( any_wildcards );
  XFREE( delete_match_strict_entry( any_wildcards, LOW_PRIORITY ) );
  oxm_matches *lldp_wildcards = create_oxm_matches();
  set_lldp_wildcards_entry( lldp_wildcards );
  XFREE( delete_match_strict_entry( lldp_wildcards, HIGH_PRIORITY ) );

  delete_oxm_matches( alice_wildcards );
  delete_oxm_matches( bob_wildcards );
  delete_oxm_matches( carol_wildcards );
  delete_oxm_matches( any_wildcards );
  delete_oxm_matches( lldp_wildcards );
}


static void
test_foreach_entry_if_wildcards_table_only() {
  add_all_wildcards_entry();

  char *user_data = xstrdup( USER_DATA );
  count = 0;
  foreach_match_table( test_foreach_entry_if_wildcards_table_only_helper, user_data );
  assert_int_equal( count, 5 );

  delete_all_wildcards_entry();
  XFREE( user_data );
}


static void
test_foreach_entry_helper( oxm_matches *match, uint16_t priority, void *data, void *user_data ) {
  oxm_matches *alice = create_oxm_matches();
  set_alice_match_entry( alice );
  oxm_matches *bob = create_oxm_matches();
  set_bob_match_entry( bob );
  oxm_matches *carol = create_oxm_matches();
  set_carol_match_entry( carol );

  oxm_matches *alice_wildcards = create_oxm_matches();
  set_alice_wildcards_entry( alice_wildcards );
  oxm_matches *bob_wildcards = create_oxm_matches();
  set_bob_wildcards_entry( bob_wildcards );
  oxm_matches *carol_wildcards = create_oxm_matches();
  set_carol_wildcards_entry( carol_wildcards );
  oxm_matches *any_wildcards = create_oxm_matches();
  set_any_wildcards_entry( any_wildcards );
  oxm_matches *lldp_wildcards = create_oxm_matches();
  set_lldp_wildcards_entry( lldp_wildcards );


  switch ( ++count ) {
    case 1:
      assert_string_equal( ( char * ) data, ALICE_MATCH_SERVICE_NAME );
      assert_true( priority == HIGH_PRIORITY );
      assert_true( compare_oxm_match_strict( match, alice ) );
      XFREE( data );
      break;
    case 2:
      assert_string_equal( ( char * ) data, BOB_MATCH_SERVICE_NAME );
      assert_true( priority == HIGH_PRIORITY );
      assert_true( compare_oxm_match_strict( match, bob ) );
      XFREE( data );
      break;
    case 3:
      assert_string_equal( ( char * ) data, CAROL_MATCH_OTHER_SERVICE_NAME );
      assert_true( priority == HIGH_PRIORITY );
      assert_true( compare_oxm_match_strict( match, carol ) );
      XFREE( data );
      break;
    case 5:
      assert_string_equal( ( char * ) data, ALICE_MATCH_SERVICE_NAME );
      assert_true( priority == DEFAULT_PRIORITY );
      assert_true( compare_oxm_match_strict( match, alice_wildcards ) );
      XFREE( data );
      break;
    case 6:
      assert_string_equal( ( char * ) data, BOB_MATCH_SERVICE_NAME );
      assert_true( priority == DEFAULT_PRIORITY );
      assert_true( compare_oxm_match_strict( match, bob_wildcards ) );
      XFREE( data );
      break;
    case 7:
      assert_string_equal( ( char * ) data, CAROL_MATCH_OTHER_SERVICE_NAME );
      assert_true( priority == DEFAULT_PRIORITY );
      assert_true( compare_oxm_match_strict( match, carol_wildcards ) );
      XFREE( data );
      break;
    case 8:
      assert_string_equal( ( char * ) data, ANY_MATCH_SERVICE_NAME );
      assert_true( priority == LOW_PRIORITY );
      assert_true( compare_oxm_match_strict( match, any_wildcards ) );
      XFREE( data );
      break;
    case 4:
      assert_string_equal( ( char * ) data, LLDP_MATCH_SERVICE_NAME );
      assert_true( priority == HIGH_PRIORITY );
      assert_true( compare_oxm_match_strict( match, lldp_wildcards ) );
      XFREE( data );
      break;
    default:
      assert_true( false );
      break;
  }
  assert_string_equal( ( char * ) user_data, USER_DATA );

  delete_oxm_matches( alice );
  delete_oxm_matches( bob );
  delete_oxm_matches( carol );
  delete_oxm_matches( alice_wildcards );
  delete_oxm_matches( bob_wildcards );
  delete_oxm_matches( carol_wildcards );
  delete_oxm_matches( any_wildcards );
  delete_oxm_matches( lldp_wildcards );
}


static void
test_foreach_entry() {
  add_all_exact_entry();
  add_all_wildcards_entry();

  char *user_data = xstrdup( USER_DATA );
  count = 0;
  foreach_match_table( test_foreach_entry_helper, user_data );
  assert_int_equal( count, 8 );

  XFREE( user_data );
}


static void
test_map_entry_if_match_set_nw_src_helper( oxm_matches *match, uint16_t priority, void *data, void *user_data ) {
  oxm_matches *alice = create_oxm_matches();
  set_alice_match_entry( alice );

  oxm_matches *alice_wildcards = create_oxm_matches();
  set_alice_wildcards_entry( alice_wildcards );


  switch ( ++count ) {
    case 1:
      assert_string_equal( ( char * ) data, ALICE_MATCH_SERVICE_NAME );
      assert_true( priority == HIGH_PRIORITY );
      assert_true( compare_oxm_match_strict( match, alice ) );
      XFREE( data );
      break;
    case 2:
      assert_string_equal( ( char * ) data, ALICE_MATCH_SERVICE_NAME );
      assert_true( priority == DEFAULT_PRIORITY );
      assert_true( compare_oxm_match_strict( match, alice_wildcards ) );
      XFREE( data );
      break;
    default:
      assert_true( false );
      break;
  }
  assert_string_equal( ( char * ) user_data, USER_DATA );

  delete_oxm_matches( alice );
  delete_oxm_matches( alice_wildcards );
}


static void
test_map_entry_if_match_set_nw_src() {
  add_all_exact_entry();
  add_all_wildcards_entry();

  oxm_matches *match = create_oxm_matches();
  append_oxm_match_eth_type( match, ETHERTYPE_IP );
  append_oxm_match_ipv4_src( match, 0x0a000101, 0 );
  char *user_data = xstrdup( USER_DATA );
  count = 0;
  map_match_table( match, test_map_entry_if_match_set_nw_src_helper, user_data );
  assert_int_equal( count, 2 );

  XFREE( user_data );

  delete_oxm_matches( match );
}


static void
set_nw_src_prefix_20_wildcards_entry( oxm_matches *match ) {
  append_oxm_match_eth_type( match, ETHERTYPE_IP );
  append_oxm_match_ipv4_src( match, 0x0a000200, 0xfffff000 );
  append_oxm_match_ipv4_dst( match, 0x0a000100, 0xfffffff0 );
}


static void
set_nw_dst_prefix_20_wildcards_entry( oxm_matches *match ) {
  append_oxm_match_eth_type( match, ETHERTYPE_IP );
  append_oxm_match_ipv4_src( match, 0x0a000200, 0xfffffff0 );
  append_oxm_match_ipv4_dst( match, 0x0a000100, 0xfffff000 );
}


static void
set_nw_prefix_24_wildcards_entry( oxm_matches *match ) {
  append_oxm_match_eth_type( match, ETHERTYPE_IP );
  append_oxm_match_ipv4_src( match, 0x0a000200, 0xffffff00 );
  append_oxm_match_ipv4_dst( match, 0x0a000100, 0xffffff00 );
}


static void
set_nw_prefix_28_wildcards_entry( oxm_matches *match ) {
  append_oxm_match_eth_type( match, ETHERTYPE_IP );
  append_oxm_match_ipv4_src( match, 0x0a000200, 0xfffffff0 );
  append_oxm_match_ipv4_dst( match, 0x0a000100, 0xfffffff0 );
}



#define NW_SRC_PREFIX_20_SERVICE_NAME "nw_src_prefix-20"
#define NW_DST_PREFIX_20_SERVICE_NAME "nw_dst_prefix-20"
#define NW_PREFIX_24_SERVICE_NAME "nw_prefix-24"
#define NW_PREFIX_28_SERVICE_NAME "nw_prefix-28"


static void
test_map_entry_if_match_set_nw_prefix_helper( oxm_matches *match, uint16_t priority, void *data, void *user_data ) {
  oxm_matches *nw_prefix_24 = create_oxm_matches();
  set_nw_prefix_24_wildcards_entry( nw_prefix_24 );
  oxm_matches *nw_prefix_28 = create_oxm_matches();
  set_nw_prefix_28_wildcards_entry( nw_prefix_28 );


  switch ( ++count ) {
    case 1:
      assert_string_equal( ( char * ) data, NW_PREFIX_24_SERVICE_NAME );
      assert_true( priority == DEFAULT_PRIORITY );
      assert_true( compare_oxm_match_strict( match, nw_prefix_24 ) );
      XFREE( data );
      break;
    case 2:
      assert_string_equal( ( char * ) data, NW_PREFIX_28_SERVICE_NAME );
      assert_true( priority == DEFAULT_PRIORITY );
      assert_true( compare_oxm_match_strict( match, nw_prefix_28 ) );
      XFREE( data );
      break;
    default:
      assert_true( false );
      break;
  }
  assert_string_equal( ( char * ) user_data, USER_DATA );

  delete_oxm_matches( nw_prefix_24 );
  delete_oxm_matches( nw_prefix_28 );
}


static void
test_map_entry_if_match_set_nw_prefix() {
  oxm_matches *nw_src_prefix_20 = create_oxm_matches();
  set_nw_src_prefix_20_wildcards_entry( nw_src_prefix_20 );
  assert_true( insert_match_entry( nw_src_prefix_20, DEFAULT_PRIORITY, xstrdup( NW_SRC_PREFIX_20_SERVICE_NAME ) ) );
  oxm_matches *nw_dst_prefix_20 = create_oxm_matches();
  set_nw_dst_prefix_20_wildcards_entry( nw_dst_prefix_20 );
  assert_true( insert_match_entry( nw_dst_prefix_20, DEFAULT_PRIORITY, xstrdup( NW_DST_PREFIX_20_SERVICE_NAME ) ) );
  oxm_matches *nw_prefix_24 = create_oxm_matches();
  set_nw_prefix_24_wildcards_entry( nw_prefix_24 );
  assert_true( insert_match_entry( nw_prefix_24, DEFAULT_PRIORITY, xstrdup( NW_PREFIX_24_SERVICE_NAME ) ) );
  oxm_matches *nw_prefix_28 = create_oxm_matches();
  set_nw_prefix_28_wildcards_entry( nw_prefix_28 );
  assert_true( insert_match_entry( nw_prefix_28, DEFAULT_PRIORITY, xstrdup( NW_PREFIX_28_SERVICE_NAME ) ) );

  oxm_matches *match = create_oxm_matches();
  set_nw_prefix_24_wildcards_entry( match );
  char *user_data = xstrdup( USER_DATA );
  count = 0;
  map_match_table( match, test_map_entry_if_match_set_nw_prefix_helper, user_data );
  assert_int_equal( count, 2 );

  XFREE( user_data );

  delete_oxm_matches( nw_src_prefix_20 );
  delete_oxm_matches( nw_dst_prefix_20 );
  delete_oxm_matches( nw_prefix_24 );
  delete_oxm_matches( nw_prefix_28 );
  delete_oxm_matches( match );
}


/*************************************************************************
 * Run tests.
 *************************************************************************/

int
main() {
  const UnitTest tests[] = {
    // init and finalize tests.
    unit_test_setup_teardown( test_init_and_finalize_match_table_succeeds, setup, teardown ),
    unit_test_setup_teardown( test_init_match_table_dies_if_already_initialized, setup, teardown ),
    unit_test_setup_teardown( test_finalize_match_table_dies_if_not_initialized, setup, teardown ),
    unit_test_setup_teardown( test_insert_match_entry_dies_if_not_initialized, setup, teardown ),
    unit_test_setup_teardown( test_lookup_match_strict_entry_dies_if_not_initialized, setup, teardown ),
    unit_test_setup_teardown( test_lookup_match_entry_dies_if_not_initialized, setup, teardown ),
    unit_test_setup_teardown( test_update_match_entry_dies_if_not_initialized, setup, teardown ),
    unit_test_setup_teardown( test_delete_match_strict_entry_dies_if_not_initialized, setup, teardown ),
    unit_test_setup_teardown( test_foreach_match_entry_dies_if_not_initialized, setup, teardown ),

    // insert tests.
    unit_test_setup_teardown( test_insert_wildcards_entry_into_empty_table_succeeds, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_insert_wildcards_entry_into_not_empty_exact_table_succeeds, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_insert_existing_same_priority_wildcards_entry_succeeds, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_insert_existing_same_match_same_priority_wildcards_entry_fails, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_insert_different_priority_wildcards_entry_succeeds, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_insert_highest_priority_wildcards_entry_succeeds, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_insert_lowest_priority_wildcards_entry_succeeds, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_reinsert_of_deleted_wildcards_entry_succeeds, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_reinsert_of_deleted_highest_priority_wildcards_entry_succeeds, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_reinsert_of_deleted_lowhest_priority_wildcards_entry_succeeds, setup_and_init, finalize_and_teardown ),

    // update tests.
    unit_test_setup_teardown( test_update_exact_wildcards_succeeds, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_update_nonexistent_wildcards_entry_fails, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_update_of_deleted_wildcards_entry_fails, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_update_different_priority_wildcards_entry_fails, setup_and_init, finalize_and_teardown ),

    // delete tests.
    unit_test_setup_teardown( test_delete_nonexistent_wildcards_entry_fails, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_delete_of_deleted_wildcards_entry_fails, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_delete_different_priority_wildcards_entry_fails, setup_and_init, finalize_and_teardown ),

    // foreach tests.
    unit_test_setup_teardown( test_foreach_match_entry_dies_if_function_is_null, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_foreach_entry_if_empty_table, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_foreach_entry_if_wildcards_table_only, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_foreach_entry, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_map_entry_if_match_set_nw_src, setup_and_init, finalize_and_teardown ),
    unit_test_setup_teardown( test_map_entry_if_match_set_nw_prefix, setup_and_init, finalize_and_teardown ),
  };

  return run_tests( tests );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
