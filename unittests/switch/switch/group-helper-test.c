/*
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


#include <stdio.h>
#include <string.h>
#include "trema.h"
#include "ofdp.h"
#include "group-helper.h"
#include "mocks.h"
#include "cmockery_trema.h"


#define DATAPATH_ID 0xabc
#define MY_TRANSACTION_ID 0x11223344
#define GROUP_ID 1
#define INVALID_GROUP_ID 3333
#define WATCH_GROUP_1 0xaa
#define WATCH_GROUP_2 0xbb
#define DEV_PORT_1 "trema1-0"
#define DEV_PORT_2 "trema2-0"
#define WATCH_PORT_1 1
#define WATCH_PORT_2 2
#define WEIGHT_1 123
#define WEIGHT_2 456


static void
test_create_group_mod( void **state ) {
  list_element *buckets_head;

  create_list( &buckets_head );
  size_t total_len = sizeof( struct ofp_bucket ) + sizeof( struct ofp_action_output ) ;
  struct ofp_bucket *bucket = ( struct ofp_bucket * ) ( xmalloc( total_len ) );
  bucket->len = ( uint16_t ) total_len;
  bucket->watch_group = WATCH_GROUP_1;
  bucket->watch_port = WATCH_PORT_1;
  bucket->weight = WEIGHT_1;
  struct ofp_action_output *ac_output = ( struct ofp_action_output * ) ( bucket->actions );
  ac_output->type = OFPAT_OUTPUT;
  ac_output->len = ( uint16_t ) sizeof( struct ofp_action_output );
  ac_output->port = 1;
  ac_output->max_len = 512;
  append_to_tail( &buckets_head, bucket );
  
  bucket = ( struct ofp_bucket * ) xmalloc( total_len );
  bucket->len = ( uint16_t ) total_len;
  bucket->watch_group = WATCH_GROUP_2;
  bucket->watch_port = WATCH_PORT_2;
  bucket->weight = WEIGHT_2;
  ac_output = ( struct ofp_action_output * ) ( char * ) ( bucket->actions );
  ac_output->type = OFPAT_OUTPUT;
  ac_output->len = ( uint16_t ) sizeof( struct ofp_action_output );
  ac_output->port = 2;
  ac_output->max_len = 1024;
  append_to_tail( &buckets_head, bucket );
  system( "sudo ip link add name trema1-0 type veth peer name trema1-1" );
  system( "sudo ip link add name trema2-0 type veth peer name trema2-1" );
  add_thread();
  init_event_handler_safe();
  init_timer_safe();
  init_table_manager( UINT8_MAX );
  init_switch_port();
  add_switch_port( DEV_PORT_1, WATCH_PORT_1, UINT8_MAX, UINT8_MAX );
  add_switch_port( DEV_PORT_2, WATCH_PORT_2, UINT8_MAX, UINT8_MAX );
  *state = ( void * ) buckets_head;
}


static void
test_destroy_group_mod( void **state ) {
  UNUSED( state );
  system( "sudo ip link delete trema1-0 2>/dev/null" );
  system( "sudo ip link delete trema2-0 2>/dev/null" );
  finalize_table_manager();
  finalize_switch_port();
  finalize_timer_safe();
  finalize_event_handler_safe();
}


static void
test_group_mod_add( void **state ) {
  list_element *buckets = *state;
  
  handle_group_add( MY_TRANSACTION_ID, OFPGT_SELECT, GROUP_ID, buckets );
  group_entry *group_entry = lookup_group_entry( GROUP_ID );
  assert_int_equal( group_entry->group_id, GROUP_ID );
  assert_int_equal( group_entry->type, OFPGT_SELECT );

  bucket_list *bkt_element = get_first_element( group_entry->buckets );
  if ( bkt_element->data == NULL ) {
    bkt_element = bkt_element->next;
  }
  bucket *bucket1 = bkt_element->data;
  struct ofp_bucket *ofp_bucket1 = buckets->data;

  assert_int_equal( bucket1->watch_group, ofp_bucket1->watch_group );
  assert_int_equal( bucket1->weight, ofp_bucket1->weight );
  assert_int_equal( bucket1->watch_port, ofp_bucket1->watch_port );

  action_list *ac_element = get_first_element( bucket1->actions );
  if ( ac_element->data == NULL ) {
    ac_element = ac_element->next;
  }
  action *ac1 = ac_element->data;
  struct ofp_action_output *ofp_ac_out1 = ( struct ofp_action_output * ) ofp_bucket1->actions;
  assert_int_equal( ac1->type, ofp_ac_out1->type );
  assert_int_equal( ac1->port, ofp_ac_out1->port );
  assert_int_equal( ac1->max_len, ofp_ac_out1->max_len );

  bucket *bucket2 = bkt_element->next->data;
  struct ofp_bucket *ofp_bucket2 = buckets->next->data;

  assert_int_equal( bucket2->watch_group, ofp_bucket2->watch_group );
  assert_int_equal( bucket2->weight, ofp_bucket2->weight );
  assert_int_equal( bucket2->watch_port, ofp_bucket2->watch_port );

  ac_element = get_first_element( bucket2->actions );
  if ( ac_element->data == NULL ) {
    ac_element = ac_element->next;
  }
  action *ac2 = ac_element->data;
  struct ofp_action_output *ofp_ac_out2 = ( struct ofp_action_output * ) ofp_bucket2->actions;
  assert_int_equal( ac2->type, ofp_ac_out2->type );
  assert_int_equal( ac2->port, ofp_ac_out2->port );
  assert_int_equal( ac2->max_len, ofp_ac_out2->max_len );
}


static void
test_group_mod_mod( void **state ) {
  list_element *buckets = *state;
  
  handle_group_add( MY_TRANSACTION_ID, OFPGT_SELECT, GROUP_ID, buckets );

 list_element *buckets_head;

  create_list( &buckets_head );
  size_t total_len = sizeof( struct ofp_bucket ) + sizeof( struct ofp_action_header ) ;
  struct ofp_bucket *ofp_bucket = ( struct ofp_bucket * ) ( xmalloc( total_len ) );

  ofp_bucket->len = ( uint16_t ) total_len;
  ofp_bucket->watch_group = WATCH_GROUP_1;
  ofp_bucket->watch_port = WATCH_PORT_1;
  ofp_bucket->weight = WEIGHT_1;
  struct ofp_action_header *ac_hdr = ( struct ofp_action_header * ) ( ofp_bucket->actions );
  ac_hdr->type = OFPAT_COPY_TTL_IN;
  ac_hdr->len = ( uint16_t ) sizeof( struct ofp_action_header );
  append_to_tail( &buckets_head, ofp_bucket );
 
  handle_group_mod_mod( MY_TRANSACTION_ID, OFPGT_ALL, GROUP_ID, buckets_head );
  group_entry *group_entry = lookup_group_entry( GROUP_ID );
  assert_int_equal( group_entry->group_id, GROUP_ID );

  bucket_list *bkt_element = get_first_element( group_entry->buckets );
  if ( bkt_element->data == NULL ) {
    bkt_element = bkt_element->next;
  }
  bucket *bucket = bkt_element->data; 
  assert_true( bucket );
  assert_int_equal( bucket->weight, WEIGHT_1 );
  assert_int_equal( bucket->watch_port, WATCH_PORT_1 );
  assert_int_equal( bucket->watch_group, WATCH_GROUP_1 );

  action_list *ac_element = get_first_element( bucket->actions );
  if ( ac_element->data == NULL ) {
    ac_element = ac_element->next;
  }
  action *action = ac_element->data;
  assert_true( action );
  assert_int_equal( action->type, OFPAT_COPY_TTL_IN );
}


static void
test_group_mod_delete( void **state ) {
  list_element *buckets = *state;

  handle_group_add( MY_TRANSACTION_ID, OFPGT_SELECT, GROUP_ID, buckets );
  handle_group_mod_delete( MY_TRANSACTION_ID, GROUP_ID );
  group_entry *group_entry = lookup_group_entry( GROUP_ID );
  assert_true( group_entry == NULL );
}
  

static void
test_group_mod_delete_invalid( void **state ) {
  list_element *buckets = *state;

  handle_group_add( MY_TRANSACTION_ID, OFPGT_SELECT, GROUP_ID, buckets );
  handle_group_mod_delete( MY_TRANSACTION_ID, INVALID_GROUP_ID );
  group_entry *group_entry = lookup_group_entry( GROUP_ID );
  assert_true( group_entry );
}

int
main() {
  const UnitTest tests[] = {
    unit_test_setup_teardown( test_group_mod_add, test_create_group_mod, test_destroy_group_mod ),
    unit_test_setup_teardown( test_group_mod_mod, test_create_group_mod, test_destroy_group_mod ),
    unit_test_setup_teardown( test_group_mod_delete, test_create_group_mod, test_destroy_group_mod ),
    unit_test_setup_teardown( test_group_mod_delete_invalid, test_create_group_mod, test_destroy_group_mod )
  };
  return run_tests( tests );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
