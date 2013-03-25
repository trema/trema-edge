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
#include "cmockery_trema.h"
#include "openflow.h"
#include "wrapper.h"
#include "checks.h"
#include "table_manager_group.h"
#include "group-helper.h"
#include "mocks.h"


#define MY_TRANSACTION_ID 0x11223344
#define GROUP_ID 1
#define INVALID_GROUP_ID 3333
#define WATCH_GROUP_1 0xaa
#define WATCH_GROUP_2 0xbb
#define WATCH_PORT_1 1
#define WATCH_PORT_2 2
#define WEIGHT_1 123
#define WEIGHT_2 456

#ifdef TEST
static void 
insert_num( list_element **head, uint32_t *num ) {
  list_element *e;

  for ( e = *head; e != NULL; e = e->next ) {
    if ( *num > *( uint32_t * ) e->data ) {
      break;
    }
  }
  if ( e == NULL ) {
    append_to_tail( head, num );
  }
  else if ( e == *head ) {
    insert_in_front( head, num );
  }
  else {
    insert_before( head, e->data, num );
  }
}
#endif

void
insert_dnum( dlist_element *list, uint32_t *num ) {
  dlist_element *e;
  dlist_element *last = list;

  if ( list->next != NULL ) {
    e = list->next;
  }
  else if ( list->prev != NULL ) {
    e = list->prev;
  }
  else {
    e = list;
  }
  while ( e != NULL ) {
    if ( e->data != NULL ) {
      if ( *num > *( uint32_t * ) e->data ) {
        insert_before_dlist( e, num );
        return;
      }
    }
    last = e;
    e = e->next;
  }
  insert_after_dlist( last, num );
}

static void
create_group_mod( void **state ) {
  dlist_element *test_list = create_dlist();
  list_element *ll;
  create_list( &ll );
  uint32_t *nums = ( uint32_t * ) xmalloc( sizeof( uint32_t ) * 5 );
  uint32_t i;
  i = 0;
  nums[ i ] = 1;
  insert_dnum( test_list, &nums[ i ] );
  i = 1;
  nums[ i ] = 2;
  insert_dnum( test_list, &nums[ i ] );
  i = 2;
  nums[ i ] = 3;
  insert_dnum( test_list, &nums[ i ] );
  i = 3;
  nums[ i ] = 4;
  insert_dnum( test_list, &nums[ i ] );
  i = 4;
  nums[ i ] = 5;
  insert_dnum( test_list, &nums[ i ] );
  
#ifdef TEST  
  for ( i = 0; i < 5; i++ ) {
    nums[ i ] = i + 1;
    insert_num( &ll, &nums[ i ] );
  }
#endif  
  for ( list_element *e = ll; e != NULL; e = e->next ) {
    uint32_t *num = e->data;
    printf( "ll num = %u\n", *num );
  }

  dlist_element *node = find_element( test_list, ( void * ) &nums[ 2 ] );
  assert( node );
  dlist_element *first = get_first_element( test_list );
  if ( first->data == NULL ) {
    first = first->next;
  }
  while ( first != NULL ) {
    if ( first->data != NULL ) {
      uint32_t *num = first->data;
      printf( "first dl num = %u\n", *num );
    }
    first = first->next;
  }
  dlist_element *last = get_last_element( test_list );
  if ( last->data == NULL ) {
    last = last->prev;
  }
  while ( last != NULL ) {
    if ( last->data != NULL ) {
      uint32_t *num = last->data;
      printf( "last dl num = %u\n", *num );
    }
    last = last->prev;
  }
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
  init_group_table();
  *state = ( void * ) buckets_head;
}


static void
destroy_group_mod( void **state ) {
  UNUSED( state );
  remove_group_entry( GROUP_ID );
}


static void
destroy_group_delete( void **state ) {
  UNUSED( state );
}


static void
test_group_mod_add( void **state ) {
  list_element *buckets = *state;
  
  handle_group_add( MY_TRANSACTION_ID, OFPGT_SELECT, GROUP_ID, buckets );
  group_entry *group_entry = lookup_group_entry( GROUP_ID );
  assert_int_equal( group_entry->group_id, GROUP_ID );
  assert_int_equal( group_entry->type, OFPGT_SELECT );

  bucket_list *bkt_element = get_first_element( group_entry->bucket_list );
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

  bucket_list *bkt_element = get_first_element( group_entry->bucket_list );
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

  expect_value( mock_send_error_message, transaction_id, MY_TRANSACTION_ID );
  expect_value( mock_send_error_message, type, OFPET_GROUP_MOD_FAILED );
  expect_value( mock_send_error_message, code, OFPGMFC_UNKNOWN_GROUP );
  handle_group_add( MY_TRANSACTION_ID, OFPGT_SELECT, GROUP_ID, buckets );

  handle_group_mod_delete( MY_TRANSACTION_ID, INVALID_GROUP_ID );
  group_entry *group_entry = lookup_group_entry( GROUP_ID );
  assert_true( group_entry );
}

int
main() {
  const UnitTest tests[] = {
    unit_test_setup_teardown( test_group_mod_add, create_group_mod, destroy_group_mod ),
    unit_test_setup_teardown( test_group_mod_mod, create_group_mod, destroy_group_mod ),
    unit_test_setup_teardown( test_group_mod_delete, create_group_mod, destroy_group_delete ),
    unit_test_setup_teardown( test_group_mod_delete_invalid, create_group_mod, destroy_group_mod )
  };
  return run_tests( tests );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
