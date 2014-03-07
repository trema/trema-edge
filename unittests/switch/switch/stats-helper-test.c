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
#include "ofdp_error.h"
#include "port_manager.h"
#include "switch_port.h"
#include "controller_manager.h"
#include "table_manager.h"
#include "action-tlv.h"
#include "oxm.h"
#include "stats-helper.h"
#include "mocks.h"


#define SELECT_TIMEOUT_USEC 100000 
#define MAX_SEND_QUEUE      512
#define MAX_RECV_QUEUE      512
#define PORT_NO             2
#define MAX_LEN             1024
#define TABLE_ID            1
#define GROUP_ID            2222
#define QUEUE_ID            1111
#define VLAN_ETHERTYPE      0x8888
#define MPLS_ETHERTYPE      0x7777
#define PBB_ETHERTYPE       0x6666
#define WEIGHT              11
#define WATCH_PORT          PORT_NO
#define WATCH_GROUP         22
#define MPLS_TTL            32
#define NW_TTL              16
#define MAX_ENTRIES         256
#define TABLE_NAME          "test_table"
#define NEXT_TABLE_ID       1
#define NEXT_TABLE_ID_MISS  2
#define COOKIE              0x31b33850c19f50e


extern uint16_t action_list_length( action_list ** );
extern uint16_t bucket_list_length( bucket_list ** );
extern void pack_bucket( struct ofp_bucket *ofp_bucket, bucket_list **list );
extern uint16_t count_features( void *feature, size_t feature_size );
extern uint16_t assign_instruction_ids( struct ofp_instruction *ins, instructions_capabilities *instructions_cap );
extern uint16_t assign_action_ids( struct ofp_action_header *ac_hdr, actions_capabilities *action_cap );
extern struct ofp_table_features * assign_table_features( table_features *table_feature );
extern flow_stats *retrieve_flow_stats( uint32_t *nr_stats, uint8_t table_id, uint32_t out_port, uint32_t out_group, uint64_t cookie, uint64_t cookie_mask, struct ofp_match *match );

static const uint8_t HW_ADDR[ OFP_ETH_ALEN ] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
static const char *DEV_NAME = "test_veth";


#undef get_ofp_port_structure
#define get_ofp_port_structure mock_get_ofp_port_structure
OFDPE get_ofp_port_structure( uint32_t port_no, ofp_port *out_port );



static uint16_t
all_actions_len( void ) {

  uint16_t len = 0;

  len = ( uint16_t ) ( sizeof( struct ofp_action_output ) ); 
  len = ( uint16_t ) ( len + sizeof( struct ofp_action_group ) ); 
  len = ( uint16_t ) ( len + sizeof( struct ofp_action_set_queue ) ); 
  len = ( uint16_t ) ( len + sizeof( struct ofp_action_mpls_ttl ) );
  len = ( uint16_t ) ( len + sizeof( struct ofp_action_header ) );
  len = ( uint16_t ) ( len + sizeof( struct ofp_action_nw_ttl ) );
  len = ( uint16_t ) ( len + sizeof( struct ofp_action_header ) );
  len = ( uint16_t ) ( len + sizeof( struct ofp_action_header ) );
  len = ( uint16_t ) ( len + sizeof( struct ofp_action_header ) );
  len = ( uint16_t ) ( len + sizeof( struct ofp_action_push ) );
  len = ( uint16_t ) ( len + sizeof( struct ofp_action_push ) );
  len = ( uint16_t ) ( len + sizeof( struct ofp_action_push ) );
  len = ( uint16_t ) ( len + sizeof( struct ofp_action_header ) );
  len = ( uint16_t ) ( len + sizeof( struct ofp_action_pop_mpls ) );
  len = ( uint16_t ) ( len + sizeof( struct ofp_action_header ) );
  len = ( uint16_t ) ( len + sizeof( struct ofp_action_set_field ) );

  return len;
}


static void
create_port_desc( void **state ) {
  UNUSED( state );

  int ret = init_port_manager( SELECT_TIMEOUT_USEC, MAX_SEND_QUEUE, MAX_RECV_QUEUE );
  if ( ret != OFDPE_SUCCESS ) {
   return;
  }

  expect_string( mock_create_ether_device, name, DEV_NAME );
  expect_value( mock_create_ether_device, max_send_queue, MAX_SEND_QUEUE );
  expect_value( mock_create_ether_device, max_recv_queue, MAX_RECV_QUEUE );
  switch_port *port = ( switch_port * ) xmalloc( sizeof( switch_port ) );
  port->device = ( ether_device * ) xmalloc( sizeof( ether_device ) );
  memcpy( port->device->name, DEV_NAME, sizeof( port->device->name ) );
  memcpy( port->device->hw_addr, HW_ADDR, sizeof( port->device->hw_addr ) );
  will_return( mock_create_ether_device, port->device );

  expect_value( mock_send_for_notify_port_config, port_no, PORT_NO );
  expect_value( mock_send_for_notify_port_config, reason, OFPPR_ADD );

  char *device_name = xstrdup( DEV_NAME );
  ret = add_port( PORT_NO, device_name );
  xfree( device_name );
}


static void
create_group_features( void **state ) {
  init_group_table();
  struct ofp_group_features *features = ( struct ofp_group_features * ) xmalloc( sizeof( struct ofp_group_features ) );
  features->types = OFPGT_ALL;
  features->capabilities = OFPGFC_SELECT_WEIGHT | OFPGFC_SELECT_LIVENESS;
  features->max_groups[ OFPGT_ALL ] = 128;
  features->max_groups[ OFPGT_SELECT ] = 256;
  features->max_groups[ OFPGT_INDIRECT ] = 512;
  features->max_groups[ OFPGT_FF ] = 640;
  features->actions[ OFPGT_ALL ] = OFPAT_OUTPUT;
  features->actions[ OFPGT_SELECT ] = OFPAT_COPY_TTL_OUT;
  features->actions[ OFPGT_INDIRECT ] = OFPAT_PUSH_VLAN;
  features->actions[ OFPGT_FF ] = OFPAT_GROUP;
  set_group_features( features );
  *state = ( void * ) features;
}


static action_list *
complete_action_list( void ) {
  action_list *ac_list = init_action_list();

//  expect_value( mock_is_valid_port_no, port_no, PORT_NO );
  action *ac_output = create_action_output( PORT_NO, MAX_LEN );
  append_action( ac_list, ac_output );

  const uint32_t group_id = GROUP_ID;
  action *ac_group = create_action_group( group_id );
  append_action( ac_list, ac_group );
  
  const uint32_t queue_id = QUEUE_ID;
  action *ac_set_queue = create_action_set_queue( queue_id );
  append_action( ac_list, ac_set_queue );
  
  const uint8_t mpls_ttl = MPLS_TTL;
  action *ac_set_mpls_ttl = create_action_set_mpls_ttl( mpls_ttl );
  append_action( ac_list, ac_set_mpls_ttl );
  
  action *ac_dec_mpls_ttl = create_action_dec_mpls_ttl();
  append_action( ac_list, ac_dec_mpls_ttl );
  
  const uint8_t nw_ttl = NW_TTL;
  action *ac_set_ipv4_ttl = create_action_set_ipv4_ttl( nw_ttl );
  append_action( ac_list, ac_set_ipv4_ttl );
  

  action *ac_dec_ipv4_ttl = create_action_dec_ipv4_ttl();
  append_action( ac_list, ac_dec_ipv4_ttl );
  
  action *ac_copy_ttl_out = create_action_copy_ttl_out();
  append_action( ac_list, ac_copy_ttl_out );
  
  action *ac_copy_ttl_in = create_action_copy_ttl_in();
  append_action( ac_list, ac_copy_ttl_in );
  
  const uint16_t ether_type = VLAN_ETHERTYPE;
  action *ac_action_push_vlan = create_action_push_vlan( ether_type );
  append_action( ac_list, ac_action_push_vlan );
  

  const uint16_t mpls_type = MPLS_ETHERTYPE;
  action *ac_action_push_mpls = create_action_push_mpls( mpls_type );
  append_action( ac_list, ac_action_push_mpls );
  

  const uint16_t pbb_type = PBB_ETHERTYPE;
  action *ac_action_push_pbb = create_action_push_pbb( pbb_type );
  append_action( ac_list, ac_action_push_pbb );


  action *ac_action_pop_vlan = create_action_pop_vlan();
  append_action( ac_list, ac_action_pop_vlan );
  
  action *ac_action_pop_mpls = create_action_pop_mpls( mpls_type );
  append_action( ac_list, ac_action_pop_mpls );

  action *ac_action_pop_pbb = create_action_pop_pbb();
  append_action( ac_list, ac_action_pop_pbb );
  
  match *match = init_match();
  action *ac_action_set_field = create_action_set_field( match );
  append_action( ac_list, ac_action_set_field );
  return ac_list;
}


static void
create_action_list( void **state ) {
  action_list *ac_list = complete_action_list();

  init_actions();
  *state = ( void * ) ac_list;
}


static void
create_bucket_list( void **state ) {
  bucket_list *bkt_list = create_action_bucket_list();

  action_list *ac_list = complete_action_list();
  const uint16_t weight = WEIGHT;
  const uint32_t watch_port = WATCH_PORT;
  const uint32_t watch_group = WATCH_GROUP;

//  expect_value( mock_is_valid_port_no, port_no, watch_port );
  bucket *bkt = create_action_bucket( weight, watch_port, watch_group, ac_list );
  if ( bkt != NULL ) {
    append_action_bucket( bkt_list, bkt );
  }
  init_actions();
  *state = ( void * ) bkt_list;
}


static void
destroy_port_desc( void **state ) {
  UNUSED( state );
  finalize_port_manager();
}


static void
destroy_group_features( void **state ) {
  UNUSED( state );
  finalize_group_table();
}


static void
destroy_action_list( void **state ) {
  action_list *ac_list = *state;

  finalize_action_list( &ac_list );
  finalize_actions();
}


static void
destroy_bucket_list( void **state ) {
  bucket_list *bkt_list = *state;

  delete_action_bucket_list( &bkt_list );
  finalize_actions();
}


static void
test_request_port_desc( void **state ) {
  UNUSED( state );

  list_element *list = request_port_desc();
  assert_true( list );
  struct ofp_port *ofp_port = list->data;
  assert_int_equal( ofp_port->port_no, PORT_NO );
  assert_string_equal( ofp_port->name, DEV_NAME );
  assert_memory_equal( ofp_port->hw_addr, HW_ADDR, sizeof( ofp_port->hw_addr ) );
}


static void
test_request_group_features( void **state ) {
  struct ofp_group_features *set_features = *state;
  struct ofp_group_features *features;
  
  features = request_group_features();
  assert_true( features );
  assert_memory_equal( features, set_features, sizeof( *features ) );
}


static void
test_action_list_length( void **state ) {
  action_list *ac_list = *state;

  uint16_t expected_len = all_actions_len();;
  uint16_t len = action_list_length( &ac_list );
  assert_int_equal( len, expected_len );
}


static void
test_bucket_list_length( void **state ) {
  bucket_list *bkt_list = *state;

  uint16_t expected_len = all_actions_len();

  expected_len = ( uint16_t ) ( expected_len + sizeof( struct ofp_bucket ) );

  uint16_t len = bucket_list_length( &bkt_list );
  assert_int_equal( len, expected_len );
}


static void
test_pack_bucket( void **state ) {
  bucket_list *bkt_list = *state;
  struct ofp_bucket *bucket;

  uint16_t bucket_len = ( uint16_t ) ( sizeof( *bucket ) + all_actions_len() );

  bucket = ( struct ofp_bucket * ) xmalloc( bucket_len );
  pack_bucket( bucket, &bkt_list );
  assert_int_equal( bucket->weight, WEIGHT );
  assert_int_equal( bucket->watch_port, WATCH_PORT );
  assert_int_equal( bucket->watch_group, WATCH_GROUP );

  const struct ofp_action_output const *ac_output = ( const struct ofp_action_output const * ) &bucket->actions[ 0 ];
  assert_int_equal( ac_output->type, OFPAT_OUTPUT );
  assert_int_equal( ac_output->len, sizeof( *ac_output ) );
  assert_int_equal( ac_output->port, PORT_NO );
  assert_int_equal( ac_output->max_len, MAX_LEN );

  const struct ofp_action_group const *ac_group = ( const struct ofp_action_group const * )( ( const char const * ) ac_output + ac_output->len );
  assert_int_equal( ac_group->type, OFPAT_GROUP );
  assert_int_equal( ac_group->len, sizeof ( *ac_group ) );
  assert_int_equal( ac_group->group_id, GROUP_ID );

  const struct ofp_action_set_queue const *ac_set_queue = ( const struct ofp_action_set_queue const * )( ( const char const * ) ac_group + ac_group->len );
  assert_int_equal( ac_set_queue->type, OFPAT_SET_QUEUE );
  assert_int_equal( ac_set_queue->len, sizeof( *ac_set_queue ) );
  assert_int_equal( ac_set_queue->queue_id, QUEUE_ID );

  const struct ofp_action_mpls_ttl *ac_set_mpls_ttl = ( const struct ofp_action_mpls_ttl const * )( ( const char const * ) ac_set_queue + ac_set_queue->len );
  assert_int_equal( ac_set_mpls_ttl->type, OFPAT_SET_MPLS_TTL );
  assert_int_equal( ac_set_mpls_ttl->len, sizeof( *ac_set_mpls_ttl ) );
  assert_int_equal( ac_set_mpls_ttl->mpls_ttl, MPLS_TTL );
  
  const struct ofp_action_header const *ac_dec_mpls_ttl = ( const struct ofp_action_header const * )( ( const char const * ) ac_set_mpls_ttl + ac_set_mpls_ttl->len );
  assert_int_equal( ac_dec_mpls_ttl->type, OFPAT_DEC_MPLS_TTL );
  assert_int_equal( ac_dec_mpls_ttl->len, sizeof( *ac_dec_mpls_ttl ) );

  const struct ofp_action_nw_ttl const *ac_set_nw_ttl = ( const struct ofp_action_nw_ttl const * )( ( const char const * ) ac_dec_mpls_ttl + ac_dec_mpls_ttl->len );
  assert_int_equal( ac_set_nw_ttl->type, OFPAT_SET_NW_TTL );
  assert_int_equal( ac_set_nw_ttl->len, sizeof( *ac_set_nw_ttl ) );
  assert_int_equal( ac_set_nw_ttl->nw_ttl, NW_TTL );
  
  const struct ofp_action_header const *ac_dec_nw_ttl = ( const struct ofp_action_header const * )( ( const char const * ) ac_set_nw_ttl + ac_set_nw_ttl->len );
  assert_int_equal( ac_dec_nw_ttl->type, OFPAT_DEC_NW_TTL );
  assert_int_equal( ac_dec_nw_ttl->len, sizeof( *ac_dec_nw_ttl ) );
  
  const struct ofp_action_header const *ac_copy_ttl_out = ( const struct ofp_action_header const * )( ( const char const * ) ac_dec_nw_ttl + ac_dec_nw_ttl->len );
  assert_int_equal( ac_copy_ttl_out->type, OFPAT_COPY_TTL_OUT );
  assert_int_equal( ac_copy_ttl_out->len, sizeof( *ac_copy_ttl_out ) );
  
  const struct ofp_action_header const *ac_copy_ttl_in = ( const struct ofp_action_header const * )( ( const char const * ) ac_copy_ttl_out + ac_copy_ttl_out->len );
  assert_int_equal( ac_copy_ttl_in->type, OFPAT_COPY_TTL_IN );
  assert_int_equal( ac_copy_ttl_in->len, sizeof( *ac_copy_ttl_in ) );
  
  const struct ofp_action_push const *ac_action_push_vlan = ( const struct ofp_action_push const * )( ( const char const * ) ac_copy_ttl_in + ac_copy_ttl_in->len );
  assert_int_equal( ac_action_push_vlan->type, OFPAT_PUSH_VLAN );
  assert_int_equal( ac_action_push_vlan->len, sizeof( *ac_action_push_vlan ) );
  assert_int_equal( ac_action_push_vlan->ethertype, VLAN_ETHERTYPE );

  const struct ofp_action_push const *ac_action_push_mpls = ( const struct ofp_action_push const * )( ( const char const * ) ac_action_push_vlan + ac_action_push_vlan->len );
  assert_int_equal( ac_action_push_mpls->type, OFPAT_PUSH_MPLS );
  assert_int_equal( ac_action_push_mpls->len, sizeof( *ac_action_push_mpls ) );
  assert_int_equal( ac_action_push_mpls->ethertype, MPLS_ETHERTYPE );

  const struct ofp_action_push const *ac_action_push_pbb = ( const struct ofp_action_push const * )( ( const char const * ) ac_action_push_mpls + ac_action_push_mpls->len );
  assert_int_equal( ac_action_push_pbb->type, OFPAT_PUSH_PBB );
  assert_int_equal( ac_action_push_pbb->len, sizeof ( *ac_action_push_pbb ) );
  assert_int_equal( ac_action_push_pbb->ethertype, PBB_ETHERTYPE );
  
  const struct ofp_action_header const *ac_pop_vlan = ( const struct ofp_action_header const * )( ( const char const * ) ac_action_push_pbb + ac_action_push_pbb->len );
  assert_int_equal( ac_pop_vlan->type, OFPAT_POP_VLAN );
  assert_int_equal( ac_pop_vlan->len, sizeof( *ac_pop_vlan ) );
  
  const struct ofp_action_pop_mpls const *ac_pop_mpls = ( const struct ofp_action_pop_mpls const * )( ( const char const * ) ac_pop_vlan + ac_pop_vlan->len );
  assert_int_equal( ac_pop_mpls->type, OFPAT_POP_MPLS );
  assert_int_equal( ac_pop_mpls->len, sizeof( *ac_pop_mpls ) );
  assert_int_equal( ac_pop_mpls->ethertype, MPLS_ETHERTYPE );

  const struct ofp_action_header const *ac_pop_pbb = ( const struct ofp_action_header const * )( ( const char const * ) ac_pop_mpls + ac_pop_mpls->len );
  assert_int_equal( ac_pop_pbb->type, OFPAT_POP_PBB );
  assert_int_equal( ac_pop_pbb->len, sizeof( *ac_pop_pbb ) );

  const struct ofp_action_set_field const *ac_set_field = ( const struct ofp_action_set_field const * )( ( const char const * ) ac_pop_pbb + ac_pop_pbb->len );
  assert_int_equal( ac_set_field->type, OFPAT_SET_FIELD );
  assert_int_equal( ac_set_field->len, sizeof( *ac_set_field ) );
}


static void
test_count_features( void **state ) {
  UNUSED( state );
  
  instructions_capabilities *ins_cap = ( instructions_capabilities * ) xcalloc( 1, sizeof( *ins_cap ) );
  uint16_t feature_len;
  
  feature_len = count_features( ( void * ) ins_cap, sizeof( *ins_cap ) );
  assert_int_equal( feature_len, 0 );
  
  // test setting all the attributes to true
  memset( ins_cap, 1, sizeof( *ins_cap ) );
  feature_len = count_features( ( void * ) ins_cap, sizeof( *ins_cap ) );
  assert_int_equal( feature_len, 6 );
  
  // test setting the first and last attribute
  memset( ins_cap, 0, sizeof( *ins_cap ) );
  ins_cap->meter = true;
  ins_cap->goto_table = true;
  feature_len = count_features( ( void * ) ins_cap, sizeof( *ins_cap ) );
  assert_int_equal( feature_len, 2 );
  
  // test some attributes found around the middle of the structure.
  memset( ins_cap, 0, sizeof( *ins_cap ) );
  ins_cap->clear_actions = true;
  ins_cap->write_actions = true;
  ins_cap->write_metadata = true;
  feature_len = count_features( ( void * ) ins_cap, sizeof( *ins_cap ) );
  assert_int_equal( feature_len, 3 );
  xfree( ins_cap );
  
}


static void
assert_instruction( const struct ofp_instruction *instruction, const instructions_capabilities *ins_cap ) {
  assert_int_equal( instruction->len, sizeof( struct ofp_instruction ) );
  if ( instruction->type == OFPIT_METER  ) {
    assert_int_equal( ins_cap->meter, true );
  }
  else if ( instruction->type == OFPIT_APPLY_ACTIONS ) {
    assert_int_equal( ins_cap->apply_actions, true );
  }
  else if ( instruction->type ==  OFPIT_CLEAR_ACTIONS ) {
    assert_int_equal( ins_cap->clear_actions, true );
  }
  else if ( instruction->type == OFPIT_WRITE_ACTIONS ) {
    assert_int_equal( ins_cap->write_actions, true );
  }
  else if ( instruction->type == OFPIT_WRITE_METADATA ) {
    assert_int_equal( ins_cap->write_metadata, true );
  }
  else if ( instruction->type == OFPIT_GOTO_TABLE ) {
    assert_int_equal( ins_cap->goto_table, true );
  }
}


static void
test_assign_instruction_ids( void **state ) {
  UNUSED( state );
  
  instructions_capabilities *ins_cap = ( instructions_capabilities * ) xmalloc( sizeof( *ins_cap ) );
  uint16_t feature_len;
  
  // test setting all the instructions
  memset( ins_cap, 1, sizeof( *ins_cap ) );
  
  feature_len = count_features( ( void * ) ins_cap, sizeof( *ins_cap ) );
  // allocate space for all ofp_instruction
  struct ofp_instruction *instructions = ( struct ofp_instruction * ) xmalloc( feature_len * sizeof( *instructions ) );
  uint16_t total_len = assign_instruction_ids( instructions, ins_cap );
  for ( uint16_t i = 0; i < feature_len; i++) {
    assert_instruction( &instructions[ i ], ins_cap );
  }
  assert_int_equal( total_len, feature_len * sizeof( struct ofp_instruction ) );
  xfree( instructions );
  xfree( ins_cap );
}


static void
assert_action_ids( const struct ofp_action_header *ac_hdr, const actions_capabilities *ac_cap ) {
  assert_int_equal( ac_hdr->len, sizeof( struct ofp_action_header ) );
  if ( ac_hdr->type == OFPAT_OUTPUT ) {
    assert_int_equal( ac_cap->output, true );
  }
  else if ( ac_hdr->type == OFPAT_SET_QUEUE ) {
    assert_int_equal( ac_cap->set_queue, true );
  }
  else if ( ac_hdr->type == OFPAT_GROUP ) {
    assert_int_equal( ac_cap->group, true );
  }
  else if ( ac_hdr->type == OFPAT_PUSH_VLAN ) {
    assert_int_equal( ac_cap->push_vlan, true );
  }
  else if ( ac_hdr->type == OFPAT_POP_VLAN ) {
    assert_int_equal( ac_cap->pop_vlan, true );
  }
  else if ( ac_hdr->type == OFPAT_PUSH_MPLS ) {
    assert_int_equal( ac_cap->push_mpls, true );
  }
  else if ( ac_hdr->type == OFPAT_POP_MPLS ) {
    assert_int_equal( ac_cap->pop_mpls, true );
  }
  else if ( ac_hdr->type == OFPAT_PUSH_PBB ) {
    assert_int_equal( ac_cap->push_pbb, true );
  }
  else if ( ac_hdr->type == OFPAT_POP_PBB ) {
    assert_int_equal( ac_cap->pop_pbb, true );
  }
}


static void
test_assign_action_ids( void **state ) {
  UNUSED( state );

  actions_capabilities *ac_cap = ( actions_capabilities * ) xmalloc( sizeof( *ac_cap ) );
  uint16_t feature_len;

  memset( ac_cap, 1, sizeof( *ac_cap ) );
  ac_cap->drop = false;
  feature_len = count_features( ( void * ) ac_cap, sizeof( *ac_cap ) );
  struct ofp_action_header *ac_hdr = ( struct ofp_action_header * ) xmalloc( feature_len * sizeof( *ac_hdr ) );
  uint16_t total_len = assign_action_ids( ac_hdr, ac_cap );
  for ( uint16_t i = 0; i < feature_len; i++ ) {
    assert_action_ids( &ac_hdr[ i ], ac_cap );
  }
  assert_int_equal( total_len, feature_len * sizeof( struct ofp_action_header ) );
  xfree( ac_hdr );
  xfree( ac_cap );
}


static void
assert_table_feature_prop_actions( const struct ofp_table_feature_prop_actions const *tfpa, uint16_t type ) {
  uint16_t expected_len = ( uint16_t ) sizeof( *tfpa );

  assert_int_equal( tfpa->type, type );
  const struct ofp_action_header const *ac_id = tfpa->action_ids;
  assert_int_equal( ac_id->type, OFPAT_OUTPUT );
  assert_int_equal( ac_id->len, sizeof( *ac_id ) );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *ac_id ) );

  ac_id = &tfpa->action_ids[ 1 ];
  assert_int_equal( ac_id->type, OFPAT_SET_QUEUE );
  assert_int_equal( ac_id->len, sizeof( *ac_id ) );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *ac_id ) );

  ac_id = &tfpa->action_ids[ 2 ];
  assert_int_equal( ac_id->type, OFPAT_GROUP );
  assert_int_equal( ac_id->len, sizeof( *ac_id ) );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *ac_id ) );

  ac_id = &tfpa->action_ids[ 3 ];
  assert_int_equal( ac_id->type, OFPAT_PUSH_VLAN );
  assert_int_equal( ac_id->len, sizeof( *ac_id ) );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *ac_id ) );

  ac_id = &tfpa->action_ids[ 4 ];
  assert_int_equal( ac_id->type, OFPAT_POP_VLAN );
  assert_int_equal( ac_id->len, sizeof( *ac_id ) );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *ac_id ) );

  ac_id = &tfpa->action_ids[ 5 ];
  assert_int_equal( ac_id->type, OFPAT_PUSH_MPLS );
  assert_int_equal( ac_id->len, sizeof( *ac_id ) );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *ac_id ) );
  
  ac_id = &tfpa->action_ids[ 6 ]; 
  assert_int_equal( ac_id->type, OFPAT_POP_MPLS );
  assert_int_equal( ac_id->len, sizeof( *ac_id ) );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *ac_id ) );

  ac_id = &tfpa->action_ids[ 7 ];
  assert_int_equal( ac_id->type, OFPAT_PUSH_PBB );
  assert_int_equal( ac_id->len, sizeof( *ac_id ) );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *ac_id ) );

  ac_id = &tfpa->action_ids[ 8 ];
  assert_int_equal( ac_id->type, OFPAT_POP_PBB );
  assert_int_equal( ac_id->len, sizeof( *ac_id ) );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *ac_id ) );


  expected_len = ( uint16_t ) ( expected_len + PADLEN_TO_64( expected_len ) );
  assert_int_equal( tfpa->length, expected_len );
}


static void
assert_table_feature_prop_instructions( const struct ofp_table_feature_prop_instructions *tfpi, uint16_t type ) {
  uint16_t expected_len = ( uint16_t ) sizeof( *tfpi );

  assert_int_equal( tfpi->type, type );
  const struct ofp_instruction const *instruction = &tfpi->instruction_ids[ 0 ];
  assert_int_equal( instruction->type, OFPIT_METER );
  assert_int_equal( instruction->len, sizeof( *instruction ) );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *instruction ) );

  instruction = &tfpi->instruction_ids[ 1 ];
  assert_int_equal( instruction->type, OFPIT_APPLY_ACTIONS );
  assert_int_equal( instruction->len, sizeof( *instruction ) );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *instruction ) );

  instruction = &tfpi->instruction_ids[ 2 ];
  assert_int_equal( instruction->type, OFPIT_CLEAR_ACTIONS );
  assert_int_equal( instruction->len, sizeof( *instruction ) );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *instruction ) );

  instruction = &tfpi->instruction_ids[ 3 ];
  assert_int_equal( instruction->type, OFPIT_WRITE_ACTIONS );
  assert_int_equal( instruction->len, sizeof( *instruction ) );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *instruction ) );

  instruction = &tfpi->instruction_ids[ 4 ];
  assert_int_equal( instruction->type, OFPIT_WRITE_METADATA );
  assert_int_equal( instruction->len, sizeof( *instruction ) );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *instruction ) );

  instruction = &tfpi->instruction_ids[ 5 ];
  assert_int_equal( instruction->type, OFPIT_GOTO_TABLE );
  assert_int_equal( instruction->len, sizeof( *instruction ) );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *instruction ) );


  expected_len = ( uint16_t ) ( expected_len + PADLEN_TO_64( expected_len ) );
  assert_int_equal( tfpi->length, expected_len );
}


static void
assert_table_feature_prop_oxm( const struct ofp_table_feature_prop_oxm const *tfpo, uint16_t type ) {
  uint16_t expected_len = ( uint16_t ) sizeof( *tfpo );

  assert_int_equal( tfpo->type, type );
  const uint32_t const *oxm_id = ( const uint32_t const * ) &tfpo->oxm_ids[ 0 ];
  assert_int_equal( *oxm_id, OXM_OF_IN_PORT );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_IN_PHY_PORT );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_METADATA );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_ETH_DST );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_ETH_SRC );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_ETH_TYPE );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_VLAN_VID );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_VLAN_PCP );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_IP_DSCP );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_IP_ECN );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_IP_PROTO );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_IPV4_SRC );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_IPV4_DST );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_TCP_SRC );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_TCP_DST );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_UDP_SRC );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_UDP_DST );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_SCTP_SRC );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_SCTP_DST );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_ICMPV4_TYPE );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_ICMPV4_CODE );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_ARP_OP );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_ARP_SPA );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_ARP_TPA );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_ARP_SHA );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_ARP_THA );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_IPV6_SRC );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_IPV6_DST );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_IPV6_FLABEL );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_ICMPV6_TYPE );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_ICMPV6_CODE );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_IPV6_ND_TARGET );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_IPV6_ND_SLL );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_IPV6_ND_TLL );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_MPLS_LABEL );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_MPLS_TC );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_MPLS_BOS );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );
  // comment out until datapath's match field is created
  // oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  // assert_int_equal( *oxm_id, OXM_OF_PBB_ISID );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_TUNNEL_ID );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  oxm_id = ( const uint32_t const * ) ( ( const char const * ) oxm_id + sizeof( uint32_t ) ); 
  assert_int_equal( *oxm_id, OXM_OF_IPV6_EXTHDR );
  expected_len = ( uint16_t ) ( expected_len + sizeof( *oxm_id ) );

  expected_len = ( uint16_t ) ( expected_len + PADLEN_TO_64( expected_len ) );
  assert_int_equal( tfpo->length, expected_len );
}


static void
assert_table_feature_prop_next_tables( const struct ofp_table_feature_prop_next_tables const *tfpnt, uint16_t type ) {
  uint16_t expected_len = ( uint16_t ) sizeof( *tfpnt );

  assert_int_equal( tfpnt->type, type );

  expected_len = ( uint16_t ) ( expected_len + PADLEN_TO_64( expected_len ) );
  assert_int_equal( tfpnt->length, expected_len );
}


static void
test_assign_table_features( void **state ) {
  UNUSED( state );

  table_features *features = ( table_features * ) xmalloc( sizeof( *features ) );
  features->table_id = 0;
  strncpy( features->name, TABLE_NAME, OFP_MAX_TABLE_NAME_LEN );
  features->name[ OFP_MAX_TABLE_NAME_LEN - 1 ] = '\0';
  features->metadata_match = UINT64_MAX; 
  features->metadata_write = UINT64_MAX;
  features->config = OFPTC_DEPRECATED_MASK;
  features->max_entries = MAX_ENTRIES;
  memset( &features->instructions, 1, sizeof( features->instructions ) );
  memset( &features->instructions_miss, 1, sizeof( features->instructions_miss ) );
  features->min_next_table_ids = NEXT_TABLE_ID;
  features->min_next_table_ids_miss = NEXT_TABLE_ID_MISS;
  memset( &features->write_actions, 1, sizeof( features->write_actions ) );
  memset( &features->write_actions_miss, 1, sizeof( features->write_actions_miss ) );
  memset( &features->apply_actions, 1, sizeof( features->apply_actions ) );
  memset( &features->apply_actions_miss, 1, sizeof( features->apply_actions_miss ) );
  memset( &features->matches, 1, sizeof( features->matches ) );
  memset( &features->wildcards, 1, sizeof( features->wildcards ) );
  memset( &features->write_setfield, 1, sizeof( features->write_setfield ) );
  memset( &features->write_setfield_miss, 1, sizeof( features->write_setfield_miss ) );
  memset( &features->apply_setfield, 1, sizeof( features->apply_setfield ) );
  memset( &features->apply_setfield_miss, 1, sizeof( features->apply_setfield_miss ) );

  init_oxm();
  struct ofp_table_features *ofp_table_features  = assign_table_features( features );
  assert_int_equal( ofp_table_features->table_id, 0 );
  assert_string_equal( ofp_table_features->name, TABLE_NAME );
  assert_int_equal( ofp_table_features->metadata_match, UINT64_MAX );
  assert_int_equal( ofp_table_features->metadata_write, UINT64_MAX );
  assert_int_equal( ofp_table_features->config, OFPTC_DEPRECATED_MASK );
  assert_int_equal( ofp_table_features->max_entries, MAX_ENTRIES );

  const struct ofp_table_feature_prop_instructions const *tfpi = ( const struct ofp_table_feature_prop_instructions const * ) &ofp_table_features->properties[ 0 ];
  assert_table_feature_prop_instructions( tfpi, OFPTFPT_INSTRUCTIONS ); 

  tfpi = ( const struct ofp_table_feature_prop_instructions const * )( ( const char const * ) tfpi + tfpi->length );
  assert_table_feature_prop_instructions( tfpi, OFPTFPT_INSTRUCTIONS_MISS );

  const struct ofp_table_feature_prop_actions *tfpa = ( const struct ofp_table_feature_prop_actions const * ) ( ( const char const * ) tfpi + tfpi->length );
  assert_table_feature_prop_actions( tfpa, OFPTFPT_WRITE_ACTIONS );

  tfpa = ( const struct ofp_table_feature_prop_actions  const * ) ( ( const char const * ) tfpa + tfpa->length );
  assert_table_feature_prop_actions( tfpa, OFPTFPT_WRITE_ACTIONS_MISS );

  tfpa = ( const struct ofp_table_feature_prop_actions const * ) ( ( const char const * ) tfpa + tfpa->length );
  assert_table_feature_prop_actions( tfpa, OFPTFPT_APPLY_ACTIONS );

  tfpa = ( const struct ofp_table_feature_prop_actions const * ) ( ( const char const * ) tfpa + tfpa->length );
  assert_table_feature_prop_actions( tfpa, OFPTFPT_APPLY_ACTIONS_MISS );

  const struct ofp_table_feature_prop_oxm const *tfpo = ( const struct ofp_table_feature_prop_oxm const * ) ( ( const char const * ) tfpa + tfpa->length );
  assert_table_feature_prop_oxm( tfpo, OFPTFPT_MATCH );

  tfpo = ( const struct ofp_table_feature_prop_oxm const * ) ( ( const char const * ) tfpo + tfpo->length );
  assert_table_feature_prop_oxm( tfpo, OFPTFPT_WILDCARDS );

  tfpo = ( const struct ofp_table_feature_prop_oxm const * ) ( ( const char const * ) tfpo + tfpo->length );
  assert_table_feature_prop_oxm( tfpo, OFPTFPT_WRITE_SETFIELD );

  tfpo = ( const struct ofp_table_feature_prop_oxm const * ) ( ( const char const * ) tfpo + tfpo->length );
  assert_table_feature_prop_oxm( tfpo, OFPTFPT_WRITE_SETFIELD_MISS );

  tfpo = ( const struct ofp_table_feature_prop_oxm const * ) ( ( const char const * ) tfpo + tfpo->length );
  assert_table_feature_prop_oxm( tfpo, OFPTFPT_APPLY_SETFIELD );

  tfpo = ( const struct ofp_table_feature_prop_oxm const * ) ( ( const char const * ) tfpo + tfpo->length ); 
  assert_table_feature_prop_oxm( tfpo, OFPTFPT_APPLY_SETFIELD_MISS );
  
  const struct ofp_table_feature_prop_next_tables *tfpnt = ( const struct ofp_table_feature_prop_next_tables const * ) ( ( const char const * ) tfpo + tfpo->length ); 
  assert_table_feature_prop_next_tables( tfpnt, OFPTFPT_NEXT_TABLES );
  const uint8_t const *table_id = ( const uint8_t const * ) ( &tfpnt->next_table_ids );
  assert_int_equal( *table_id, NEXT_TABLE_ID );

  tfpnt = ( const struct ofp_table_feature_prop_next_tables const * ) ( ( const char const * ) tfpnt + tfpnt->length );
  assert_table_feature_prop_next_tables( tfpnt, OFPTFPT_NEXT_TABLES_MISS );
  table_id = ( const uint8_t const * ) ( &tfpnt->next_table_ids );
  assert_int_equal( *table_id, NEXT_TABLE_ID_MISS );
}


static void
test_retrieve_flow_stats( void **state ) {
  UNUSED( state );

  uint16_t total_len = ( uint16_t ) ( sizeof( struct ofp_match ) +
    OXM_LENGTH( OXM_OF_IN_PORT ) +
    sizeof( uint32_t ) + OXM_LENGTH( OXM_OF_IN_PHY_PORT ) + 
    sizeof( uint32_t ) + OXM_LENGTH ( OXM_OF_METADATA )
  );
  total_len = ( uint16_t ) ( total_len + PADLEN_TO_64( total_len ) );
  struct ofp_match *ofp_match =  ( struct ofp_match * ) ( xmalloc( total_len ) );
  ofp_match->type = OFPMT_OXM;
  ofp_match->length = total_len;

  uint32_t *oxm_id = ( uint32_t * ) ( ( char * ) ofp_match->oxm_fields );
  *oxm_id = OXM_OF_IN_PORT;

  uint32_t *in_port = ( uint32_t * ) ( ( char * ) oxm_id + sizeof( *oxm_id ) );
  *in_port = PORT_NO;

  oxm_id = ( uint32_t * ) ( ( char * ) in_port + OXM_LENGTH( OXM_OF_IN_PORT ) );
  *oxm_id = OXM_OF_IN_PHY_PORT;

  uint32_t *in_phy_port = ( uint32_t * ) ( ( char * ) oxm_id + sizeof( *oxm_id ) );
  *in_phy_port = PORT_NO;

  oxm_id = ( uint32_t * ) ( ( char * ) in_phy_port + OXM_LENGTH( OXM_OF_IN_PHY_PORT ) );
  *oxm_id = OXM_OF_METADATA;

  uint64_t *metadata = ( uint64_t * ) ( ( char * ) oxm_id + sizeof( *oxm_id ) );
  uint64_t dummy_metadata = 0x1122334455667788;
  memcpy( metadata, &dummy_metadata, sizeof( uint64_t ) );
  
  uint32_t nr_stats = 0;
  uint8_t table_id = TABLE_ID;
  uint32_t out_port = PORT_NO;
  uint32_t out_group = GROUP_ID;
  uint64_t cookie = COOKIE;
  uint64_t cookie_mask = 0xffffffffffffffff;
  init_table_manager();
  retrieve_flow_stats( &nr_stats, table_id, out_port, out_group, cookie, cookie_mask, ofp_match );
  assert_int_equal( nr_stats, 0 );
}


static void
test_desc_stats( void **state ) {
  UNUSED( state );

  assert_string_equal( dp_desc(), "Trema-based OpenFlow switch" );
  assert_string_equal( mfr_desc(), "Trema project" );
  assert_string_equal( serial_num(), "0" );
  const char *desc = hw_desc();
  assert_true( strlen( desc ) > 0 );
}


static void
test_instructions( void **state ) {
  UNUSED( state );
  uint64_t metadata = 0x5dd2ca2bcd04d53e;
  uint64_t metadata_mask = 0x3012174b861ea4fd;
  instruction *metadata_ins = create_instruction_write_metadata( metadata, metadata_mask );
  instruction_list *ins_list = init_instruction_list();
  append_instruction( ins_list, metadata_ins );

  instruction *meter = create_instruction_meter( 0xc7231908 );
  append_instruction( ins_list, meter );
  
  instruction *apply_actions = create_instruction_apply_actions( complete_action_list() );
  append_instruction( ins_list, apply_actions );
  
  instruction *clear_actions = create_instruction_clear_actions();
  append_instruction( ins_list, clear_actions );

  dlist_element *e = get_first_element( ins_list );
  if ( e->data == NULL ) {
    e = ins_list->next;
  }
  for (; e != ins_list; e = e->next ) {
    if ( e->data != NULL ) {
      instruction *ins = e->data;
      printf( "ins type( %u )\n", ins->type );
    }
  }
  instruction_list *new_ins_list;
  new_ins_list = copy_instruction_list( ins_list );
  
  remove_instruction( ins_list, meter );
  e = get_first_element( ins_list );
  if ( e->data == NULL ) {
    e = ins_list->next;
  }
  for (; e != ins_list; e = e->next ) {
    if ( e->data != NULL ) {
      instruction *ins = e->data;
      printf( "ad ins type( %u )\n", ins->type );
    }
  }

  
  e = get_first_element( new_ins_list );
  if ( e->data == NULL ) {
    e = new_ins_list->next;
  }
  for (; e != new_ins_list; e = e->next ) {
    if ( e->data != NULL ) {
      instruction *ins = e->data;
      printf( "ins type( %u )\n", ins->type );
    }
  }
  finalize_instruction_list( &new_ins_list );
  finalize_instruction_list( &ins_list );
}


static void
test_bucket_list( void **state ) {
  bucket_list *bkt_list = *state;

  action_list *ac_list = complete_action_list();
  const uint16_t weight = WEIGHT + 1;
  const uint32_t watch_port = WATCH_PORT + 1;
  const uint32_t watch_group = WATCH_GROUP + 1;

  expect_value( mock_is_valid_group_no, group_id, GROUP_ID );
  expect_value( mock_is_valid_group_no, group_id, GROUP_ID );
  bucket *bkt = create_action_bucket( weight, watch_port, watch_group, ac_list );
  if ( bkt != NULL ) {
    append_action_bucket( bkt_list, bkt );
  }

  validate_action_bucket( bkt_list );
  uint32_t bkt_cnt;
  bkt_cnt = get_bucket_count( bkt_list );
  assert_int_equal( bkt_cnt, 2 );
  remove_action_bucket( bkt_list, bkt );
  bkt_cnt = get_bucket_count( bkt_list );
  assert_int_equal( bkt_cnt, 1 );
}


int
main( void ) {
  const UnitTest tests[] = {
    unit_test( test_instructions ),
    unit_test_setup_teardown( test_bucket_list, create_bucket_list, destroy_bucket_list ),
    unit_test_setup_teardown( test_request_port_desc, create_port_desc, destroy_port_desc ),
    unit_test_setup_teardown( test_request_group_features, create_group_features, destroy_group_features ),
    unit_test_setup_teardown( test_action_list_length, create_action_list, destroy_action_list ),
    unit_test_setup_teardown( test_bucket_list_length, create_bucket_list, destroy_bucket_list ),
    unit_test_setup_teardown( test_pack_bucket, create_bucket_list, destroy_bucket_list ),
    unit_test( test_count_features ),
    unit_test( test_assign_instruction_ids ),
    unit_test( test_assign_action_ids ),
    unit_test( test_assign_table_features ),
    unit_test( test_retrieve_flow_stats ),
    unit_test( test_desc_stats ),
  };
  return run_tests( tests );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/
 