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
#include <arpa/inet.h>
#include "cmockery_trema.h"
#include "openflow.h"
#include "wrapper.h"
#include "checks.h"
#include "async.h"
#include "ofdp_error.h"
#include "port_manager.h"
#include "switch_port.h"
#include "controller_manager.h"
#include "table_manager.h"
#include "action-tlv.h"
#include "oxm.h"
#include "stats-helper.h"
#include "datapath.h"
#include "mocks.h"
#include "ofdp.h"


#define TRANSACTION_ID      0xa0c6d6f2
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


extern void _handle_set_config( const uint32_t transaction_id, const uint16_t flags, uint16_t miss_send_len, void *user_data );
extern void _handle_get_config_request( const uint32_t transaction, void *user_data );


static void
init_datapath_condition( void **state ) {
  ofdp_library_argument *args = xmalloc( sizeof( ofdp_library_argument ) );
  args->program_name = "protocol-handler-test";
  args->loglevel = "info";
  create_list( &args->devices_info );
  args->datapath_id = 0xabc;
  args->is_daemon = false;
  args->max_flow_entries = 256;
  args->max_recv_queue = MAX_RECV_QUEUE;
  args->max_send_queue = MAX_SEND_QUEUE;
  args->switch_mtu = SWITCH_MTU;
  args->num_controller_buffer = NUM_CONTROLLER_BUFFER;
  args->num_pool = NUM_POOL;
  args->select_timeout_usec = SELECT_TIMEOUT_USEC;
  init_datapath( args );
  *state = args;
}


static void
test_set_config( void **state ) {
  UNUSED( state );
  
  const uint32_t transaction_id = TRANSACTION_ID;
  uint16_t flags = OFPC_FRAG_NORMAL;
  const uint16_t miss_send_len = OFP_DEFAULT_MISS_SEND_LEN;
  _handle_set_config( transaction_id, flags, miss_send_len, NULL );
  
  expect_value( mock_switch_send_openflow_message, buffer->length, sizeof( struct ofp_switch_config ) );
  expect_value( mock_switch_send_openflow_message, ( ( struct ofp_switch_config * ) buffer->data )->flags, ntohs( flags ) );
  _handle_get_config_request( transaction_id, NULL );
  struct ofp_switch_config config;
  get_switch_config( &config );
  assert_int_equal( config.flags, flags );
  assert_int_equal( config.miss_send_len, miss_send_len );
}


static void
finalize_datapath_condition( void **state ) {
  UNUSED( state );
  finalize_datapath();
}


int
main( void ) {
  const UnitTest tests[] = {
    unit_test_setup_teardown( test_set_config, init_datapath_condition, finalize_datapath_condition ),
  };
  return run_tests( tests );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/
 
