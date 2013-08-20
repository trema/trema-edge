/*
 * Dumps packet-in message.
 *
 * Author: Yasuhito Takamiya <yasuhito@gmail.com>
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


#include <inttypes.h>
#include "trema.h"


static void
handle_packet_in( uint64_t datapath_id, packet_in message ) {
  info( "received a packet_in" );
  info( "datapath_id: %#" PRIx64, datapath_id );
  info( "transaction_id: %#x", message.transaction_id );
  info( "buffer_id: %#x", message.buffer_id );
  info( "total_len: %u", message.total_len );
  info( "reason: %#x", message.reason );
  info( "table_id: %#x", message.table_id );
  info( "cookie: %#" PRIx64, message.cookie );
  char match_string[ MATCH_STRING_LENGTH ];
  memset( match_string, '\0', MATCH_STRING_LENGTH );
  match_to_string( message.match, match_string, sizeof( match_string ) );
  info( "match: %s", match_string );
  info( "data:" );
  dump_buffer( message.data, info );
}


static void
handle_switch_ready( uint64_t datapath_id, void *user_data ) {
  UNUSED( user_data );

  openflow_actions *actions = create_actions();
  append_action_output( actions, OFPP_CONTROLLER, OFPCML_NO_BUFFER );
  openflow_instructions *insts = create_instructions();
  append_instructions_apply_actions( insts, actions );

  buffer *flow_mod = create_flow_mod(
    get_transaction_id(),
    get_cookie(),
    0,
    0,
    OFPFC_ADD,
    0,
    0,
    OFP_LOW_PRIORITY,
    OFP_NO_BUFFER,
    0,
    0,
    OFPFF_SEND_FLOW_REM,
    NULL,
    insts
  );
  send_openflow_message( datapath_id, flow_mod );
  free_buffer( flow_mod );

  delete_instructions( insts );
  delete_actions( actions );
}


int
main( int argc, char *argv[] ) {
  init_trema( &argc, &argv );
  set_packet_in_handler( handle_packet_in, NULL );
  set_switch_ready_handler( handle_switch_ready, NULL );
  start_trema();
  return 0;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
