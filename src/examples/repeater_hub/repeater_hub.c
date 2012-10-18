/*
 * Repeater hub controller.
 *
 * Author: Yasuhito TAKAMIYA <yasuhito@gmail.com>
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


#include "trema.h"


static void
handle_packet_in( uint64_t datapath_id, packet_in message ) {
  if ( message.data == NULL ) {
    error( "data must not be NULL" );
    return;
  }
  uint32_t in_port = get_in_port_from_oxm_matches( message.match );
  if ( in_port == 0 ) {
    return;
  }

  openflow_actions *actions = create_actions();
  append_action_output( actions, OFPP_FLOOD, UINT16_MAX );

  openflow_instructions *insts = create_instructions();
  append_instructions_write_actions( insts, actions );

  oxm_matches *match = create_oxm_matches();
  set_match_from_packet( match, in_port, 0, message.data );

  buffer *flow_mod = create_flow_mod(
    get_transaction_id(),
    get_cookie(),
    0,
    0,
    OFPFC_ADD,
    60,
    0,
    UINT16_MAX,
    message.buffer_id,
    0,
    0,
    OFPFF_SEND_FLOW_REM,
    match,
    insts
  );
  send_openflow_message( datapath_id, flow_mod );
  free_buffer( flow_mod );
  delete_oxm_matches( match );
  delete_instructions( insts );

  if ( message.buffer_id == UINT32_MAX ) {
    buffer *frame = duplicate_buffer( message.data );
    fill_ether_padding( frame );
    buffer *packet_out = create_packet_out(
      get_transaction_id(),
      message.buffer_id,
      in_port,
      actions,
      frame
    );
    send_openflow_message( datapath_id, packet_out );
    free_buffer( packet_out );
    free_buffer( frame );
  }

  delete_actions( actions );
}


static void
handle_switch_ready( uint64_t datapath_id, void *user_data ) {
  UNUSED( user_data );

  openflow_actions *actions = create_actions();
  append_action_output( actions, OFPP_CONTROLLER, OFPCML_NO_BUFFER );

  openflow_instructions *insts = create_instructions();
  append_instructions_write_actions( insts, actions );

  buffer *flow_mod = create_flow_mod(
    get_transaction_id(),
    get_cookie(),
    0,
    0,
    OFPFC_ADD,
    0,
    0,
    UINT16_MAX,
    UINT32_MAX,
    0,
    0,
    OFPFF_SEND_FLOW_REM,
    NULL,
    insts
  );
  send_openflow_message( datapath_id, flow_mod );
  free_buffer( flow_mod );
  delete_instructions( insts );
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
