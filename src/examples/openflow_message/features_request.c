/*
 * Sends a features request message.
 *
 * Author: Shin-ya Zenke, Yasuhito Takamiya <yasuhito@gmail.com>
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
#include <stdio.h>
#include "trema.h"


static void
handle_features_reply(
  uint64_t datapath_id,
  uint32_t transaction_id,
  uint32_t n_buffers,
  uint8_t n_tables,
  uint8_t auxiliary_id,
  uint32_t capabilities,
  void *user_data ) {
  UNUSED( user_data );

  info( "datapath_id: %#" PRIx64, datapath_id );
  info( "transaction_id: %#lx", transaction_id );
  info( "n_buffers: %lu", n_buffers );
  info( "n_tables: %u", n_tables );
  info( "auxiliary_id: %u", auxiliary_id );
  info( "capabilities:" );
  if ( capabilities & OFPC_FLOW_STATS ) {
    info( "  OFPC_FLOW_STATS" );
  }
  if ( capabilities & OFPC_TABLE_STATS ) {
    info( "  OFPC_TABLE_STATS" );
  }
  if ( capabilities & OFPC_PORT_STATS ) {
    info( "  OFPC_PORT_STATS" );
  }
  if ( capabilities & OFPC_IP_REASM ) {
    info( "  OFPC_IP_REASM" );
  }
  if ( capabilities & OFPC_QUEUE_STATS ) {
    info( "  OFPC_QUEUE_STATS" );
  }
  if ( capabilities & OFPC_PORT_BLOCKED ) {
    info( "  OFPC_PORT_BLOCKED" );
  }
}


static void
send_features_request( uint64_t datapath_id, void *user_data ) {
  UNUSED( user_data );

  buffer *features_request = create_features_request( get_transaction_id() );
  bool ret = send_openflow_message( datapath_id, features_request );
  if ( !ret ) {
    error( "Failed to send a features request message to the switch with datapath ID = %#" PRIx64 ".", datapath_id );
    stop_trema();
  }
  free_buffer( features_request );
}


int
main( int argc, char *argv[] ) {
  init_trema( &argc, &argv );

  set_switch_ready_handler( send_features_request, NULL );
  set_features_reply_handler( handle_features_reply, NULL );

  start_trema();

  return 0;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
