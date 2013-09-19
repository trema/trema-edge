/*
 * Copyright (C) 2013 NEC Corporation
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
handle_multipart_reply( uint64_t datapath_id, uint32_t transaction_id, uint16_t type,
                        uint16_t flags, const buffer *data, void *user_data ) {
  UNUSED( user_data );

  if ( type != OFPMP_PORT_DESC ) {
    return;
  }

  info( "datapath_id: %#" PRIx64, datapath_id );
  info( "transaction_id: %x", transaction_id );
  info( "type: %u", type );
  info( "flags: %u", flags );
  struct ofp_port *port = ( struct ofp_port * ) data->data;
  size_t length = data->length;
  while ( length >= sizeof( struct ofp_port ) ) {
    info( "port_no: %u", port->port_no );
    info( "  hw_addr: %02x:%02x:%02x:%02x:%02x:%02x",
          port->hw_addr[ 0 ], port->hw_addr[ 1 ], port->hw_addr[ 2 ],
          port->hw_addr[ 3 ], port->hw_addr[ 4 ], port->hw_addr[ 5 ] );
    info( "  name: %s", port->name );
    info( "  config: %#x", port->config );
    info( "  state: %#x", port->state );
    info( "  curr: %#x", port->curr );
    info( "  advertised: %#x", port->advertised );
    info( "  supported: %#x", port->supported );
    info( "  peer: %#x", port->peer );
    info( "  curr_speed: %#x", port->curr_speed );
    info( "  max_speed: %#x", port->max_speed );

    length -= ( uint16_t ) sizeof( struct ofp_port );
    port++;
  }
}


static void
send_port_desc_multipart_request( uint64_t datapath_id, void *user_data ) {
  UNUSED( user_data );

  buffer *port_desc_multipart_request = create_port_desc_multipart_request( get_transaction_id(), 0 );
  bool ret = send_openflow_message( datapath_id, port_desc_multipart_request );
  if ( !ret ) {
    error( "Failed to send a port-desc-multipart-request message to the switch with datapath ID = %#" PRIx64 ".", datapath_id );
    stop_trema();
  }
  free_buffer( port_desc_multipart_request );
}


int
main( int argc, char *argv[] ) {
  init_trema( &argc, &argv );

  set_switch_ready_handler( send_port_desc_multipart_request, NULL );
  set_multipart_reply_handler( handle_multipart_reply, NULL );

  start_trema();

  return 0;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
