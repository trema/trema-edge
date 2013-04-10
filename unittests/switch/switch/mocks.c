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


#include "trema.h"
#include "ofdp.h"
#include "cmockery_trema.h"


bool
mock_switch_send_openflow_message( buffer *buffer ) {
  struct ofp_header *header = buffer->data;
  check_expected( buffer->length );
  if ( header->type == OFPT_GET_CONFIG_REPLY ) {
    check_expected( ( ( struct ofp_switch_config * ) buffer->data )->flags );
  } 
  return true;
}


bool
mock_send_error_message( uint32_t transaction_id, uint16_t type, uint16_t code ) {
  check_expected( transaction_id );
  check_expected( type );
  check_expected( code );
  return true;
}


int
mock_time_now( struct timespec *now ) {
  UNUSED( now );
  return 1;
}


ether_device *
mock_create_ether_device( const char *name, const size_t max_send_queue, const size_t max_recv_queue ) {
  check_expected( name );
  check_expected( max_send_queue );
  check_expected( max_recv_queue );
  return ( ether_device * ) ( ( uint32_t ) mock() );
}


bool
mock_set_frame_received_handler( ether_device *device, frame_received_handler callback, void *user_data ) {
  UNUSED( device );
  UNUSED( callback );
  UNUSED( user_data );
  return true;
}


OFDPE
mock_send_for_notify_port_config( uint32_t port_no, uint8_t reason ) {
  check_expected( port_no );
  check_expected( reason );
  return OFDPE_SUCCESS;
}


void
mock_delete_ether_device( ether_device * device ) {
  UNUSED( device );
  return;
}


bool
mock_is_valid_port_no( const uint32_t port_no ) {
  UNUSED( port_no );
  return true;
}


bool
mock_is_valid_group_no( const uint32_t group_id ) {
  check_expected( group_id );
  return true;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/

