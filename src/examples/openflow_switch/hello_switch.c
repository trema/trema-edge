/*
 * A simple switch that has minimum function to test hello message.
 *
 * Copyright (C) 2012 Hiroyasu OHYAMA
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


#include "chibach.h"


static void handle_features_request( uint32_t, void * );
static void handle_hello( uint32_t, uint8_t, const buffer *, void * );


static void
handle_features_request( uint32_t tid, void *user_data ) {
  UNUSED( user_data );

  switch_send_openflow_message( create_features_reply( tid, get_datapath_id(), 0, 1, 0, 0 ) );
}


static void
handle_hello( uint32_t tid, uint8_t version, const buffer *data, void *user_data ) {
  UNUSED( version );
  UNUSED( user_data );
  UNUSED( data );

  info( "received: OFPT_HELLO" );

  switch_send_openflow_message( create_hello( tid, NULL ) );
}


int
main( int argc, char **argv ) {
  init_chibach( &argc, &argv );

  set_hello_handler( handle_hello, NULL );
  set_features_request_handler( handle_features_request, NULL );

  start_chibach();

  stop_chibach();

  return 0;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
