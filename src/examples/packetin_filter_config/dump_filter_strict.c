/*
 * Author: Yasunobu Chiba
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


#include <stdio.h>
#include <string.h>
#include "trema.h"
#include "utils.h"


static void
dump_filter_strict( void ) {
  oxm_matches *match = create_oxm_matches();
  append_oxm_match_in_port( match, 1 );
  append_oxm_match_eth_type( match, 0x0800 );
  append_oxm_match_vlan_vid( match, 0, 0 );
  append_oxm_match_ipv4_src( match, 0x0a000001, 0 );
  append_oxm_match_ipv4_dst( match, 0x0a000002, 0 );
  append_oxm_match_ip_dscp( match, 0 );
  append_oxm_match_ip_ecn( match, 0 );
  append_oxm_match_ip_proto( match, 0x6 );
  append_oxm_match_tcp_src( match, 1024 );
  append_oxm_match_tcp_dst( match, 2048 );

  static handler_data data;
  data.match = match;
  snprintf( data.service_name, sizeof( data.service_name ), "dumper" );
  data.service_name[ sizeof( data.service_name ) - 1 ] = '\0';
  data.strict = true;

  bool ret = dump_packetin_filter( data.match, UINT16_MAX, data.service_name, data.strict,
                                   dump_filters, &data );
  if ( ret == false ) {
    error( "Failed to dump packetin filters ( ret = %d ).", ret );
  }
  else {
    add_periodic_event_callback( 5, timeout, &data );
  }
}


int
main( int argc, char *argv[] ) {
  init_trema( &argc, &argv );

  dump_filter_strict();

  start_trema();
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
