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


#include <stdint.h>
#include "trema.h"
#include "ofdp.h"
#include "oxm.h"


static uint32_t ip_proto_field( const bool attr, const enum oxm_ofb_match_fields oxm_type );
static uint16_t ip_proto_length( const match *match );
static void pack_ip_proto( struct ofp_match *ofp_match, const match *match );


static struct oxm oxm_ip_proto = {
  OFPXMT_OFB_IP_PROTO,
  ( uint16_t ) sizeof( uint8_t ),
  ip_proto_field,
  ip_proto_length,
  pack_ip_proto
};


void 
init_oxm_ip_proto( void ) {
  register_oxm( &oxm_ip_proto );
}


static uint32_t
ip_proto_field( const bool attr, const enum oxm_ofb_match_fields oxm_type ) {
  uint32_t field = 0;

  if ( attr && oxm_type == oxm_ip_proto.type ) {
    field = OXM_OF_IP_PROTO;
  }
  return field;
}


static uint16_t
ip_proto_length( const match *match ) {
  uint16_t length = 0;
  
  if ( match->ip_proto.valid ) {
    length = oxm_ip_proto.length;
  }
  return length;
}


static void
pack_ip_proto( struct ofp_match *ofp_match, const match *match ) {
  if ( match->ip_proto.valid ) {
    ofp_match->type = oxm_ip_proto.type;
    ofp_match->length = oxm_ip_proto.length;
    memcpy( &ofp_match->oxm_fields, &match->ip_proto.value, oxm_ip_proto.length );
  }
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
