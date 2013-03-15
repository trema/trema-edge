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


static uint32_t tunnel_id_field( const bool attr, const enum oxm_ofb_match_fields oxm_type );
static uint16_t tunnel_id_length( const match *match );
static uint16_t pack_tunnel_id( oxm_match_header *hdr, const match *match );


static struct oxm oxm_tunnel_id = {
  OFPXMT_OFB_TUNNEL_ID,
  ( uint16_t ) sizeof( oxm_match_header ) + sizeof( uint64_t ),
  tunnel_id_field,
  tunnel_id_length,
  pack_tunnel_id
};


void 
init_oxm_tunnel_id( void ) {
  register_oxm( &oxm_tunnel_id );
}


static uint32_t
tunnel_id_field( const bool attr, const enum oxm_ofb_match_fields oxm_type ) {
  uint32_t field = 0; 

  if ( attr && oxm_type == oxm_tunnel_id.type ) {
    field = OXM_OF_TUNNEL_ID;
  }
  return field;
}


static uint16_t
tunnel_id_length( const match *match ) {
  uint16_t length = 0;
  
  if ( match->tunnel_id.valid ) {
    length = oxm_tunnel_id.length;
    if ( match->tunnel_id.mask != UINT64_MAX ) {
      length = ( uint16_t ) ( length * 2 );
    }
  }
  return length;
}


static uint16_t
pack_tunnel_id( oxm_match_header *hdr, const match *match ) {
  if ( match->tunnel_id.valid ) {
    *hdr = OXM_OF_TUNNEL_ID;
    uint64_t *value = ( uint64_t * ) ( ( char * ) hdr + sizeof ( oxm_match_header ) );
    *value = match->tunnel_id.value;
    return oxm_tunnel_id.length;
  }
  return 0;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
