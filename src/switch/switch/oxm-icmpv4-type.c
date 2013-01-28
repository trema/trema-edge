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


static uint32_t get_icmpv4_field( const bool attr, const enum oxm_ofb_match_fields oxm_type );
static uint16_t icmpv4_type_length( const match *match );
static void pack_icmpv4_type( struct ofp_match *ofp_match, const match *match );


static struct oxm oxm_icmpv4_type = {
  OFPXMT_OFB_ICMPV4_TYPE,
  ( uint16_t ) sizeof( uint8_t ),
  get_icmpv4_field,
  icmpv4_type_length,
  pack_icmpv4_type
};


void 
init_oxm_icmpv4_type( void ) {
  register_oxm( &oxm_icmpv4_type );
}


static uint32_t
get_icmpv4_field( const bool attr, const enum oxm_ofb_match_fields oxm_type ) {
  uint32_t field = 0;

  if ( attr && oxm_type == oxm_icmpv4_type.type ) {
    field = OXM_OF_ICMPV4_TYPE;
  }
  return field;
}


static uint16_t
icmpv4_type_length( const match *match ) {
  uint16_t length = 0;
  
  if ( match->icmpv4_type.valid ) {
    length = oxm_icmpv4_type.length;
  }
  return length;
}


static void
pack_icmpv4_type( struct ofp_match *ofp_match, const match *match ) {
  if ( match->icmpv4_type.valid ) {
    ofp_match->type = oxm_icmpv4_type.type;
    ofp_match->length = oxm_icmpv4_type.length;
    memcpy( &ofp_match->oxm_fields, &match->icmpv4_type.value, oxm_icmpv4_type.length );
  }
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
