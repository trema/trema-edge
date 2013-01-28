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


static uint32_t arp_tha_field( const bool attr, const enum oxm_ofb_match_fields oxm_type );
static uint16_t arp_tha_length( const match *match );
static void pack_arp_tha( struct ofp_match *ofp_match, const match *match );


static struct oxm oxm_arp_tha = {
  OFPXMT_OFB_ARP_THA,
  OFP_ETH_ALEN,
  arp_tha_field,
  arp_tha_length,
  pack_arp_tha
};


void 
init_oxm_arp_tha( void ) {
  register_oxm( &oxm_arp_tha );
}


static uint32_t
arp_tha_field( const bool attr, const enum oxm_ofb_match_fields oxm_type ) {
  uint32_t field = 0;

  if ( attr && oxm_type == oxm_arp_tha.type ) {
    field = OXM_OF_ARP_THA;
  }
  return field;
}


static uint16_t
arp_tha_length( const match *match ) {
  uint16_t length = 0;
  
  if ( match->arp_tha[ 0 ].valid ) {
    length = oxm_arp_tha.length;
    if ( match->arp_tha[ 0 ].mask != UINT8_MAX ) {
      length = ( uint16_t ) ( length * 2 );
    }
  }
  return length;
}


static void
pack_arp_tha( struct ofp_match *ofp_match, const match *match ) {
  if ( match->arp_tha[ 0 ].valid ) {
    ofp_match->type = oxm_arp_tha.type;
    ofp_match->length = oxm_arp_tha.length;
    memcpy( &ofp_match->oxm_fields, &match->arp_tha[ 0 ].value, oxm_arp_tha.length );
  }
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
