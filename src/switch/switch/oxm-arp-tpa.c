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


static uint32_t arp_tpa_field( const bool attr, const enum oxm_ofb_match_fields oxm_type );
static uint16_t arp_tpa_length( const match *match );
static void pack_arp_tpa( struct ofp_match *ofp_match, const match *match );


static struct oxm oxm_arp_tpa = {
  OFPXMT_OFB_ARP_TPA,
  ( uint16_t ) sizeof( uint32_t ),
  arp_tpa_field,
  arp_tpa_length,
  pack_arp_tpa
};


void 
init_oxm_arp_tpa( void ) {
  register_oxm( &oxm_arp_tpa );
}


static uint32_t
arp_tpa_field( const bool attr, const enum oxm_ofb_match_fields oxm_type ) {
  uint32_t field = 0;

  if ( attr && oxm_type == oxm_arp_tpa.type ) {
    field = OXM_OF_ARP_TPA;
  }
  return field;
}


static uint16_t
arp_tpa_length( const match *match ) {
  uint16_t length = 0;
  
  if ( match->arp_tpa.valid ) {
    length = oxm_arp_tpa.length;
    if ( match->arp_tpa.mask != UINT32_MAX ) {
      length = ( uint16_t ) ( length * 2 );
    }
  }
  return length;
}


static void
pack_arp_tpa( struct ofp_match *ofp_match, const match *match ) {
  if ( match->arp_tpa.valid ) {
    ofp_match->type = oxm_arp_tpa.type;
    ofp_match->length = oxm_arp_tpa.length;
    memcpy( &ofp_match->oxm_fields, &match->arp_tpa.value, oxm_arp_tpa.length );
  }
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
