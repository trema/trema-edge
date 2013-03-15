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


static uint32_t vlan_vid_field( const bool attr, const enum oxm_ofb_match_fields oxm_type );
static uint16_t vlan_vid_length( const match *match );
static uint16_t pack_vlan_vid( oxm_match_header *hdr, const match *match );


static struct oxm oxm_vlan_vid = {
  OFPXMT_OFB_VLAN_VID,
  ( uint16_t ) sizeof( oxm_match_header ) + sizeof( uint16_t ),
  vlan_vid_field,
  vlan_vid_length,
  pack_vlan_vid
};


void 
init_oxm_vlan_vid( void ) {
  register_oxm( &oxm_vlan_vid );
}


static uint32_t
vlan_vid_field( const bool attr, const enum oxm_ofb_match_fields oxm_type ) {
  uint32_t field = 0;

  if ( attr && oxm_type == oxm_vlan_vid.type ) {
    field = OXM_OF_VLAN_VID;
  }
  return field;
}


static uint16_t
vlan_vid_length( const match *match ) {
  uint16_t length = 0;
  
  if ( match->vlan_vid.valid ) {
    length = oxm_vlan_vid.length;
    if ( match->vlan_vid.mask != UINT16_MAX ) {
      length = ( uint16_t ) ( length * 2 );
    }
  }
  return length;
}


static uint16_t
pack_vlan_vid( oxm_match_header *hdr, const match *match ) {
  if ( match->vlan_vid.valid ) {
    *hdr = OXM_OF_VLAN_VID;
    uint16_t *value = ( uint16_t * ) ( ( char * ) hdr + sizeof ( oxm_match_header ) );
    *value = match->vlan_vid.value;
    return oxm_vlan_vid.length;
  }
  return 0;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
