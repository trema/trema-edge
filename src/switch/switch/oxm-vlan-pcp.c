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


static uint32_t vlan_pcp_field( const bool attr, const enum oxm_ofb_match_fields oxm_type );
static uint16_t vlan_pcp_length( const match *match );
static uint16_t pack_vlan_pcp( oxm_match_header *hdr, const match *match );


static struct oxm oxm_vlan_pcp = {
  OFPXMT_OFB_VLAN_PCP,
  ( uint16_t ) sizeof( oxm_match_header ) + sizeof( uint8_t ),
  vlan_pcp_field,
  vlan_pcp_length,
  pack_vlan_pcp
};


void 
init_oxm_vlan_pcp( void ) {
  register_oxm( &oxm_vlan_pcp );
}


static uint32_t
vlan_pcp_field( const bool attr, const enum oxm_ofb_match_fields oxm_type ) {
  uint32_t field = 0;

  if ( attr && oxm_type == oxm_vlan_pcp.type ) {
    field = OXM_OF_VLAN_PCP;
  }
  return field;
}


static uint16_t
vlan_pcp_length( const match *match ) {
  uint16_t length = 0;
  
  if ( match->vlan_pcp.valid ) {
    length = oxm_vlan_pcp.length;
  }
  return length;
}


static uint16_t
pack_vlan_pcp( oxm_match_header *hdr, const match *match ) {
  if ( match->vlan_pcp.valid ) {
    *hdr = OXM_OF_VLAN_PCP;
    uint8_t *value = ( uint8_t * ) ( ( char * ) hdr + sizeof ( oxm_match_header ) );
    *value = match->vlan_pcp.value;
    return oxm_vlan_pcp.length;
  }
  return 0;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
