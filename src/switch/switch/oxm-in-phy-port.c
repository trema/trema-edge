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


static uint32_t in_phy_port_field( const bool attr, const enum oxm_ofb_match_fields oxm_type );
static uint16_t in_phy_port_length( const match *match );
static uint16_t pack_in_phy_port( oxm_match_header *hdr, const match *match );



static struct oxm oxm_in_phy_port = {
  OFPXMT_OFB_IN_PHY_PORT,
  ( uint16_t ) sizeof( oxm_match_header ) + sizeof( uint32_t ),
  in_phy_port_field,
  in_phy_port_length,
  pack_in_phy_port
};


static uint32_t
in_phy_port_field( const bool attr, const enum oxm_ofb_match_fields oxm_type ) {
  uint32_t field = 0;

  if ( attr && oxm_type == oxm_in_phy_port.type  ) {
    field = OXM_OF_IN_PHY_PORT;
  }
  return field;
}


static uint16_t
in_phy_port_length( const match *match ) {
  uint16_t length = 0;
  
  if ( match->in_port.valid ) {
    length = oxm_in_phy_port.length;
  }
  return length;
}


void 
init_oxm_in_phy_port( void ) {
  register_oxm( &oxm_in_phy_port );
}


static uint16_t
pack_in_phy_port( oxm_match_header *hdr, const match *match ) {
  UNUSED( hdr );
  UNUSED( match );
  return 0;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
