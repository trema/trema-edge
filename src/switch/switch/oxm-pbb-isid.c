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


static uint32_t pbb_isid_field( const bool attr, const enum oxm_ofb_match_fields oxm_type );
static uint16_t pbb_isid_length( const match *match );
static uint16_t pack_pbb_isid( oxm_match_header *hdr, const match *match );


static struct oxm oxm_pbb_isid = {
  OFPXMT_OFB_PBB_ISID,
  ( uint16_t ) sizeof( oxm_match_header ) + sizeof( uint32_t ),
  pbb_isid_field,
  pbb_isid_length,
  pack_pbb_isid
};


void 
init_oxm_pbb_isid( void ) {
  register_oxm( &oxm_pbb_isid );
}


static uint32_t
pbb_isid_field( const bool attr, const enum oxm_ofb_match_fields oxm_type ) {
  uint32_t field = 0;
  
  if ( attr && oxm_type == oxm_pbb_isid.type ) {
    field = OXM_OF_PBB_ISID;
  }
  return field;
}


static uint16_t
pbb_isid_length( const match *match ) {
  uint16_t length = 0;
  
  if ( match->pbb_isid.valid ) {
    length = oxm_pbb_isid.length;

    if( match->pbb_isid.mask != UINT32_MAX ){
      length = ( uint16_t ) ( length * 2);
    }
  }
  return length;
}


static uint16_t
pack_pbb_isid( oxm_match_header *hdr, const match *match ) {
  if ( match->pbb_isid.valid ) {
    *hdr = OXM_OF_PBB_ISID;
    uint8_t *value = ( uint8_t * ) ( ( char * ) hdr + sizeof ( oxm_match_header ) );
    value[ 0 ] = ( match->pbb_isid.value >> 16 ) & 0xFF;
    value[ 1 ] = ( match->pbb_isid.value >>  8 ) & 0xFF;
    value[ 2 ] = ( match->pbb_isid.value >>  0 ) & 0xFF;
    return oxm_pbb_isid.length;
  }
  return 0;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
