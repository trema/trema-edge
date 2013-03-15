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


static uint32_t metadata_field( const bool attr, const enum oxm_ofb_match_fields oxm_type );
static uint16_t metadata_length( const match *match );
static uint16_t pack_metadata( oxm_match_header *hdr, const match *match );


static struct oxm oxm_metadata = {
  OFPXMT_OFB_METADATA,
  ( uint16_t ) sizeof( oxm_match_header ) + sizeof( uint64_t ),
  metadata_field,
  metadata_length,
  pack_metadata
};


void 
init_oxm_metadata( void ) {
  register_oxm( &oxm_metadata );
}


static uint32_t
metadata_field( const bool attr, const enum oxm_ofb_match_fields oxm_type ) {
  uint32_t field = 0;

  if ( attr && oxm_type == oxm_metadata.type ) {
    field = OXM_OF_METADATA;
  }
  return field;
}


static uint16_t
metadata_length( const match *match ) {
  uint16_t length = 0;
  
  if ( match->metadata.valid ) {
    length = oxm_metadata.length;
    if ( match->metadata.mask != UINT64_MAX ) {
      length = ( uint16_t ) ( length * 2 );
    }
  }
  return length;
}


static uint16_t
pack_metadata( oxm_match_header *hdr, const match *match ) {
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
