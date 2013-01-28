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


static uint32_t ipv6_nd_sll_field( const bool attr, const enum oxm_ofb_match_fields oxm_type );
static uint16_t ipv6_nd_sll_length( const match *match );
static void pack_ipv6_nd_sll( struct ofp_match *ofp_match, const match *match );


static struct oxm oxm_ipv6_nd_sll = {
  OFPXMT_OFB_IPV6_ND_SLL,
  OFP_ETH_ALEN,
  ipv6_nd_sll_field,
  ipv6_nd_sll_length,
  pack_ipv6_nd_sll
};


void 
init_oxm_ipv6_nd_sll( void ) {
  register_oxm( &oxm_ipv6_nd_sll );
}


static uint32_t
ipv6_nd_sll_field( const bool attr, const enum oxm_ofb_match_fields oxm_type ) {
  uint32_t field = 0;

  if ( attr && oxm_type == oxm_ipv6_nd_sll.type ) {
    field = OXM_OF_IPV6_ND_SLL;
  }
  return field;
}


static uint16_t
ipv6_nd_sll_length( const match *match ) {
  uint16_t length = 0;
  
  if ( match->ipv6_nd_sll[ 0 ].valid ) {
    length = oxm_ipv6_nd_sll.length;
  }
  return length;
}


static void
pack_ipv6_nd_sll( struct ofp_match *ofp_match, const match *match ) {
  if ( match->ipv6_nd_sll[ 0 ].valid ) {
    ofp_match->type = oxm_ipv6_nd_sll.type;
    ofp_match->length = oxm_ipv6_nd_sll.length;
    memcpy( &ofp_match->oxm_fields, &match->ipv6_nd_sll[ 0 ].value, oxm_ipv6_nd_sll.length );
  }
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
