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
#include <stdlib.h>
#include "trema.h"
#include "ofdp.h"
#include "oxm-arp-op.h"
#include "oxm-arp-sha.h"
#include "oxm-arp-spa.h"
#include "oxm-arp-tha.h"
#include "oxm-arp-tpa.h"
#include "oxm-eth-dst.h"
#include "oxm-eth-src.h"
#include "oxm-eth-type.h"
#include "oxm-icmpv4-code.h"
#include "oxm-icmpv4-type.h"
#include "oxm-icmpv6-code.h"
#include "oxm-icmpv6-type.h"
#include "oxm-in-phy-port.h"
#include "oxm-in-port.h"
#include "oxm-ip-dscp.h"
#include "oxm-ip-ecn.h"
#include "oxm-ip-proto.h"
#include "oxm-ipv4-dst.h"
#include "oxm-ipv4-src.h"
#include "oxm-ipv6-dst.h"
#include "oxm-ipv6-exthdr.h"
#include "oxm-ipv6-flabel.h"
#include "oxm-ipv6-nd-sll.h"
#include "oxm-ipv6-nd-target.h"
#include "oxm-ipv6-nd-tll.h"
#include "oxm-ipv6-src.h"
#include "oxm-metadata.h"
#include "oxm-mpls-bos.h"
#include "oxm-mpls-label.h"
#include "oxm-mpls-tc.h"
#include "oxm-pbb-isid.h"
#include "oxm-sctp-dst.h"
#include "oxm-sctp-src.h"
#include "oxm-tcp-dst.h"
#include "oxm-tcp-src.h"
#include "oxm-tunnel-id.h"
#include "oxm-udp-dst.h"
#include "oxm-udp-src.h"
#include "oxm-vlan-pcp.h"
#include "oxm-vlan-vid.h"
#include "oxm.h"


/*
 * We could have created an array of oxm structures with a match field is the 
 * index. But we chose not because not wanted to restrict ourselves on the 
 * match type value. This introduces a sligtly overhead on searching.
 */
static struct oxm **oxm_arr;
static uint32_t nr_oxm;
static uint32_t oxm_alloc;


void
register_oxm( struct oxm *oxm ) {
  ALLOC_GROW( oxm_arr, nr_oxm + 1, oxm_alloc );
  oxm_arr[ nr_oxm++ ] = oxm;
}


void
init_oxm( void ) {
  init_oxm_in_port();
  init_oxm_in_phy_port();
  init_oxm_arp_op();
  init_oxm_arp_sha();
  init_oxm_arp_spa();
  init_oxm_arp_tpa();
  init_oxm_arp_tha();
  init_oxm_eth_dst();
  init_oxm_eth_src();
  init_oxm_eth_type();
  init_oxm_icmpv4_code();
  init_oxm_icmpv4_type();
  init_oxm_icmpv6_code();
  init_oxm_icmpv6_type();
  init_oxm_ip_dscp();
  init_oxm_ip_ecn();
  init_oxm_ip_proto();
  init_oxm_ipv4_dst();
  init_oxm_ipv4_src();
  init_oxm_ipv6_src();
  init_oxm_ipv6_dst();
  init_oxm_ipv6_exthdr();
  init_oxm_ipv6_flabel();
  init_oxm_ipv6_nd_sll();
  init_oxm_ipv6_nd_target();
  init_oxm_ipv6_nd_tll();
  init_oxm_metadata();
  init_oxm_mpls_bos();
  init_oxm_mpls_label();
  init_oxm_mpls_tc();
  init_oxm_sctp_dst();
  init_oxm_sctp_src();
  init_oxm_tcp_dst();
  init_oxm_tcp_src();
  init_oxm_tunnel_id();
  init_oxm_udp_dst();
  init_oxm_udp_src();
  init_oxm_vlan_pcp();
  init_oxm_vlan_vid();
  init_oxm_pbb_isid();
}


uint32_t
oxm_attr_field( const bool attr, const enum oxm_ofb_match_fields oxm_type ) {
  uint32_t field = 0;

  for ( uint32_t i = 0; i < nr_oxm && !field; i++ ) {
    field = oxm_arr[ i ]->oxm_attr_field( attr, oxm_type );
  }
  return field;
}


uint16_t
oxm_length( const uint16_t type ) {
  for ( uint32_t i = 0; i < nr_oxm; i++ ) {
    if ( oxm_arr[ i ]->type == type ) {
      return oxm_arr[ i ]->length;
    }
  }
  return 0;
}


uint16_t
match_length( const match *match ) {
  assert( match );
  uint16_t length = 0;
  
  for ( uint32_t i  = 0; i < nr_oxm; i++ ) {
    length = ( uint16_t )( length + oxm_arr[ i ]->match_length( match ) );
  }
  return length;
}


static uint16_t
_pack_oxm( oxm_match_header *hdr, const match *match ) {
  int pack_len = 0;
  for ( uint32_t i = 0; i < nr_oxm; i++ ) {
    pack_len += oxm_arr[ i ]->pack( hdr, match );
  }
  return ( uint16_t ) pack_len;
}
uint16_t ( *pack_oxm )( oxm_match_header *hdr, const match *match ) = _pack_oxm;


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
