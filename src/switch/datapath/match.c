/*
 * Copyright (C) 2012-2013 NEC Corporation
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


#include <linux/if_ether.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include "match.h"


static void
init_match8( match8 *match ) {
  assert( match != NULL );

  memset( match, 0, sizeof( match8 ) );

  match->value = 0;
  match->mask = UINT8_MAX;
  match->valid = false;
}


static void
init_match16( match16 *match ) {
  assert( match != NULL );

  memset( match, 0, sizeof( match16 ) );

  match->value = 0;
  match->mask = UINT16_MAX;
  match->valid = false;
}


static void
init_match32( match32 *match ) {
  assert( match != NULL );

  memset( match, 0, sizeof( match32 ) );

  match->value = 0;
  match->mask = UINT32_MAX;
  match->valid = false;
}


static void
init_match64( match64 *match ) {
  assert( match != NULL );

  memset( match, 0, sizeof( match64 ) );

  match->value = 0;
  match->mask = UINT64_MAX;
  match->valid = false;
}


static void
init_match( match *new_match ) {
  assert( new_match != NULL );

  memset( new_match, 0, sizeof( match ) );

  init_match16( &new_match->arp_opcode );
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    init_match8( &( new_match->arp_sha[ i ] ) );
  }
  init_match32( &new_match->arp_spa );
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    init_match8( &( new_match->arp_tha[ i ] ) );
  }
  init_match32( &new_match->arp_tpa );
  init_match32( &new_match->in_phy_port );
  init_match32( &new_match->in_port );
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    init_match8( &( new_match->eth_dst[ i ] ) );
  }
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    init_match8( &( new_match->eth_src[ i ] ) );
  }
  init_match16( &new_match->eth_type );
  init_match8( &new_match->icmpv4_code );
  init_match8( &new_match->icmpv4_type );
  init_match8( &new_match->icmpv6_code );
  init_match8( &new_match->icmpv6_type );
  init_match8( &new_match->ip_dscp );
  init_match8( &new_match->ip_ecn );
  init_match8( &new_match->ip_proto );
  init_match32( &new_match->ipv4_dst );
  init_match32( &new_match->ipv4_src );
  for ( int i = 0; i < IPV6_ADDRLEN; i++ ) {
    init_match8( &( new_match->ipv6_dst[ i ] ) );
  }
  init_match16( &new_match->ipv6_exthdr );
  init_match32( &new_match->ipv6_flabel );
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    init_match8( &( new_match->ipv6_nd_sll[ i ] ) );
  }
  for ( int i = 0; i < IPV6_ADDRLEN; i++ ) {
    init_match8( &( new_match->ipv6_nd_target[ i ] ) );
  }
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    init_match8( &( new_match->ipv6_nd_tll[ i ] ) );
  }
  for ( int i = 0; i < IPV6_ADDRLEN; i++ ) {
    init_match8( &( new_match->ipv6_src[ i ] ) );
  }
  init_match64( &new_match->metadata );
  init_match8( &new_match->mpls_bos );
  init_match32( &new_match->mpls_label );
  init_match8( &new_match->mpls_tc );
  init_match16( &new_match->sctp_dst );
  init_match16( &new_match->sctp_src );
  init_match16( &new_match->tcp_dst );
  init_match16( &new_match->tcp_src );
  init_match64( &new_match->tunnel_id );
  init_match16( &new_match->udp_dst );
  init_match16( &new_match->udp_src );
  init_match8( &new_match->vlan_pcp );
  init_match16( &new_match->vlan_vid );
  init_match32( &new_match->pbb_isid );
}


match *
create_match() {
  match *new_match = xmalloc( sizeof( match ) );

  init_match( new_match );

  return new_match;
}


void
delete_match( match *match ) {
  assert( match != NULL );

  xfree( match );
}


match *
duplicate_match( const match *src ) {
  if ( src == NULL ) {
    return NULL;
  }

  match *dst = xmalloc( sizeof( match ) );
  memcpy( dst, src, sizeof( match ) );

  return dst;
}


OFDPE
validate_match( match *match ) {
  assert( match != NULL );

  // FIXME: reimplement this function properly.

  if ( match->in_phy_port.valid && !match->in_port.valid ) {
    return ERROR_OFDPE_BAD_MATCH_BAD_PREREQ;
  }
  if ( match->vlan_pcp.valid && !match->vlan_vid.valid ) {
    return ERROR_OFDPE_BAD_MATCH_BAD_PREREQ;
  }
  if ( match->ip_dscp.valid || match->ip_ecn.valid || match->ip_proto.valid ) {
    if ( match->eth_type.value != ETH_ETHTYPE_IPV4 && match->eth_type.value != ETH_ETHTYPE_IPV6 ) {
      return ERROR_OFDPE_BAD_MATCH_BAD_PREREQ;
    }
  }

  if ( match->ipv4_src.valid || match->ipv4_dst.valid ) {
    if ( !match->eth_type.valid || match->eth_type.value != ETH_ETHTYPE_IPV4 ) {
      return ERROR_OFDPE_BAD_MATCH_BAD_PREREQ;
    }
  }

  if ( match->tcp_src.valid || match->tcp_dst.valid ) {
    if ( !match->ip_proto.valid || match->ip_proto.value != IPPROTO_TCP ) {
      return ERROR_OFDPE_BAD_MATCH_BAD_PREREQ;
    }
  }

  if ( match->udp_src.valid || match->udp_dst.valid ) {
    if ( !match->ip_proto.valid || match->ip_proto.value != IPPROTO_UDP ) {
      return ERROR_OFDPE_BAD_MATCH_BAD_PREREQ;
    }
  }

  if ( match->sctp_src.valid || match->sctp_dst.valid ) {
    if ( !match->ip_proto.valid || match->ip_proto.value != IPPROTO_SCTP ) {
      return ERROR_OFDPE_BAD_MATCH_BAD_PREREQ;
    }
  }

  if ( match->icmpv4_type.valid || match->icmpv4_code.valid ) {
    if ( !match->ip_proto.valid || match->ip_proto.value != IPPROTO_ICMP ) {
      return ERROR_OFDPE_BAD_MATCH_BAD_PREREQ;
    }
  }

  if ( match->arp_opcode.valid || match->arp_spa.valid || match->arp_tpa.valid ||
       match->arp_sha[ 0 ].valid || match->arp_tha[ 0 ].valid ) {
    if ( !match->eth_type.valid || match->eth_type.value != ETH_ETHTYPE_ARP ) {
      return ERROR_OFDPE_BAD_MATCH_BAD_PREREQ;
    }
  }

  if ( match->ipv6_src[ 0 ].valid || match->ipv6_dst[ 0 ].valid || match->ipv6_flabel.valid || match->ipv6_exthdr.valid ) {
    if ( !match->eth_type.valid || match->eth_type.value != ETH_ETHTYPE_IPV6 ) {
      return ERROR_OFDPE_BAD_MATCH_BAD_PREREQ;
    }
  }

  if ( match->icmpv6_type.valid || match->icmpv6_code.valid ) {
    if ( !match->ip_proto.valid || match->ip_proto.value != IPPROTO_ICMPV6 ) {
      return ERROR_OFDPE_BAD_MATCH_BAD_PREREQ;
    }
  }

  if ( match->ipv6_nd_target[ 0 ].valid ) {
    if ( !match->icmpv6_type.valid ||
         ( match->icmpv6_type.value != ND_NEIGHBOR_SOLICIT && match->icmpv6_type.value != ND_NEIGHBOR_ADVERT ) ) {
      return ERROR_OFDPE_BAD_MATCH_BAD_PREREQ;
    }
  }

  if ( match->ipv6_nd_sll[ 0 ].valid ) {
    if ( !match->icmpv6_type.valid || match->icmpv6_type.value != ND_NEIGHBOR_SOLICIT ) {
      return ERROR_OFDPE_BAD_MATCH_BAD_PREREQ;
    }
  }

  if ( match->ipv6_nd_tll[ 0 ].valid ) {
    if ( !match->icmpv6_type.valid || match->icmpv6_type.value != ND_NEIGHBOR_ADVERT ) {
      return ERROR_OFDPE_BAD_MATCH_BAD_PREREQ;
    }
  }

  if ( match->mpls_label.valid || match->mpls_tc.valid || match->mpls_bos.valid ) {
    if ( !match->eth_type.valid || ( match->eth_type.value != ETH_P_MPLS_UC && match->eth_type.value != ETH_P_MPLS_MC ) ) {
      return ERROR_OFDPE_BAD_MATCH_BAD_PREREQ;
    }
  }

  if ( match->pbb_isid.valid ) {
    if ( !match->eth_type.valid || match->eth_type.value != ETH_P_8021AH ) {
      return ERROR_OFDPE_BAD_MATCH_BAD_PREREQ;
    }
  }

  return OFDPE_SUCCESS;
}


static bool
compare_match8_strict( const match8 x, const match8 y ) {
  if ( x.valid != y.valid ) {
    return false;
  }
  if ( !x.valid || ( x.value == y.value && x.mask == y.mask ) ) {
    return true;
  }
  return false;
}


static bool
compare_match16_strict( const match16 x, const match16 y ) {
  if ( x.valid != y.valid ) {
    return false;
  }
  if ( !x.valid || ( x.value == y.value && x.mask == y.mask ) ) {
    return true;
  }
  return false;
}


static bool
compare_match32_strict( const match32 x, const match32 y ) {
  if ( x.valid != y.valid ) {
    return false;
  }
  if ( !x.valid || ( x.value == y.value && x.mask == y.mask ) ) {
    return true;
  }
  return false;
}


static bool
compare_match64_strict( const match64 x, const match64 y ) {
  if ( x.valid != y.valid ) {
    return false;
  }
  if ( !x.valid || ( x.value == y.value && x.mask == y.mask ) ) {
    return true;
  }
  return false;
}


bool
compare_match_strict( const match *x, const match *y ) {
  assert( x != NULL );
  assert( y != NULL );

  if ( !compare_match16_strict( x->arp_opcode, y->arp_opcode ) ) {
    return false;
  }
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    if ( !compare_match8_strict( x->arp_sha[ i ], y->arp_sha[ i ] ) ) {
      return false;
    }
  }
  if ( !compare_match32_strict( x->arp_spa, y->arp_spa ) ) {
    return false;
  }
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    if ( !compare_match8_strict( x->arp_tha[ i ], y->arp_tha[ i ] ) ) {
      return false;
    }
  }
  if ( !compare_match32_strict( x->arp_tpa, y->arp_tpa ) ) {
    return false;
  }
  if ( !compare_match32_strict( x->in_phy_port, y->in_phy_port ) ) {
    return false;
  }
  if ( !compare_match32_strict( x->in_port, y->in_port ) ) {
    return false;
  }

  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    if ( !compare_match8_strict( x->eth_dst[ i ], y->eth_dst[ i ] ) ) {
      return false;
    }
  }
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    if ( !compare_match8_strict( x->eth_src[ i ], y->eth_src[ i ] ) ) {
      return false;
    }
  }

  if ( !compare_match16_strict( x->eth_type, y->eth_type ) ) {
    return false;
  }
  if ( !compare_match8_strict( x->icmpv4_code, y->icmpv4_code ) ) {
    return false;
  }
  if ( !compare_match8_strict( x->icmpv4_type, y->icmpv4_type ) ) {
    return false;
  }
  if ( !compare_match8_strict( x->icmpv6_code, y->icmpv6_code ) ) {
    return false;
  }
  if ( !compare_match8_strict( x->icmpv6_type, y->icmpv6_type ) ) {
    return false;
  }
  if ( !compare_match8_strict( x->ip_dscp, y->ip_dscp ) ) {
    return false;
  }
  if ( !compare_match8_strict( x->ip_ecn, y->ip_ecn ) ) {
    return false;
  }
  if ( !compare_match8_strict( x->ip_proto, y->ip_proto ) ) {
    return false;
  }
  if ( !compare_match32_strict( x->ipv4_dst, y->ipv4_dst ) ) {
    return false;
  }
  if ( !compare_match32_strict( x->ipv4_src, y->ipv4_src ) ) {
    return false;
  }

  for ( int i = 0; i < IPV6_ADDRLEN; i++ ) {
    if ( !compare_match8_strict( x->ipv6_dst[ i ], y->ipv6_dst[ i ] ) ) {
      return false;
    }
  }
  if ( !compare_match16_strict( x->ipv6_exthdr, y->ipv6_exthdr ) ) {
    return false;
  }
  if ( !compare_match32_strict( x->ipv6_flabel, y->ipv6_flabel ) ) {
    return false;
  }

  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    if ( !compare_match8_strict( x->ipv6_nd_sll[ i ], y->ipv6_nd_sll[ i ] ) ) {
      return false;
    }
  }
  for ( int i = 0; i < IPV6_ADDRLEN; i++ ) {
    if ( !compare_match8_strict( x->ipv6_nd_target[ i ], y->ipv6_nd_target[ i ] ) ) {
      return false;
    }
  }
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    if ( !compare_match8_strict( x->ipv6_nd_tll[ i ], y->ipv6_nd_tll[ i ] ) ) {
      return false;
    }
  }
  for ( int i = 0; i < IPV6_ADDRLEN; i++ ) {
    if ( !compare_match8_strict( x->ipv6_src[ i ], y->ipv6_src[ i ] ) ) {
      return false;
    }
  }

  if ( !compare_match64_strict( x->metadata, y->metadata ) ) {
    return false;
  }
  if ( !compare_match8_strict( x->mpls_bos, y->mpls_bos ) ) {
    return false;
  }
  if ( !compare_match32_strict( x->mpls_label, y->mpls_label ) ) {
    return false;
  }
  if ( !compare_match8_strict( x->mpls_tc, y->mpls_tc ) ) {
    return false;
  }
  if ( !compare_match16_strict( x->sctp_dst, y->sctp_dst ) ) {
    return false;
  }
  if ( !compare_match16_strict( x->sctp_src, y->sctp_src ) ) {
    return false;
  }
  if ( !compare_match16_strict( x->tcp_dst, y->tcp_dst ) ) {
    return false;
  }
  if ( !compare_match16_strict( x->tcp_src, y->tcp_src ) ) {
    return false;
  }
  if ( !compare_match64_strict( x->tunnel_id, y->tunnel_id ) ) {
    return false;
  }
  if ( !compare_match16_strict( x->udp_dst, y->udp_dst ) ) {
    return false;
  }
  if ( !compare_match16_strict( x->udp_src, y->udp_src ) ) {
    return false;
  }
  if ( !compare_match8_strict( x->vlan_pcp, y->vlan_pcp ) ) {
    return false;
  }
  if ( !compare_match16_strict( x->vlan_vid, y->vlan_vid ) ) {
    return false;
  }
  if ( !compare_match32_strict( x->pbb_isid, y->pbb_isid ) ) {
    return false;
  }

  return true;
}


static bool
compare_match8( const match8 narrow, const match8 wide ) {
  if ( !wide.valid ) {
    return true;
  }
  if ( !narrow.valid ) {
    return false;
  }

  uint8_t mask = narrow.mask & wide.mask;
  if ( ( narrow.value & mask ) == ( wide.value & wide.mask ) ) {
    return true;
  }

  return false;
}


static bool
compare_match16( const match16 narrow, const match16 wide ) {
  if ( !wide.valid ) {
    return true;
  }
  if ( !narrow.valid ) {
    return false;
  }

  uint16_t mask = narrow.mask & wide.mask;
  if ( ( narrow.value & mask ) == ( wide.value & wide.mask ) ) {
    return true;
  }

  return false;
}


static bool
compare_match32( const match32 narrow, const match32 wide ) {
  if ( !wide.valid ) {
    return true;
  }
  if ( !narrow.valid ) {
    return false;
  }

  uint32_t mask = narrow.mask & wide.mask;
  if ( ( narrow.value & mask ) == ( wide.value & wide.mask ) ) {
    return true;
  }

  return false;
}


static bool
compare_match64( const match64 narrow, const match64 wide ) {
  if ( !wide.valid ) {
    return true;
  }
  if ( !narrow.valid ) {
    return false;
  }

  uint64_t mask = narrow.mask & wide.mask;
  if ( ( narrow.value & mask ) == ( wide.value & wide.mask ) ) {
    return true;
  }

  return false;
}


static bool
compare_vlan( const match16 narrow, const match16 wide ) {
  if ( !wide.valid ) { // with and without a VLAN tag
    return true;
  }
  if ( !narrow.valid ) {
    return false;
  }
  if ( wide.value == OFPVID_NONE && wide.mask == UINT16_MAX ) { // without a VLAN tag
    if ( narrow.value == OFPVID_NONE && narrow.mask == UINT16_MAX ) {
      return true;
    }
    else {
      return false;
    }
  }
  if ( wide.value == OFPVID_PRESENT && wide.mask == OFPVID_PRESENT ) { // with a VLAN tag regardless of its value
    if ( narrow.value == OFPVID_NONE && narrow.mask == UINT16_MAX ){
      return false;
    }
    else {
      return true;
    }
  }
  if ( wide.value & OFPVID_PRESENT ) { // with a VLAN tag with VID
    if ( (wide.value & ~OFPVID_PRESENT) == (narrow.value & ~OFPVID_PRESENT) && narrow.mask == UINT16_MAX ) {
      return true;
    }
    else {
      return false;
    }
  }
  uint16_t mask = ( uint16_t ) ( ~OFPVID_PRESENT & narrow.mask & wide.mask );
  if ( ( narrow.value & mask ) == ( wide.value & wide.mask ) ) {
    return true;
  }

  return false;
}


bool
compare_match( const match *narrow, const match *wide ) {
  assert( narrow != NULL );
  assert( wide != NULL );

  if ( !compare_match16( narrow->arp_opcode, wide->arp_opcode ) ) {
    return false;
  }
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    if ( !compare_match8( narrow->arp_sha[ i ], wide->arp_sha[ i ] ) ) {
      return false;
    }
  }
  if ( !compare_match32( narrow->arp_spa, wide->arp_spa ) ) {
    return false;
  }
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    if ( !compare_match8( narrow->arp_tha[ i ], wide->arp_tha[ i ] ) ) {
      return false;
    }
  }
  if ( !compare_match32( narrow->arp_tpa, wide->arp_tpa ) ) {
    return false;
  }
  if ( !compare_match32( narrow->in_phy_port, wide->in_phy_port ) ) {
    return false;
  }
  if ( !compare_match32( narrow->in_port, wide->in_port ) ) {
    return false;
  }

  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    if ( !compare_match8( narrow->eth_dst[ i ], wide->eth_dst[ i ] ) ) {
      return false;
    }
  }
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    if ( !compare_match8( narrow->eth_src[ i ], wide->eth_src[ i ] ) ) {
      return false;
    }
  }

  if ( !compare_match16( narrow->eth_type, wide->eth_type ) ) {
    return false;
  }
  if ( !compare_match8( narrow->icmpv4_code, wide->icmpv4_code ) ) {
    return false;
  }
  if ( !compare_match8( narrow->icmpv4_type, wide->icmpv4_type ) ) {
    return false;
  }
  if ( !compare_match8( narrow->icmpv6_code, wide->icmpv6_code ) ) {
    return false;
  }
  if ( !compare_match8( narrow->icmpv6_type, wide->icmpv6_type ) ) {
    return false;
  }
  if ( !compare_match8( narrow->ip_dscp, wide->ip_dscp ) ) {
    return false;
  }
  if ( !compare_match8( narrow->ip_ecn, wide->ip_ecn ) ) {
    return false;
  }
  if ( !compare_match8( narrow->ip_proto, wide->ip_proto ) ) {
    return false;
  }
  if ( !compare_match32( narrow->ipv4_dst, wide->ipv4_dst ) ) {
    return false;
  }
  if ( !compare_match32( narrow->ipv4_src, wide->ipv4_src ) ) {
    return false;
  }

  for ( int i = 0; i < IPV6_ADDRLEN; i++ ) {
    if ( !compare_match8( narrow->ipv6_dst[ i ], wide->ipv6_dst[ i ] ) ) {
      return false;
    }
  }
  if ( !compare_match16( narrow->ipv6_exthdr, wide->ipv6_exthdr ) ) {
    return false;
  }
  if ( !compare_match32( narrow->ipv6_flabel, wide->ipv6_flabel ) ) {
    return false;
  }

  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    if ( !compare_match8( narrow->ipv6_nd_sll[ i ], wide->ipv6_nd_sll[ i ] ) ) {
      return false;
    }
  }
  for ( int i = 0; i < IPV6_ADDRLEN; i++ ) {
    if ( !compare_match8( narrow->ipv6_nd_target[ i ], wide->ipv6_nd_target[ i ] ) ) {
      return false;
    }
  }
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    if ( !compare_match8( narrow->ipv6_nd_tll[ i ], wide->ipv6_nd_tll[ i ] ) ) {
      return false;
    }
  }
  for ( int i = 0; i < IPV6_ADDRLEN; i++ ) {
    if ( !compare_match8( narrow->ipv6_src[ i ], wide->ipv6_src[ i ] ) ) {
      return false;
    }
  }

  if ( !compare_match64( narrow->metadata, wide->metadata ) ) {
    return false;
  }
  if ( !compare_match8( narrow->mpls_bos, wide->mpls_bos ) ) {
    return false;
  }
  if ( !compare_match32( narrow->mpls_label, wide->mpls_label ) ) {
    return false;
  }
  if ( !compare_match8( narrow->mpls_tc, wide->mpls_tc ) ) {
    return false;
  }
  if ( !compare_match16( narrow->sctp_dst, wide->sctp_dst ) ) {
    return false;
  }
  if ( !compare_match16( narrow->sctp_src, wide->sctp_src ) ) {
    return false;
  }
  if ( !compare_match16( narrow->tcp_dst, wide->tcp_dst ) ) {
    return false;
  }
  if ( !compare_match16( narrow->tcp_src, wide->tcp_src ) ) {
    return false;
  }
  if ( !compare_match64( narrow->tunnel_id, wide->tunnel_id ) ) {
    return false;
  }
  if ( !compare_match16( narrow->udp_dst, wide->udp_dst ) ) {
    return false;
  }
  if ( !compare_match16( narrow->udp_src, wide->udp_src ) ) {
    return false;
  }
  if ( !compare_match8( narrow->vlan_pcp, wide->vlan_pcp ) ) {
    return false;
  }
  if ( !compare_vlan( narrow->vlan_vid, wide->vlan_vid ) ) {
    return false;
  }
  if ( !compare_match32( narrow->pbb_isid, wide->pbb_isid ) ) {
    return false;
  }

  return true;
}


void
build_match_from_packet_info( match *m, const packet_info *pinfo ) {
  assert( m != NULL );
  assert( pinfo != NULL );

  init_match( m );

  m->in_phy_port.value = pinfo->eth_in_phy_port;
  m->in_phy_port.mask = UINT32_MAX;
  m->in_phy_port.valid = true;
  m->in_port.value = pinfo->eth_in_port;
  m->in_port.mask = UINT32_MAX;
  m->in_port.valid = true;

  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    m->eth_dst[ i ].value = pinfo->eth_macda[ i ];
    m->eth_dst[ i ].mask = UINT8_MAX;
    m->eth_dst[ i ].valid = true;
  }
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    m->eth_src[ i ].value = pinfo->eth_macsa[ i ];
    m->eth_src[ i ].mask = UINT8_MAX;
    m->eth_src[ i ].valid = true;
  }

  if ( ( pinfo->format & ( ETH_DIX | ETH_8023_SNAP ) ) != 0 ) {
    m->eth_type.value = pinfo->eth_type;
    m->eth_type.mask = UINT16_MAX;
    m->eth_type.valid = true;
    if ( pinfo->eth_type == ETH_P_8021AH  ) {
      m->pbb_isid.value = pinfo->pbb_isid;
      m->pbb_isid.mask = UINT32_MAX;
      m->pbb_isid.valid = true;
    }
  }

  if ( ( pinfo->format & NW_ARP ) != 0 ) {
    m->arp_opcode.value = pinfo->arp_ar_op;
    m->arp_opcode.mask = UINT16_MAX;
    m->arp_opcode.valid = true;
    for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
      m->arp_sha[ i ].value = pinfo->arp_sha[ i ];
      m->arp_sha[ i ].mask = UINT8_MAX;
      m->arp_sha[ i ].valid = true;
    }
    m->arp_spa.value = pinfo->arp_spa;
    m->arp_spa.mask = UINT32_MAX;
    m->arp_spa.valid = true;
    for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
      m->arp_tha[ i ].value = pinfo->arp_tha[ i ];
      m->arp_tha[ i ].mask = UINT8_MAX;
      m->arp_tha[ i ].valid = true;
    }
    m->arp_tpa.value = pinfo->arp_tpa;
    m->arp_tpa.mask = UINT32_MAX;
    m->arp_tpa.valid = true;
  }

  if ( ( pinfo->format & NW_ICMPV4 ) != 0 ) {
    m->icmpv4_type.value = pinfo->icmpv4_type;
    m->icmpv4_type.mask = UINT8_MAX;
    m->icmpv4_type.valid = true;
    m->icmpv4_code.value = pinfo->icmpv4_code;
    m->icmpv4_code.mask = UINT8_MAX;
    m->icmpv4_code.valid = true;
  }

  if ( ( pinfo->format & ( NW_IPV4 | NW_IPV6 | NW_ICMPV4 | NW_ICMPV6 | NW_IGMP ) ) != 0 ) {
    m->ip_dscp.value = pinfo->ip_dscp;
    m->ip_dscp.mask = UINT8_MAX;
    m->ip_dscp.valid = true;
    m->ip_ecn.value = pinfo->ip_ecn;
    m->ip_ecn.mask = UINT8_MAX;
    m->ip_ecn.valid = true;
    m->ip_proto.value = pinfo->ip_proto;
    m->ip_proto.mask = UINT8_MAX;
    m->ip_proto.valid = true;
  }

  if ( ( pinfo->format & ( NW_IPV4 | NW_ICMPV4 | NW_IGMP ) ) != 0 ) {
    m->ipv4_dst.value = pinfo->ipv4_daddr;
    m->ipv4_dst.mask = UINT32_MAX;
    m->ipv4_dst.valid = true;
    m->ipv4_src.value = pinfo->ipv4_saddr;
    m->ipv4_src.mask = UINT32_MAX;
    m->ipv4_src.valid = true;
  }

  if ( ( pinfo->format & ( NW_IPV6 | NW_ICMPV6 ) ) != 0 ) {
    for ( int i = 0; i < IPV6_ADDRLEN; i++ ) {
      m->ipv6_dst[ i ].value = pinfo->ipv6_daddr.s6_addr[ i ];
      m->ipv6_dst[ i ].mask = UINT8_MAX;
      m->ipv6_dst[ i ].valid = true;
    }
    for ( int i = 0; i < IPV6_ADDRLEN; i++ ) {
      m->ipv6_src[ i ].value = pinfo->ipv6_saddr.s6_addr[ i ];
      m->ipv6_src[ i ].mask = UINT8_MAX;
      m->ipv6_src[ i ].valid = true;
    }

    m->ipv6_flabel.value = pinfo->ipv6_flowlabel;
    m->ipv6_flabel.mask = UINT32_MAX;
    m->ipv6_flabel.valid = true;
    m->ipv6_exthdr.value = pinfo->ipv6_exthdr;
    m->ipv6_exthdr.mask = UINT16_MAX;
    m->ipv6_exthdr.valid = true;
  }

  if ( ( pinfo->format & NW_ICMPV6 ) != 0 ) {
    m->icmpv6_code.value = pinfo->icmpv6_code;
    m->icmpv6_code.mask = UINT8_MAX;
    m->icmpv6_code.valid = true;
    m->icmpv6_type.value = pinfo->icmpv6_type;
    m->icmpv6_type.mask = UINT8_MAX;
    m->icmpv6_type.valid = true;

    if ( pinfo->icmpv6_type == ND_NEIGHBOR_SOLICIT || pinfo->icmpv6_type == ND_NEIGHBOR_ADVERT ) {
      for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
        m->ipv6_nd_sll[ i ].value = pinfo->icmpv6_nd_sll[ i ];
        m->ipv6_nd_sll[ i ].mask = UINT8_MAX;
        m->ipv6_nd_sll[ i ].valid = true;
      }
      for ( int i = 0; i < IPV6_ADDRLEN; i++ ) {
        m->ipv6_nd_target[ i ].value = pinfo->icmpv6_nd_target.s6_addr[ i ];
        m->ipv6_nd_target[ i ].mask = UINT8_MAX;
        m->ipv6_nd_target[ i ].valid = true;
      }
      for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
        m->ipv6_nd_tll[ i ].value = pinfo->icmpv6_nd_tll[ i ];
        m->ipv6_nd_tll[ i ].mask = UINT8_MAX;
        m->ipv6_nd_tll[ i ].valid = true;
      }
    }
  }

  m->metadata.value = pinfo->metadata;
  m->metadata.mask = UINT64_MAX;
  m->metadata.valid = true;

  if ( ( pinfo->format & MPLS ) != 0 ) {
    m->mpls_bos.value = pinfo->mpls_bos;
    m->mpls_bos.mask = UINT8_MAX;
    m->mpls_bos.valid = true;
    m->mpls_label.value = pinfo->mpls_label;
    m->mpls_label.mask = UINT32_MAX;
    m->mpls_label.valid = true;
    m->mpls_tc.value = pinfo->mpls_tc;
    m->mpls_tc.mask = UINT8_MAX;
    m->mpls_tc.valid = true;
  }

  if ( ( pinfo->format & TP_SCTP ) != 0 ) {
    m->sctp_dst.value = pinfo->sctp_dst_port;
    m->sctp_dst.mask = UINT16_MAX;
    m->sctp_dst.valid = true;
    m->sctp_src.value = pinfo->sctp_src_port;
    m->sctp_src.mask = UINT16_MAX;
    m->sctp_src.valid = true;
  }

  if ( ( pinfo->format & TP_TCP ) != 0 ) {
    m->tcp_dst.value = pinfo->tcp_dst_port;
    m->tcp_dst.mask = UINT16_MAX;
    m->tcp_dst.valid = true;
    m->tcp_src.value = pinfo->tcp_src_port;
    m->tcp_src.mask = UINT16_MAX;
    m->tcp_src.valid = true;
  }

  if ( ( pinfo->format & TP_UDP ) != 0 ) {
    m->udp_dst.value = pinfo->udp_dst_port;
    m->udp_dst.mask = UINT16_MAX;
    m->udp_dst.valid = true;
    m->udp_src.value = pinfo->udp_src_port;
    m->udp_src.mask = UINT16_MAX;
    m->udp_src.valid = true;
  }

  if ( ( pinfo->format & ETH_8021Q ) != 0 ) {
    m->vlan_pcp.value = pinfo->vlan_prio;
    m->vlan_pcp.mask = UINT8_MAX;
    m->vlan_pcp.valid = true;
    m->vlan_vid.value = pinfo->vlan_vid | OFPVID_PRESENT;
    m->vlan_vid.mask = UINT16_MAX;
    m->vlan_vid.valid = true;
  }
  else {
    m->vlan_vid.value = OFPVID_NONE;
    m->vlan_vid.mask = UINT16_MAX;
    m->vlan_vid.valid = true;
  }

  // tunnel_id is always valid to match.
  m->tunnel_id.value = pinfo->tunnel_id; // This value is zero if the packet was received on a physical port.
  m->tunnel_id.mask = UINT64_MAX;
  m->tunnel_id.valid = true;
}


void
build_all_wildcarded_match( match *m ) {
  assert( m != NULL );

  init_match( m );

  m->in_phy_port.mask = 0;
  m->in_phy_port.valid = true;
  m->in_port.mask = 0;
  m->in_port.valid = true;

  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    m->eth_dst[ i ].mask = 0;
    m->eth_dst[ i ].valid = true;
  }
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    m->eth_src[ i ].mask = 0;
    m->eth_src[ i ].valid = true;
  }

  m->eth_type.mask = 0;
  m->eth_type.valid = true;
  m->pbb_isid.mask = 0;
  m->pbb_isid.valid = true;

  m->arp_opcode.mask = 0;
  m->arp_opcode.valid = true;

  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    m->arp_sha[ i ].mask = 0;
    m->arp_sha[ i ].valid = true;
  }
  m->arp_spa.mask = 0;
  m->arp_spa.valid = true;
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    m->arp_tha[ i ].mask = 0;
    m->arp_tha[ i ].valid = true;
  }
  m->arp_tpa.mask = 0;
  m->arp_tpa.valid = true;

  m->icmpv4_type.mask = 0;
  m->icmpv4_type.valid = true;
  m->icmpv4_code.mask = 0;
  m->icmpv4_code.valid = true;

  m->ip_dscp.mask = 0;
  m->ip_dscp.valid = true;
  m->ip_ecn.mask = 0;
  m->ip_ecn.valid = true;
  m->ip_proto.mask = 0;
  m->ip_proto.valid = true;

  m->ipv4_dst.mask = 0;
  m->ipv4_dst.valid = true;
  m->ipv4_src.mask = 0;
  m->ipv4_src.valid = true;

  for ( int i = 0; i < IPV6_ADDRLEN; i++ ) {
    m->ipv6_dst[ i ].mask = 0;
    m->ipv6_dst[ i ].valid = true;
  }
  for ( int i = 0; i < IPV6_ADDRLEN; i++ ) {
    m->ipv6_src[ i ].mask = 0;
    m->ipv6_src[ i ].valid = true;
  }

  m->ipv6_flabel.mask = 0;
  m->ipv6_flabel.valid = true;
  m->ipv6_exthdr.mask = 0;
  m->ipv6_exthdr.valid = true;

  m->icmpv6_code.mask = 0;
  m->icmpv6_code.valid = true;
  m->icmpv6_type.mask = 0;
  m->icmpv6_type.valid = true;

  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    m->ipv6_nd_sll[ i ].mask = 0;
    m->ipv6_nd_sll[ i ].valid = true;
  }
  for ( int i = 0; i < IPV6_ADDRLEN; i++ ) {
    m->ipv6_nd_target[ i ].mask = 0;
    m->ipv6_nd_target[ i ].valid = true;
  }
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    m->ipv6_nd_tll[ i ].mask = 0;
    m->ipv6_nd_tll[ i ].valid = true;
  }

  m->metadata.mask = 0;
  m->metadata.valid = true;

  m->mpls_bos.mask = 0;
  m->mpls_bos.valid = true;
  m->mpls_label.mask = 0;
  m->mpls_label.valid = true;
  m->mpls_tc.mask = 0;
  m->mpls_tc.valid = true;

  m->sctp_dst.mask = 0;
  m->sctp_dst.valid = true;
  m->sctp_src.mask = 0;
  m->sctp_src.valid = true;

  m->tcp_dst.mask = 0;
  m->tcp_dst.valid = true;
  m->tcp_src.mask = 0;
  m->tcp_src.valid = true;

  m->udp_dst.mask = 0;
  m->udp_dst.valid = true;
  m->udp_src.mask = 0;
  m->udp_src.valid = true;

  m->vlan_pcp.mask = 0;
  m->vlan_pcp.valid = true;
  m->vlan_vid.mask = 0;
  m->vlan_vid.valid = true;

  m->tunnel_id.mask = 0;
  m->tunnel_id.valid = true;
}


static void
dump_match8( const char *prefix, const match8 *m, void dump_function( const char *format, ... ) ) {
  assert( prefix != NULL );
  assert( m != NULL );
  assert( dump_function != NULL );

  if ( !m->valid ) {
    return;
  }

  ( *dump_function )( "%s: %u/%u (%#x/%#x)%s", prefix, m->value, m->mask, m->value, m->mask, m->valid ? "" : " *** invalid ***" );
}


static void
dump_match16( const char *prefix, const match16 *m, void dump_function( const char *format, ... ) ) {
  assert( prefix != NULL );
  assert( m != NULL );
  assert( dump_function != NULL );

  if ( !m->valid ) {
    return;
  }

  ( *dump_function )( "%s: %u/%u (%#x/%#x)%s", prefix, m->value, m->mask, m->value, m->mask, m->valid ? "" : " *** invalid ***" );
}


static void
dump_match32( const char *prefix, const match32 *m, void dump_function( const char *format, ... ) ) {
  assert( prefix != NULL );
  assert( m != NULL );
  assert( dump_function != NULL );

  if ( !m->valid ) {
    return;
  }

  ( *dump_function )( "%s: %u/%u (%#x/%#x)%s", prefix, m->value, m->mask, m->value, m->mask, m->valid ? "" : " *** invalid ***" );
}


static void
dump_match64( const char *prefix, const match64 *m, void dump_function( const char *format, ... ) ) {
  assert( prefix != NULL );
  assert( m != NULL );
  assert( dump_function != NULL );

  if ( !m->valid ) {
    return;
  }

  ( *dump_function )( "%s: %" PRIu64 "/%" PRIu64 " (%#" PRIx64 "/%#" PRIx64 ")%s",
                      prefix, m->value, m->mask, m->value, m->mask, m->valid ? "" : " *** invalid ***" );
}


static void
dump_eth_addr( const char *prefix, const match8 *m, void dump_function( const char *format, ... ) ) {
  assert( prefix != NULL );
  assert( m != NULL );
  assert( dump_function != NULL );

  if ( !m->valid ) {
    return;
  }

  char addr[ 18 ];
  char mask[ 18 ];
  snprintf( addr, sizeof( addr ), "%02x:%02x:%02x:%02x:%02x:%02x",
            m[ 0 ].value, m[ 1 ].value, m[ 2 ].value, m[ 3 ].value, m[ 4 ].value, m[ 5 ].value );
  snprintf( mask, sizeof( mask ), "%02x:%02x:%02x:%02x:%02x:%02x",
            m[ 0 ].mask, m[ 1 ].mask, m[ 2 ].mask, m[ 3 ].mask, m[ 4 ].mask, m[ 5 ].mask );

  ( *dump_function )( "%s: %s/%s", prefix, addr, mask );
}


static void
dump_ipv6_addr( const char *prefix, const match8 *m, void dump_function( const char *format, ... ) ) {
  assert( prefix != NULL );
  assert( m != NULL );
  assert( dump_function != NULL );

  if ( !m->valid ) {
    return;
  }

  char addr[ INET6_ADDRSTRLEN ];
  char mask[ INET6_ADDRSTRLEN ];
  snprintf( addr, sizeof( addr ), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            m[ 0 ].value, m[ 1 ].value, m[ 2 ].value, m[ 3 ].value, m[ 4 ].value, m[ 5 ].value, m[ 6 ].value, m[ 7 ].value,
            m[ 8 ].value, m[ 9 ].value, m[ 10 ].value, m[ 11 ].value, m[ 12 ].value, m[ 13 ].value, m[ 14 ].value, m[ 15 ].value );
  snprintf( mask, sizeof( mask ), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            m[ 0 ].mask, m[ 1 ].mask, m[ 2 ].mask, m[ 3 ].mask, m[ 4 ].mask, m[ 5 ].mask, m[ 6 ].mask, m[ 7 ].mask,
            m[ 8 ].mask, m[ 9 ].mask, m[ 10 ].mask, m[ 11 ].mask, m[ 12 ].mask, m[ 13 ].mask, m[ 14 ].mask, m[ 15 ].mask );

  ( *dump_function )( "%s: %s/%s", prefix, addr, mask );
}


bool
all_wildcarded_match( const match *m ) {
  assert( m != NULL );

  match wildcarded_match;
  memset( &wildcarded_match, 0, sizeof( match ) );
  build_all_wildcarded_match( &wildcarded_match );

  match initialized_match;
  memset( &initialized_match, 0, sizeof( match ) );
  init_match( &initialized_match );

  match empty_match;
  memset( &empty_match, 0, sizeof( match ) );

  return compare_match_strict( m, &wildcarded_match ) || compare_match_strict( m, &initialized_match ) || compare_match_strict( m, &empty_match );
}


void
dump_match( const match *m, void dump_function( const char *format, ... ) ) {
  assert( m != NULL );
  assert( dump_function != NULL );

  dump_match16( "arp_opcode", &m->arp_opcode, dump_function );
  dump_eth_addr( "arp_sha", m->arp_sha, dump_function );
  dump_match32( "arp_spa", &m->arp_spa, dump_function );
  dump_eth_addr( "arp_tha", m->arp_tha, dump_function );
  dump_eth_addr( "eth_dst", m->eth_dst, dump_function );
  dump_eth_addr( "eth_src", m->eth_src, dump_function );
  dump_match16( "eth_type", &m->eth_type, dump_function );
  dump_match8( "icmpv4_type", &m->icmpv4_type, dump_function );
  dump_match8( "icmpv4_code", &m->icmpv4_code, dump_function );
  dump_match8( "icmpv6_type", &m->icmpv6_type, dump_function );
  dump_match8( "icmpv6_code", &m->icmpv6_code, dump_function );
  dump_match32( "in_phy_port", &m->in_phy_port, dump_function );
  dump_match32( "in_port", &m->in_port, dump_function );
  dump_match8( "ip_dscp", &m->ip_dscp, dump_function );
  dump_match8( "ip_ecn", &m->ip_ecn, dump_function );
  dump_match8( "ip_proto", &m->ip_proto, dump_function );
  dump_match32( "ipv4_src", &m->ipv4_src, dump_function );
  dump_match32( "ipv4_dst", &m->ipv4_dst, dump_function );
  dump_ipv6_addr( "ipv6_src", m->ipv6_src, dump_function );
  dump_ipv6_addr( "ipv6_dst", m->ipv6_dst, dump_function );
  dump_match16( "ipv6_exthdr", &m->ipv6_exthdr, dump_function );
  dump_match32( "ipv6_flabel", &m->ipv6_flabel, dump_function );
  dump_eth_addr( "ipv6_nd_sll", m->ipv6_nd_sll, dump_function );
  dump_ipv6_addr( "ipv6_nd_target", m->ipv6_nd_target, dump_function );
  dump_eth_addr( "ipv6_nd_tll", m->ipv6_nd_tll, dump_function );
  dump_match8( "mpls_bos", &m->mpls_bos, dump_function );
  dump_match32( "mpls_label", &m->mpls_label, dump_function );
  dump_match8( "mpls_tc", &m->mpls_tc, dump_function );
  dump_match16( "sctp_src", &m->sctp_src, dump_function );
  dump_match16( "sctp_dst", &m->sctp_dst, dump_function );
  dump_match16( "tcp_src", &m->tcp_src, dump_function );
  dump_match16( "tcp_dst", &m->tcp_dst, dump_function );
  dump_match16( "udp_src", &m->udp_src, dump_function );
  dump_match16( "udp_dst", &m->udp_dst, dump_function );
  dump_match64( "tunnel_id", &m->tunnel_id, dump_function );
  dump_match8( "vlan_pcp", &m->vlan_pcp, dump_function );
  dump_match16( "vlan_vid", &m->vlan_vid, dump_function );
  dump_match32( "pbb_isid", &m->pbb_isid, dump_function );
  dump_match64( "metadata", &m->metadata, dump_function );
}


static void
merge_match8( match8 *dst, const match8 *src ) {
  if ( src->valid ) {
    dst->value = src->value;
    dst->mask = src->mask;
    dst->valid = true;
  }
}


static void
merge_match16( match16 *dst, const match16 *src ) {
  if ( src->valid ) {
    dst->value = src->value;
    dst->mask = src->mask;
    dst->valid = true;
  }
}


static void
merge_match32( match32 *dst, const match32 *src ) {
  if ( src->valid ) {
    dst->value = src->value;
    dst->mask = src->mask;
    dst->valid = true;
  }
}


static void
merge_match64( match64 *dst, const match64 *src ) {
  if ( src->valid ) {
    dst->value = src->value;
    dst->mask = src->mask;
    dst->valid = true;
  }
}


void
merge_match( match *dst, const match *src) {
  assert( dst != NULL );
  assert( src != NULL );

  merge_match16( &dst->arp_opcode, &src->arp_opcode );
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    merge_match8( &( dst->arp_sha[ i ] ), &( src->arp_sha[ i ] ) );
  }
  merge_match32( &dst->arp_spa, &src->arp_spa );
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    merge_match8( &( dst->arp_tha[ i ] ), &( src->arp_tha[ i ] ) );
  }
  merge_match32( &dst->arp_tpa, &src->arp_tpa );
  merge_match32( &dst->in_phy_port, &src->in_phy_port );
  merge_match32( &dst->in_port, &src->in_port );
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    merge_match8( &( dst->eth_dst[ i ] ), &( src->eth_dst[ i ] ) );
  }
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    merge_match8( &( dst->eth_src[ i ] ), &( src->eth_src[ i ] ) );
  }
  merge_match16( &dst->eth_type, &src->eth_type );
  merge_match8( &dst->icmpv4_code, &src->icmpv4_code );
  merge_match8( &dst->icmpv4_type, &src->icmpv4_type );
  merge_match8( &dst->icmpv6_code, &src->icmpv6_code );
  merge_match8( &dst->icmpv6_type, &src->icmpv6_type );
  merge_match8( &dst->ip_dscp, &src->ip_dscp );
  merge_match8( &dst->ip_ecn, &src->ip_ecn );
  merge_match8( &dst->ip_proto, &src->ip_proto );
  merge_match32( &dst->ipv4_dst, &src->ipv4_dst );
  merge_match32( &dst->ipv4_src, &src->ipv4_src );
  for ( int i = 0; i < IPV6_ADDRLEN; i++ ) {
    merge_match8( &( dst->ipv6_dst[ i ] ), &( src->ipv6_dst[ i ] ) );
  }
  merge_match16( &dst->ipv6_exthdr, &src->ipv6_exthdr );
  merge_match32( &dst->ipv6_flabel, &src->ipv6_flabel );
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    merge_match8( &( dst->ipv6_nd_sll[ i ] ), &( src->ipv6_nd_sll[ i ] ) );
  }
  for ( int i = 0; i < IPV6_ADDRLEN; i++ ) {
    merge_match8( &( dst->ipv6_nd_target[ i ] ), &( src->ipv6_nd_target[ i ] ) );
  }
  for ( int i = 0; i < ETH_ADDRLEN; i++ ) {
    merge_match8( &( dst->ipv6_nd_tll[ i ] ), &( src->ipv6_nd_tll[ i ] ) );
  }
  for ( int i = 0; i < IPV6_ADDRLEN; i++ ) {
    merge_match8( &( dst->ipv6_src[ i ] ), &( src->ipv6_src[ i ] ) );
  }
  merge_match64( &dst->metadata, &src->metadata );
  merge_match8( &dst->mpls_bos, &src->mpls_bos );
  merge_match32( &dst->mpls_label, &src->mpls_label );
  merge_match8( &dst->mpls_tc, &src->mpls_tc );
  merge_match16( &dst->sctp_dst, &src->sctp_dst );
  merge_match16( &dst->sctp_src, &src->sctp_src );
  merge_match16( &dst->tcp_dst, &src->tcp_dst );
  merge_match16( &dst->tcp_src, &src->tcp_src );
  merge_match64( &dst->tunnel_id, &src->tunnel_id );
  merge_match16( &dst->udp_dst, &src->udp_dst );
  merge_match16( &dst->udp_src, &src->udp_src );
  merge_match8( &dst->vlan_pcp, &src->vlan_pcp );
  merge_match16( &dst->vlan_vid, &src->vlan_vid );
  merge_match32( &dst->pbb_isid, &src->pbb_isid );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
