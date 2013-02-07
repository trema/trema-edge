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


#include "trema.h"
#include "ofdp.h"
#include "oxm-helper.h"
#include "oxm-interface.h"


static void
assign_ipv6_exthdr( const oxm_match_header *hdr, match *match ) {
  const uint16_t *value = ( const uint16_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
  
  if ( *hdr == OXM_OF_IPV6_EXTHDR ) {
    MATCH_ATTR_SET( ipv6_exthdr, *value )
  }
  if ( *hdr == OXM_OF_IPV6_EXTHDR_W ) {
    const uint16_t *mask = ( const uint16_t * ) ( ( const char * ) value + sizeof ( uint16_t ) );
    MATCH_ATTR_MASK_SET( ipv6_exthdr, *value, *mask )
  }
}


static void
assign_tunnel_id( const oxm_match_header *hdr, match *match ) {
  const uint64_t *value = ( const uint64_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
  
  if ( *hdr == OXM_OF_TUNNEL_ID ) {
    MATCH_ATTR_SET( tunnel_id, *value )
  }
  if ( *hdr == OXM_OF_TUNNEL_ID_W ) {
    const uint64_t *mask = ( const uint64_t * ) ( ( const char * ) value + sizeof ( uint64_t ) );
    MATCH_ATTR_MASK_SET( tunnel_id, *value, *mask )
  }
}


static void
assign_ipv6_nd_addr( const oxm_match_header *hdr, match *match ) {
  const uint8_t *addr = ( const uint8_t * ) hdr + sizeof( oxm_match_header );
  
  if ( *hdr == OXM_OF_IPV6_ND_SLL ) {
    MATCH_ARRAY_ATTR_SET( ipv6_nd_sll, addr, ETH_ADDRLEN )
  }
  if ( *hdr == OXM_OF_IPV6_ND_TLL ) {
    MATCH_ARRAY_ATTR_SET( ipv6_nd_tll, addr, ETH_ADDRLEN )
  }
}


static void
assign_ipv6_flabel( const oxm_match_header *hdr, match *match ) {
  const uint32_t *value = ( const uint32_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
  
  if ( *hdr == OXM_OF_IPV6_FLABEL ) {
    MATCH_ATTR_SET( ipv6_flabel, *value );
  }
  if ( *hdr == OXM_OF_IPV6_FLABEL_W ) {
    const uint32_t *mask = ( const uint32_t * ) ( ( const char * ) value + sizeof ( uint32_t ) );
    MATCH_ATTR_MASK_SET( ipv6_flabel, *value, *mask );
  }
}


static void
assign_ipv6_addr( const oxm_match_header *hdr, match *match ) {
  const struct in6_addr *addr = ( const struct in6_addr * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
  const struct in6_addr *mask;
  
  if ( *hdr == OXM_OF_IPV6_SRC || *hdr == OXM_OF_IPV6_SRC_W ) {
    MATCH_ARRAY_ATTR_SET( ipv6_src, addr->s6_addr, IPV6_ADDRLEN );
    if ( *hdr == OXM_OF_IPV6_SRC_W ) {
      mask = ( const struct in6_addr * ) ( ( const char * ) addr + sizeof ( struct in6_addr ) );
      MATCH_ARRAY_MASK_SET( ipv6_src, mask->s6_addr, IPV6_ADDRLEN );
    }
  }
  if ( *hdr == OXM_OF_IPV6_DST || *hdr == OXM_OF_IPV6_DST_W ) {
    MATCH_ARRAY_ATTR_SET( ipv6_dst, addr->s6_addr, IPV6_ADDRLEN );
    if ( *hdr == OXM_OF_IPV6_DST_W ) {
      mask = ( const struct in6_addr * ) ( ( const char * ) addr + sizeof ( struct in6_addr ) );
      MATCH_ARRAY_MASK_SET( ipv6_dst, mask->s6_addr, IPV6_ADDRLEN );
    }
  }
}


static void
assign_arp_hardware_addr( const oxm_match_header *hdr, match *match ) {
  const uint8_t *addr = ( const uint8_t * ) hdr + sizeof( oxm_match_header );
  const uint8_t *mask;

  if ( *hdr == OXM_OF_ARP_SHA || *hdr == OXM_OF_ARP_SHA_W ) {
    MATCH_ARRAY_ATTR_SET( arp_sha, addr, ETH_ADDRLEN )
    if ( *hdr == OXM_OF_ARP_SHA_W ) {
      mask = addr + ( sizeof ( uint8_t ) * ETH_ADDRLEN );
      MATCH_ARRAY_MASK_SET( arp_sha, mask, ETH_ADDRLEN )
    }
  }
  if ( *hdr == OXM_OF_ARP_THA || *hdr == OXM_OF_ARP_THA_W ) {
    MATCH_ARRAY_ATTR_SET( arp_tha, addr, ETH_ADDRLEN )
    if ( *hdr == OXM_OF_ARP_THA_W ) {
      mask = addr + ( sizeof ( uint8_t ) * ETH_ADDRLEN );
      MATCH_ARRAY_MASK_SET( arp_tha, mask, ETH_ADDRLEN )
    }
  }
}


static void
assign_arp_protocol_addr( const oxm_match_header *hdr, match *match ) {
  const uint32_t *addr = ( const uint32_t * ) ( ( const uint8_t * ) hdr + sizeof ( oxm_match_header ) );
  const uint32_t *mask;
  
  if ( *hdr == OXM_OF_ARP_SPA ) {
    MATCH_ATTR_SET( arp_spa, *addr );
  }
  if ( *hdr == OXM_OF_ARP_SPA_W ) {
    mask = ( const uint32_t * ) ( ( const uint8_t * ) addr + sizeof ( uint32_t ) );
    MATCH_ATTR_MASK_SET( arp_spa, *addr, *mask );
  }
  if ( *hdr == OXM_OF_ARP_TPA ) {
    MATCH_ATTR_SET( arp_tpa, *addr )
  }
  if ( *hdr == OXM_OF_ARP_TPA_W ) {
    mask = ( const uint32_t * ) ( ( const uint8_t * ) addr + sizeof ( uint32_t ) );
    MATCH_ATTR_MASK_SET( arp_tpa, *addr, *mask )
  }

}


static void
assign_sctp_port( const oxm_match_header *hdr, match *match ) {
  const uint16_t *value = ( const uint16_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
  
  if ( *hdr == OXM_OF_SCTP_SRC ) {
    MATCH_ATTR_SET( sctp_src, *value )
  }
  if ( *hdr == OXM_OF_SCTP_DST ) {
    MATCH_ATTR_SET( sctp_dst, *value )
  }
}


static void
assign_udp_port( const oxm_match_header *hdr, match *match ) {
  const uint16_t *value = ( const uint16_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
  
  if ( *hdr == OXM_OF_UDP_SRC ) {
    MATCH_ATTR_SET( udp_src, *value )
  }
  if ( *hdr == OXM_OF_UDP_DST ) {
    MATCH_ATTR_SET( udp_dst, *value )
  }
}


static void
assign_tcp_port( const oxm_match_header *hdr, match *match ) {
  const uint16_t *value = ( const uint16_t * ) ( ( const char * ) hdr + sizeof ( oxm_match_header ) );
  
  if ( *hdr == OXM_OF_TCP_SRC ) {
    MATCH_ATTR_SET( tcp_src, *value );
  }
  if ( *hdr == OXM_OF_TCP_DST ) {
    MATCH_ATTR_SET( tcp_dst, *value );
  }
}


static void
assign_ipv4_addr( const oxm_match_header *hdr, match *match ) {
  const uint32_t *addr = ( const uint32_t * ) ( ( const uint8_t * ) hdr + sizeof ( oxm_match_header ) );
  const uint32_t *mask;
  
  switch ( *hdr ) {
    case OXM_OF_IPV4_SRC: {
      MATCH_ATTR_SET( ipv4_src, *addr )
    }
    break;
    case OXM_OF_IPV4_SRC_W: {
      mask = ( const uint32_t * ) ( ( const uint8_t * ) addr + sizeof( uint32_t ) );
      MATCH_ATTR_MASK_SET( ipv4_src, *addr, *mask )
    }
    break;
    case OXM_OF_IPV4_DST: {
      MATCH_ATTR_SET( ipv4_dst, *addr )
    }
    break;
    case OXM_OF_IPV4_DST_W: {
      mask = ( const uint32_t * ) ( ( const uint8_t * ) addr + sizeof( uint32_t ) );
      MATCH_ATTR_MASK_SET( ipv4_dst, *addr, *mask )
    }
    break;
    default:
      assert( 0 );
    break;
  }
}


static void
assign_vlan_vid( const oxm_match_header *hdr, match *match ) {
  const uint16_t *value = ( const uint16_t * ) ( ( const char * ) hdr + sizeof ( oxm_match_header ) );
  if ( *hdr == OXM_OF_VLAN_VID ) {
    if ( ( *value & OFPVID_PRESENT ) != 0 ) {
      MATCH_ATTR_SET( vlan_vid, ( *value & ( uint16_t ) ~OFPVID_PRESENT ) )
    }
    else if ( *value == OFPVID_NONE ) {
      MATCH_ATTR_SET( vlan_vid, 0 )
    }
    else {
      MATCH_ATTR_SET( vlan_vid, *value )
    }
  }
  if ( *hdr == OXM_OF_VLAN_VID_W ) {
    const uint16_t *mask = ( const uint16_t * ) ( ( const char * ) value + sizeof ( uint16_t ) );
    if ( *value == OFPVID_PRESENT && *mask == OFPVID_PRESENT ) {
      MATCH_ATTR_MASK_SET( vlan_vid, 0, 0 )
    }
    else {
      MATCH_ATTR_MASK_SET( vlan_vid, *value, *mask )
    }
  }
}


static void
assign_ether_addr( const oxm_match_header *hdr, match *match ) {
  const uint8_t *addr = ( const uint8_t * ) hdr + sizeof ( oxm_match_header );
  const uint8_t *mask;
  
  switch( *hdr ) {
    case OXM_OF_ETH_DST:
      MATCH_ARRAY_ATTR_SET( eth_dst, addr, ETH_ADDRLEN )
      break;
    case OXM_OF_ETH_DST_W:
      MATCH_ARRAY_ATTR_SET( eth_dst, addr, ETH_ADDRLEN )
      mask = addr + ( sizeof ( uint8_t ) * ETH_ADDRLEN );
      MATCH_ARRAY_MASK_SET( eth_dst, mask, ETH_ADDRLEN )
      break;
    case OXM_OF_ETH_SRC:
      MATCH_ARRAY_ATTR_SET( eth_src, addr, ETH_ADDRLEN );
      break;
    case OXM_OF_ETH_SRC_W:
      MATCH_ARRAY_ATTR_SET( eth_src, addr, ETH_ADDRLEN )
      mask = addr + ( sizeof ( uint8_t ) * ETH_ADDRLEN );
      MATCH_ARRAY_MASK_SET( eth_src, mask, ETH_ADDRLEN )
      break;
    default:
      assert( 0 );
      break;
  }
}


static void
assign_metadata( const oxm_match_header *hdr, match *match ) {
  const uint64_t *value = ( const uint64_t * ) ( ( const char * ) hdr + sizeof ( oxm_match_header ) );
  
  if ( *hdr == OXM_OF_METADATA ) {
    MATCH_ATTR_SET( metadata, *value )
  }
  if ( *hdr == OXM_OF_METADATA_W ) {
    value = ( const uint64_t * ) ( ( const char * ) hdr + sizeof ( oxm_match_header ) );
    const uint64_t *mask = ( const uint64_t * ) ( ( const char * ) value + sizeof ( uint64_t ) );
    MATCH_ATTR_MASK_SET( metadata, *value, *mask )
  }
}


static void
_assign_match( match *match, const oxm_match_header *hdr ) {
  switch( *hdr ) {
    case OXM_OF_IN_PORT: {
      const uint32_t *value = ( const uint32_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      MATCH_ATTR_SET( in_port, *value )
    }
    break;
    case OXM_OF_IN_PHY_PORT: {
      const uint32_t *value = ( const uint32_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      MATCH_ATTR_SET( in_phy_port, *value );
    }
    break;
    case OXM_OF_METADATA:
    case OXM_OF_METADATA_W: {
      assign_metadata( hdr, match );
    }
    break;
    case OXM_OF_ETH_DST:
    case OXM_OF_ETH_DST_W:
    case OXM_OF_ETH_SRC:
    case OXM_OF_ETH_SRC_W: {
      assign_ether_addr( hdr, match );
    }
    break;
    case OXM_OF_ETH_TYPE: {
      const uint16_t *value = ( const uint16_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      MATCH_ATTR_SET( eth_type, *value )
    }
    break;
    case OXM_OF_VLAN_VID:
    case OXM_OF_VLAN_VID_W: {
      assign_vlan_vid( hdr, match );
    }
    break;
    case OXM_OF_VLAN_PCP: {
      const uint8_t *value = ( const uint8_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      MATCH_ATTR_SET( vlan_pcp, * value )
    }
    break;
    case OXM_OF_IP_DSCP: {
      const uint8_t *value = ( const uint8_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      MATCH_ATTR_SET( ip_dscp, *value )
    }
    break;
    case OXM_OF_IP_ECN: {
      const uint8_t *value = ( const uint8_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      MATCH_ATTR_SET( ip_ecn, *value )
    }
    break;
    case OXM_OF_IP_PROTO: {
      const uint8_t *value = ( const uint8_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      MATCH_ATTR_SET( ip_proto, *value )
    }
    break;
    case OXM_OF_IPV4_SRC:
    case OXM_OF_IPV4_SRC_W:
    case OXM_OF_IPV4_DST:
    case OXM_OF_IPV4_DST_W: {
      assign_ipv4_addr( hdr, match );
    }
    break;
    case OXM_OF_TCP_SRC:
    case OXM_OF_TCP_DST: {
      assign_tcp_port( hdr, match );
    }
    break;
    case OXM_OF_UDP_SRC:
    case OXM_OF_UDP_DST: {
      assign_udp_port( hdr, match );
    }
    break;
    case OXM_OF_SCTP_SRC:
    case OXM_OF_SCTP_DST: {
      assign_sctp_port( hdr, match );
    }
    break;
    case OXM_OF_ICMPV4_TYPE: {
      const uint8_t *value = ( const uint8_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      MATCH_ATTR_SET( icmpv4_type, *value )
    }
    break;
    case OXM_OF_ICMPV4_CODE: {
      const uint8_t *value = ( const uint8_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      MATCH_ATTR_SET( icmpv4_code, *value )
    }
    break;
    case OXM_OF_ARP_OP: {
      const uint16_t *value = ( const uint16_t * ) ( ( const char * ) hdr + sizeof ( oxm_match_header ) );
      MATCH_ATTR_SET( arp_op, *value )
    }
    break;
    case OXM_OF_ARP_SPA:
    case OXM_OF_ARP_SPA_W:
    case OXM_OF_ARP_TPA:
    case OXM_OF_ARP_TPA_W: {
      assign_arp_protocol_addr( hdr, match );
    }
    break;
    case OXM_OF_ARP_SHA:
    case OXM_OF_ARP_SHA_W:
    case OXM_OF_ARP_THA:
    case OXM_OF_ARP_THA_W: {
      assign_arp_hardware_addr( hdr, match );
    }
    break;
    case OXM_OF_IPV6_SRC:
    case OXM_OF_IPV6_SRC_W:
    case OXM_OF_IPV6_DST:
    case OXM_OF_IPV6_DST_W: {
      assign_ipv6_addr( hdr, match );
    }
    break;
    case OXM_OF_IPV6_FLABEL:
    case OXM_OF_IPV6_FLABEL_W: {
      assign_ipv6_flabel( hdr, match );
    }
    break;
    case OXM_OF_ICMPV6_TYPE: {
      const uint8_t *value = ( const uint8_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      MATCH_ATTR_SET( icmpv6_type, *value )
    }
    break;
    case OXM_OF_ICMPV6_CODE: {
      const uint8_t *value = ( const uint8_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      MATCH_ATTR_SET( icmpv6_code, *value )
    }
    break;
    case OXM_OF_IPV6_ND_TARGET: {
      const struct in6_addr *addr = ( const struct in6_addr * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      MATCH_ARRAY_ATTR_SET( ipv6_nd_target, addr->s6_addr, IPV6_ADDRLEN )
    }
    break;
    case OXM_OF_IPV6_ND_SLL:
    case OXM_OF_IPV6_ND_TLL: {
      assign_ipv6_nd_addr( hdr, match );
    }
    break;
    case OXM_OF_MPLS_LABEL: {
      const uint32_t *value = ( const uint32_t * ) ( ( const char * ) hdr + sizeof ( oxm_match_header ) );
      MATCH_ATTR_SET( mpls_label, *value )
    }
    break;
    case OXM_OF_MPLS_TC: {
      const uint8_t *value = ( const uint8_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      MATCH_ATTR_SET( mpls_tc, *value )
    }
    break;
    case OXM_OF_MPLS_BOS: {
      const uint8_t *value = ( const uint8_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      MATCH_ATTR_SET( mpls_bos, *value )
    }
    break;
    case OXM_OF_TUNNEL_ID:
    case OXM_OF_TUNNEL_ID_W: {
      assign_tunnel_id( hdr, match );
    }
    break;
    case OXM_OF_IPV6_EXTHDR:
    case OXM_OF_IPV6_EXTHDR_W: {
      assign_ipv6_exthdr( hdr, match );
    }
    break;
    default:
      error( "Undefined oxm type ( header = %#x, type = %#x, has_mask = %u, length = %u ). ",
              *hdr, OXM_TYPE( *hdr ), OXM_HASMASK( *hdr ), OXM_LENGTH( *hdr ) );
    break;
  }
}
void ( *assign_match )( match *match, const oxm_match_header *hdr ) = _assign_match;


static void
_construct_oxm( oxm_matches *oxm_match, match *match ) {
  APPEND_OXM_MATCH( in_port )
  APPEND_OXM_MATCH( in_phy_port )
  APPEND_OXM_MATCH( eth_type )
  APPEND_OXM_MATCH( ip_proto )
  if ( match->vlan_vid.valid ) {
    append_oxm_match_vlan_vid( oxm_match, match->vlan_vid.value, match->vlan_vid.mask );
  }
  APPEND_OXM_MATCH( vlan_pcp )
  APPEND_OXM_MATCH( icmpv4_type )
  APPEND_OXM_MATCH( icmpv6_type )
  APPEND_OXM_MATCH( arp_op )
  if ( match->arp_sha[ 0 ].valid ) {
    append_oxm_match_arp_sha( oxm_match, &match->arp_sha[ 0 ].value, &match->arp_sha[ 0 ].mask );
  }
  if ( match->arp_spa.valid ) {
    append_oxm_match_arp_spa( oxm_match, match->arp_spa.value, match->arp_spa.mask );
  }
  if ( match->arp_tha[ 0 ].valid ) {
    append_oxm_match_arp_tha( oxm_match, &match->arp_tha[ 0 ].value, &match->arp_tha[ 0 ].mask );
  }
  if ( match->arp_tpa.valid ) {
    append_oxm_match_arp_tpa( oxm_match, match->arp_tpa.value, match->arp_tpa.mask );
  }
  if ( match->eth_dst[ 0 ].valid ) {
    append_oxm_match_eth_dst( oxm_match, &match->eth_dst[ 0 ].value, &match->eth_dst[ 0 ].mask );
  }
  if ( match->eth_src[ 0 ].valid ) {
    append_oxm_match_eth_src( oxm_match, &match->eth_src[ 0 ].value, &match->eth_dst[ 0 ].mask );
  }
  APPEND_OXM_MATCH( icmpv4_code )
  APPEND_OXM_MATCH( ip_dscp )
  APPEND_OXM_MATCH( ip_ecn )
  if ( match->ipv4_dst.valid ) {
    append_oxm_match_ipv4_dst( oxm_match, match->ipv4_dst.value, match->ipv4_dst.mask );
  }
  if ( match->ipv4_src.valid ) {
    append_oxm_match_ipv4_src( oxm_match, match->ipv4_src.value, match->ipv4_src.mask );
  }
  struct in6_addr ipv6_addr, ipv6_mask;
  if ( match->ipv6_src[ 0 ].valid ) {
    memcpy( &ipv6_addr.s6_addr, &match->ipv6_src[ 0 ].value, IPV6_ADDRLEN );
    memcpy( &ipv6_mask.s6_addr, &match->ipv6_src[ 0 ].mask, IPV6_ADDRLEN );
    append_oxm_match_ipv6_src( oxm_match, ipv6_addr, ipv6_mask );
  }
  if ( match->ipv6_dst[ 0 ].valid ) {
    memcpy( &ipv6_addr.s6_addr, &match->ipv6_dst[ 0 ].value, IPV6_ADDRLEN );
    memcpy( &ipv6_mask.s6_addr, &match->ipv6_dst[ 0 ].mask, IPV6_ADDRLEN );
    append_oxm_match_ipv6_dst( oxm_match, ipv6_addr, ipv6_mask );
  }
  if ( match->ipv6_exthdr.valid ) {
    append_oxm_match_ipv6_exthdr( oxm_match, match->ipv6_exthdr.value, match->ipv6_exthdr.mask );
  }
  if ( match->ipv6_flabel.valid ) {
    append_oxm_match_ipv6_flabel( oxm_match, match->ipv6_flabel.value, match->ipv6_flabel.mask );
  }
  if ( match->ipv6_nd_sll[ 0 ].valid ) {
    append_oxm_match_ipv6_nd_sll( oxm_match, &match->ipv6_nd_sll[ 0 ].value );
  }
  if ( match->ipv6_nd_target[ 0 ].valid ) {
    memcpy( &ipv6_addr.s6_addr, &match->ipv6_nd_target[ 0 ].value, IPV6_ADDRLEN );
    append_oxm_match_ipv6_nd_target( oxm_match, ipv6_addr );
  }
  if ( match->ipv6_nd_tll[ 0 ].valid ) {
    append_oxm_match_ipv6_nd_tll( oxm_match, &match->ipv6_nd_tll[ 0 ].value );
  }
  if ( match->metadata.valid ) {
    append_oxm_match_metadata( oxm_match, match->metadata.value, match->metadata.mask );
  }
  APPEND_OXM_MATCH( mpls_bos )
  APPEND_OXM_MATCH( mpls_label )
  APPEND_OXM_MATCH( mpls_tc )
  APPEND_OXM_MATCH( sctp_dst )
  APPEND_OXM_MATCH( sctp_src )
  APPEND_OXM_MATCH( tcp_dst )
  APPEND_OXM_MATCH( tcp_src )
  if ( match->tunnel_id.valid ) {
    append_oxm_match_tunnel_id( oxm_match, match->tunnel_id.value, match->tunnel_id.mask );
  }
  APPEND_OXM_MATCH( udp_dst )
  APPEND_OXM_MATCH( udp_src )
}
void ( *construct_oxm )( oxm_matches *oxm_match, match *match ) = _construct_oxm;


void
_pack_ofp_match( struct ofp_match *match, const oxm_matches *matches ) {
  assert( match != NULL );

  uint16_t oxm_len = 0;
  uint16_t oxms_len = 0;
  uint16_t ofp_match_len = 0;
  uint16_t pad_len = 0;
  struct ofp_match *dst, *src;

  if ( matches != NULL && matches->n_matches ) {
    dst = match;

    list_element *elem = matches->list;
    while ( elem != NULL ) {
      src = ( struct ofp_match * ) elem->data;
      oxm_len = oxm_length( src->type );
      memcpy( dst->oxm_fields, src->oxm_fields, oxm_len );

      oxms_len = ( uint16_t ) ( oxms_len + oxm_len );
      dst = ( struct ofp_match * ) ( ( char * ) dst + oxm_len );
      elem = elem->next;
    }
  }

  ofp_match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields ) + oxms_len );
  match->type = OFPMT_OXM;
  match->length = ( uint16_t ) ( ofp_match_len ); // exclude padding length

  pad_len = ( uint16_t ) PADLEN_TO_64( ofp_match_len );
  if ( pad_len > 0 ) {
    memset( ( char * ) match + ofp_match_len, 0, pad_len );
  }
}
void ( *pack_ofp_match )( struct ofp_match *match, const oxm_matches *matches ) = _pack_ofp_match;


static uint16_t
assign_oxm_id( uint32_t *oxm_id, const uint64_t capability, enum oxm_ofb_match_fields oxm_type ) {
  uint16_t total_len = 0;

  if ( capability != 0 ) {
    *oxm_id = oxm_attr_field( true, oxm_type );
    total_len = ( uint16_t ) sizeof( uint32_t );
  }
  return total_len;
}


static uint16_t
_assign_oxm_ids( uint32_t *oxm_id, match_capabilities *match_cap ) {
  const match_capabilities c = *match_cap;
  uint16_t total_len = 0;

  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_IN_PORT, OFPXMT_OFB_IN_PORT ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_IN_PHY_PORT, OFPXMT_OFB_IN_PHY_PORT ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_METADATA, OFPXMT_OFB_METADATA ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_ETH_DST, OFPXMT_OFB_ETH_DST ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_ETH_SRC, OFPXMT_OFB_ETH_SRC ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_ETH_TYPE, OFPXMT_OFB_ETH_TYPE ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_VLAN_VID, OFPXMT_OFB_VLAN_VID ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_VLAN_PCP, OFPXMT_OFB_VLAN_PCP ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_IP_DSCP, OFPXMT_OFB_IP_DSCP ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_IP_ECN, OFPXMT_OFB_IP_ECN ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_IP_PROTO, OFPXMT_OFB_IP_PROTO ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_IPV4_SRC, OFPXMT_OFB_IPV4_SRC ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_IPV4_DST, OFPXMT_OFB_IPV4_DST ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_TCP_SRC, OFPXMT_OFB_TCP_SRC ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_TCP_DST, OFPXMT_OFB_TCP_DST ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_UDP_SRC, OFPXMT_OFB_UDP_SRC ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_UDP_DST, OFPXMT_OFB_UDP_DST ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_SCTP_SRC, OFPXMT_OFB_SCTP_SRC ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_SCTP_DST, OFPXMT_OFB_SCTP_DST ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_ICMPV4_TYPE, OFPXMT_OFB_ICMPV4_TYPE ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_ICMPV4_CODE, OFPXMT_OFB_ICMPV4_CODE ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_ARP_OP, OFPXMT_OFB_ARP_OP ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_ARP_SPA, OFPXMT_OFB_ARP_SPA ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_ARP_TPA, OFPXMT_OFB_ARP_TPA ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_ARP_SHA, OFPXMT_OFB_ARP_SHA ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_ARP_THA, OFPXMT_OFB_ARP_THA ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_IPV6_SRC, OFPXMT_OFB_IPV6_SRC ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_IPV6_DST, OFPXMT_OFB_IPV6_DST ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_IPV6_FLABEL, OFPXMT_OFB_IPV6_FLABEL ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_ICMPV6_TYPE, OFPXMT_OFB_ICMPV6_TYPE ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_ICMPV6_CODE, OFPXMT_OFB_ICMPV6_CODE ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_IPV6_ND_TARGET, OFPXMT_OFB_IPV6_ND_TARGET ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_IPV6_ND_SLL, OFPXMT_OFB_IPV6_ND_SLL ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_IPV6_ND_TLL, OFPXMT_OFB_IPV6_ND_TLL ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_MPLS_LABEL, OFPXMT_OFB_MPLS_LABEL ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_MPLS_TC, OFPXMT_OFB_MPLS_TC ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_MPLS_BOS, OFPXMT_OFB_MPLS_BOS ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_PBB_ISID, OFPXMT_OFB_PBB_ISID ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_TUNNEL_ID, OFPXMT_OFB_TUNNEL_ID ) );
  oxm_id = ( uint32_t * )( ( char * ) oxm_id + sizeof( uint32_t ) );
  total_len = ( uint16_t ) ( total_len + assign_oxm_id( oxm_id, c & MATCH_IPV6_EXTHDR, OFPXMT_OFB_IPV6_EXTHDR ) );
  
  return total_len;
}
uint16_t ( *assign_oxm_ids )( uint32_t *oxm_id, match_capabilities *match_cap ) = _assign_oxm_ids;


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
