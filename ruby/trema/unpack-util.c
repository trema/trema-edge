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


#include <assert.h>
#include "trema.h"
#include "ruby.h"
#include "hash-util.h"
#include "conversion-util.h"


void
unpack_port( const struct ofp_port *port_desc, VALUE r_attributes ) {
  HASH_SET( r_attributes, "port_no", UINT2NUM( port_desc->port_no ) );
  VALUE hw_addr = rb_funcall( rb_eval_string( "Trema::Mac" ), rb_intern( "new" ), 1, ULL2NUM( mac_to_uint64( port_desc->hw_addr ) ) );
  HASH_SET( r_attributes, "hw_addr", hw_addr );
  HASH_SET( r_attributes, "name", rb_str_new2( port_desc->name ) );
  HASH_SET( r_attributes, "config", UINT2NUM( port_desc->config ) );
  HASH_SET( r_attributes, "state", UINT2NUM( port_desc->state ) );
  HASH_SET( r_attributes, "curr", UINT2NUM( port_desc->curr ) );
  HASH_SET( r_attributes, "advertised", UINT2NUM( port_desc->advertised ) );
  HASH_SET( r_attributes, "supported", UINT2NUM( port_desc->supported ) );
  HASH_SET( r_attributes, "peer", UINT2NUM( port_desc->peer ) );
  HASH_SET( r_attributes, "curr_speed", UINT2NUM( port_desc->curr_speed ) );
  HASH_SET( r_attributes, "max_speed", UINT2NUM( port_desc->max_speed ) );
}


static VALUE
eth_addr_to_r( const uint8_t *addr ) {
  return rb_funcall( rb_eval_string( "Trema::Mac" ), rb_intern( "new" ), 1, ULL2NUM( mac_to_uint64( addr ) ) );
}


static VALUE
ipv6_addr_to_r( const struct in6_addr *addr ) {
  char ipv6_str[ INET6_ADDRSTRLEN ];
  memset( ipv6_str, '\0', sizeof( ipv6_str ) );

  VALUE r_ipv6_addr = Qnil;
  if ( inet_ntop( AF_INET6, addr, ipv6_str, sizeof( ipv6_str ) ) != NULL ) {
    r_ipv6_addr = rb_funcall( rb_eval_string( "IPAddr" ), rb_intern( "new" ), 1, rb_str_new2( ipv6_str ) );
  }
  return r_ipv6_addr;
}


static VALUE
ipv4_addr_to_r( const uint32_t *addr ) {
  return rb_funcall( rb_eval_string( "IPAddr" ), rb_intern( "new" ), 2, UINT2NUM( *addr ), rb_eval_string( "Socket::AF_INET" )  );
}


static void
unpack_metadata( const oxm_match_header *hdr, VALUE r_attributes ) {
  const uint64_t *value = ( const uint64_t * ) ( ( const char * ) hdr + sizeof ( oxm_match_header ) );

  if ( *hdr == OXM_OF_METADATA ) {
    HASH_SET( r_attributes, "metadata", ULL2NUM( *value ) );
  }
  if ( *hdr == OXM_OF_METADATA_W ) {
    value = ( const uint64_t * ) ( ( const char * ) hdr + sizeof ( oxm_match_header ) );
    const uint64_t *mask = ( const uint64_t * ) ( ( const char * ) value + sizeof ( uint64_t ) );
    HASH_SET( r_attributes, "metadata", ULL2NUM( *value ) );
    HASH_SET( r_attributes, "metadata_mask", ULL2NUM( *mask ) );
  }
}


static void
unpack_eth_addr( const oxm_match_header *hdr, VALUE r_attributes ) {
  const uint8_t *addr = ( const uint8_t * ) hdr + sizeof ( oxm_match_header );
  const uint8_t *mask;

  VALUE r_addr = eth_addr_to_r( addr );
  switch( *hdr ) {
    case OXM_OF_ETH_DST:
      HASH_SET( r_attributes, "eth_dst", r_addr );
      break;
    case OXM_OF_ETH_DST_W: {
        HASH_SET( r_attributes, "eth_dst", r_addr );
        mask = addr + ( sizeof ( uint8_t ) * ETH_ADDRLEN );

        VALUE r_mask = eth_addr_to_r( mask );
        HASH_SET( r_attributes, "eth_dst_mask", r_mask );
      }
      break;
    case OXM_OF_ETH_SRC:
      HASH_SET( r_attributes, "eth_src", r_addr );
      break;
    case OXM_OF_ETH_SRC_W: {
        HASH_SET( r_attributes, "eth_src", r_addr );

        mask = addr + ( sizeof ( uint8_t ) * ETH_ADDRLEN );
        VALUE r_mask = eth_addr_to_r( mask );
        HASH_SET( r_attributes, "eth_src_mask", r_mask );
      }
      break;
    default:
      assert( 0 );
      break;
  }
}


static void
unpack_vlan_vid( const oxm_match_header *hdr, VALUE r_attributes ) {
  const uint16_t *value = ( const uint16_t * ) ( ( const char * ) hdr + sizeof ( oxm_match_header ) );
  if ( *hdr == OXM_OF_VLAN_VID ) {
    if ( ( *value & OFPVID_PRESENT ) != 0 ) {
      HASH_SET( r_attributes, "vlan_vid", UINT2NUM( ( *value & ( uint16_t ) ~OFPVID_PRESENT ) ) );
    }
    else if ( *value == OFPVID_NONE ) {
      HASH_SET( r_attributes, "vlan_vid", UINT2NUM( 0 ) );
    }
    else {
      HASH_SET( r_attributes, "vlan_vid", UINT2NUM( *value ) );
    }
  }
  if ( *hdr == OXM_OF_VLAN_VID_W ) {
    const uint16_t *mask = ( const uint16_t * ) ( ( const char * ) value + sizeof ( uint16_t ) );
    if ( *value == OFPVID_PRESENT && *mask == OFPVID_PRESENT ) {
      HASH_SET( r_attributes, "vlan_vid", UINT2NUM( 0 ) );
      HASH_SET( r_attributes, "vlan_vid_mask", UINT2NUM( 0 ) );
    }
    else {
      HASH_SET( r_attributes, "vlan_vid", UINT2NUM( *value ) );
      HASH_SET( r_attributes, "vlan_vid_mask", UINT2NUM( *mask ) );
    }
  }
}


static void
unpack_ipv4_addr( const oxm_match_header *hdr, VALUE r_attributes ) {
  const uint32_t *addr = ( const uint32_t * ) ( ( const uint8_t * ) hdr + sizeof ( oxm_match_header ) );
  const uint32_t *mask;

  VALUE r_addr = ipv4_addr_to_r( addr );
  switch ( *hdr ) {
    case OXM_OF_IPV4_SRC: {
      HASH_SET( r_attributes, "ipv4_src", r_addr );
    }
    break;
    case OXM_OF_IPV4_SRC_W: {
      mask = ( const uint32_t * ) ( ( const uint8_t * ) addr + sizeof( uint32_t ) );
      VALUE r_mask = ipv4_addr_to_r( mask );

      HASH_SET( r_attributes, "ipv4_src", r_addr );
      HASH_SET( r_attributes, "ipv4_src_mask", r_mask );
    }
    break;
    case OXM_OF_IPV4_DST: {
      HASH_SET( r_attributes, "ipv4_dst", r_addr );
    }
    break;
    case OXM_OF_IPV4_DST_W: {
      mask = ( const uint32_t * ) ( ( const uint8_t * ) addr + sizeof( uint32_t ) );
      VALUE r_mask = ipv4_addr_to_r( mask );

      HASH_SET( r_attributes, "ipv4_dst", r_addr );
      HASH_SET( r_attributes, "ipv4_dst_mask", r_mask );
    }
    break;
    default:
      assert( 0 );
    break;
  }
}


static void
unpack_tcp_port( const oxm_match_header *hdr, VALUE r_attributes ) {
  const uint16_t *value = ( const uint16_t * ) ( ( const char * ) hdr + sizeof ( oxm_match_header ) );

  if ( *hdr == OXM_OF_TCP_SRC ) {
    HASH_SET( r_attributes, "tcp_src", UINT2NUM( *value ) );
  }
  if ( *hdr == OXM_OF_TCP_DST ) {
    HASH_SET( r_attributes, "tcp_dst", UINT2NUM( *value ) );
  }
}


static void
unpack_udp_port( const oxm_match_header *hdr, VALUE r_attributes ) {
  const uint16_t *value = ( const uint16_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );

  if ( *hdr == OXM_OF_UDP_SRC ) {
    HASH_SET( r_attributes, "transport_port", UINT2NUM( *value ) );
    HASH_SET( r_attributes, "udp_src", UINT2NUM( *value ) );
  }
  if ( *hdr == OXM_OF_UDP_DST ) {
    HASH_SET( r_attributes, "transport_port", UINT2NUM( *value ) );
    HASH_SET( r_attributes, "udp_dst", UINT2NUM( *value ) );
  }
}


static void
unpack_sctp_port( const oxm_match_header *hdr, VALUE r_attributes ) {
  const uint16_t *value = ( const uint16_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );

  if ( *hdr == OXM_OF_SCTP_SRC ) {
    HASH_SET( r_attributes, "sctp_src", UINT2NUM( *value ) );
  }
  if ( *hdr == OXM_OF_SCTP_DST ) {
    HASH_SET( r_attributes, "sctp_dst", UINT2NUM( *value ) );
  }
}


static void
unpack_arp_protocol_addr( const oxm_match_header *hdr, VALUE r_attributes ) {
  const uint32_t *addr = ( const uint32_t * ) ( ( const uint8_t * ) hdr + sizeof ( oxm_match_header ) );
  const uint32_t *mask;

  VALUE r_addr = ipv4_addr_to_r( addr );

  if ( *hdr == OXM_OF_ARP_SPA ) {
    HASH_SET( r_attributes, "arp_spa", r_addr );
  }
  if ( *hdr == OXM_OF_ARP_SPA_W ) {
    mask = ( const uint32_t * ) ( ( const uint8_t * ) addr + sizeof ( uint32_t ) );
    VALUE r_mask = ipv4_addr_to_r( mask );

    HASH_SET( r_attributes, "arp_spa", r_addr );
    HASH_SET( r_attributes, "arp_spa_mask", r_mask );
  }
  if ( *hdr == OXM_OF_ARP_TPA ) {
    HASH_SET( r_attributes, "arp_tpa", r_addr );
  }
  if ( *hdr == OXM_OF_ARP_TPA_W ) {
    mask = ( const uint32_t * ) ( ( const uint8_t * ) addr + sizeof ( uint32_t ) );
    VALUE r_mask = ipv4_addr_to_r( mask );

    HASH_SET( r_attributes, "arp_tpa", r_addr );
    HASH_SET( r_attributes, "arp_tpa_mask", r_mask );
  }
}


static void
unpack_arp_hardware_addr( const oxm_match_header *hdr, VALUE r_attributes ) {
  const uint8_t *addr = ( const uint8_t * ) hdr + sizeof( oxm_match_header );
  const uint8_t *mask;

  VALUE r_addr = eth_addr_to_r( addr );

  if ( *hdr == OXM_OF_ARP_SHA || *hdr == OXM_OF_ARP_SHA_W ) {
    HASH_SET( r_attributes, "arp_sha", r_addr );
    if ( *hdr == OXM_OF_ARP_SHA_W ) {
      mask = addr + ( sizeof ( uint8_t ) * ETH_ADDRLEN );
      VALUE r_mask = eth_addr_to_r( mask );
      HASH_SET( r_attributes, "arp_sha_mask", r_mask );
    }
  }
  if ( *hdr == OXM_OF_ARP_THA || *hdr == OXM_OF_ARP_THA_W ) {
    HASH_SET( r_attributes, "arp_tha", r_addr );
    if ( *hdr == OXM_OF_ARP_THA_W ) {
      mask = addr + ( sizeof ( uint8_t ) * ETH_ADDRLEN );
      VALUE r_mask = eth_addr_to_r( mask );
      HASH_SET( r_attributes, "arp_tha_mask", r_mask );
    }
  }
}


static void
unpack_ipv6_addr( const oxm_match_header *hdr, VALUE r_attributes ) {
  const struct in6_addr *addr = ( const struct in6_addr * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
  const struct in6_addr *mask;


  VALUE r_ipv6_addr = ipv6_addr_to_r( addr );;

  if ( *hdr == OXM_OF_IPV6_SRC || *hdr == OXM_OF_IPV6_SRC_W ) {
    HASH_SET( r_attributes, "ipv6_src", r_ipv6_addr );

    if ( *hdr == OXM_OF_IPV6_SRC_W ) {
      mask = ( const struct in6_addr * ) ( ( const char * ) addr + sizeof ( struct in6_addr ) );
      VALUE r_ipv6_mask = ipv6_addr_to_r( mask );

      HASH_SET( r_attributes, "ipv6_src_mask", r_ipv6_mask );
    }
  }
  if ( *hdr == OXM_OF_IPV6_DST || *hdr == OXM_OF_IPV6_DST_W ) {
    HASH_SET( r_attributes, "ipv6_dst", r_ipv6_addr );
    if ( *hdr == OXM_OF_IPV6_DST_W ) {
      mask = ( const struct in6_addr * ) ( ( const char * ) addr + sizeof ( struct in6_addr ) );

      VALUE r_ipv6_mask = ipv6_addr_to_r( mask );
      HASH_SET( r_attributes, "ipv6_dst_mask", r_ipv6_mask );
    }
  }
}


static void
unpack_ipv6_flabel( const oxm_match_header *hdr, VALUE r_attributes ) {
  const uint32_t *value = ( const uint32_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );

  if ( *hdr == OXM_OF_IPV6_FLABEL ) {
    HASH_SET( r_attributes, "ipv6_flabel", UINT2NUM( *value ) );
  }
  if ( *hdr == OXM_OF_IPV6_FLABEL_W ) {
    HASH_SET( r_attributes, "ipv6_flabel", UINT2NUM( *value ) );

    const uint32_t *mask = ( const uint32_t * ) ( ( const char * ) value + sizeof ( uint32_t ) );
    HASH_SET( r_attributes, "ipv6_flabel_mask", UINT2NUM( *mask ) );
  }
}


static void
unpack_ipv6_nd_addr( const oxm_match_header *hdr, VALUE r_attributes ) {
  const uint8_t *addr = ( const uint8_t * ) hdr + sizeof( oxm_match_header );

  VALUE r_addr = eth_addr_to_r( addr );

  if ( *hdr == OXM_OF_IPV6_ND_SLL ) {
    HASH_SET( r_attributes, "ipv6_nd_sll", r_addr );
  }
  if ( *hdr == OXM_OF_IPV6_ND_TLL ) {
    HASH_SET( r_attributes, "ipv6_nd_tll", r_addr );
  }
}


static void
unpack_tunnel_id( const oxm_match_header *hdr, VALUE r_attributes ) {
  const uint64_t *value = ( const uint64_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );

  if ( *hdr == OXM_OF_TUNNEL_ID ) {
    HASH_SET( r_attributes, "tunnel_id", ULL2NUM( *value ) );
  }
  if ( *hdr == OXM_OF_TUNNEL_ID_W ) {
    HASH_SET( r_attributes, "tunnel_id", ULL2NUM( *value ) );
    const uint64_t *mask = ( const uint64_t * ) ( ( const char * ) value + sizeof ( uint64_t ) );
    HASH_SET( r_attributes, "tunnel_id", ULL2NUM( *mask ) );
  }
}


static void
unpack_ipv6_exthdr( const oxm_match_header *hdr, VALUE r_attributes ) {
  const uint16_t *value = ( const uint16_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );

  if ( *hdr == OXM_OF_IPV6_EXTHDR ) {
    HASH_SET( r_attributes, "ipv6_exthdr", UINT2NUM( *value ) );
  }
  if ( *hdr == OXM_OF_IPV6_EXTHDR_W ) {
    HASH_SET( r_attributes, "ipv6_exthdr", UINT2NUM( *value ) );

    const uint16_t *mask = ( const uint16_t * ) ( ( const char * ) value + sizeof ( uint16_t ) );
    HASH_SET( r_attributes, "ipv6_exthdr_mask", UINT2NUM( *mask ) );
  }
}


void
unpack_r_match( const oxm_match_header *hdr, VALUE r_attributes ) {
  switch( *hdr ) {
    case OXM_OF_IN_PORT: {
      const uint32_t *value = ( const uint32_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      HASH_SET( r_attributes, "in_port", UINT2NUM( *value ) );
    }
    break;
    case OXM_OF_IN_PHY_PORT: {
      const uint32_t *value = ( const uint32_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      HASH_SET( r_attributes, "in_phy_port", UINT2NUM( *value ) );
    }
    break;
    case OXM_OF_METADATA:
    case OXM_OF_METADATA_W: {
      unpack_metadata( hdr, r_attributes );
    }
    break;
    case OXM_OF_ETH_DST:
    case OXM_OF_ETH_DST_W:
    case OXM_OF_ETH_SRC:
    case OXM_OF_ETH_SRC_W: {
      unpack_eth_addr( hdr, r_attributes );
    }
    break;
    case OXM_OF_ETH_TYPE: {
      const uint16_t *value = ( const uint16_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      HASH_SET( r_attributes, "eth_type", UINT2NUM( *value ) );
    }
    break;
    case OXM_OF_VLAN_VID:
    case OXM_OF_VLAN_VID_W: {
      unpack_vlan_vid( hdr, r_attributes );
    }
    break;
    case OXM_OF_VLAN_PCP: {
      const uint8_t *value = ( const uint8_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      HASH_SET( r_attributes, "vlan_pcp", UINT2NUM( *value ) );
    }
    break;
    case OXM_OF_IP_DSCP: {
      const uint8_t *value = ( const uint8_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      HASH_SET( r_attributes, "ip_dscp", UINT2NUM( *value ) );
    }
    break;
    case OXM_OF_IP_ECN: {
      const uint8_t *value = ( const uint8_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      HASH_SET( r_attributes, "ip_ecn", UINT2NUM( *value ) );
    }
    break;
    case OXM_OF_IP_PROTO: {
      const uint8_t *value = ( const uint8_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      HASH_SET( r_attributes, "ip_proto", UINT2NUM( *value ) );
    }
    break;
    case OXM_OF_IPV4_SRC:
    case OXM_OF_IPV4_SRC_W:
    case OXM_OF_IPV4_DST:
    case OXM_OF_IPV4_DST_W: {
      unpack_ipv4_addr( hdr, r_attributes );
    }
    break;
    case OXM_OF_TCP_SRC:
    case OXM_OF_TCP_DST: {
      unpack_tcp_port( hdr, r_attributes );
    }
    break;
    case OXM_OF_UDP_SRC:
    case OXM_OF_UDP_DST: {
      unpack_udp_port( hdr, r_attributes );
    }
    break;
    case OXM_OF_SCTP_SRC:
    case OXM_OF_SCTP_DST: {
      unpack_sctp_port( hdr, r_attributes );
    }
    break;
    case OXM_OF_ICMPV4_TYPE: {
      const uint8_t *value = ( const uint8_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      HASH_SET( r_attributes, "icmpv4_type", UINT2NUM( *value ) );
    }
    break;
    case OXM_OF_ICMPV4_CODE: {
      const uint8_t *value = ( const uint8_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      HASH_SET( r_attributes, "icmpv4_code", UINT2NUM( *value ) );
    }
    break;
    case OXM_OF_ARP_OP: {
      const uint16_t *value = ( const uint16_t * ) ( ( const char * ) hdr + sizeof ( oxm_match_header ) );
      HASH_SET( r_attributes, "arp_op", UINT2NUM( *value ) );
    }
    break;
    case OXM_OF_ARP_SPA:
    case OXM_OF_ARP_SPA_W:
    case OXM_OF_ARP_TPA:
    case OXM_OF_ARP_TPA_W: {
      unpack_arp_protocol_addr( hdr, r_attributes );
    }
    break;
    case OXM_OF_ARP_SHA:
    case OXM_OF_ARP_SHA_W:
    case OXM_OF_ARP_THA:
    case OXM_OF_ARP_THA_W: {
      unpack_arp_hardware_addr( hdr, r_attributes );
    }
    break;
    case OXM_OF_IPV6_SRC:
    case OXM_OF_IPV6_SRC_W:
    case OXM_OF_IPV6_DST:
    case OXM_OF_IPV6_DST_W: {
      unpack_ipv6_addr( hdr, r_attributes );
    }
    break;
    case OXM_OF_IPV6_FLABEL:
    case OXM_OF_IPV6_FLABEL_W: {
      unpack_ipv6_flabel( hdr, r_attributes );
    }
    break;
    case OXM_OF_ICMPV6_TYPE: {
      const uint8_t *value = ( const uint8_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      HASH_SET( r_attributes, "icmpv6_type", UINT2NUM( *value ) );
    }
    break;
    case OXM_OF_ICMPV6_CODE: {
      const uint8_t *value = ( const uint8_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      HASH_SET( r_attributes, "icmpv6_code", UINT2NUM( *value ) );
    }
    break;
    case OXM_OF_IPV6_ND_TARGET: {
      const struct in6_addr *addr = ( const struct in6_addr * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      VALUE r_addr = ipv6_addr_to_r( addr );
      HASH_SET( r_attributes, "ipv6_nd_target", r_addr );
    }
    break;
    case OXM_OF_IPV6_ND_SLL:
    case OXM_OF_IPV6_ND_TLL: {
      unpack_ipv6_nd_addr( hdr, r_attributes );
    }
    break;
    case OXM_OF_MPLS_LABEL: {
      const uint32_t *value = ( const uint32_t * ) ( ( const char * ) hdr + sizeof ( oxm_match_header ) );
      HASH_SET( r_attributes, "mpls_label", UINT2NUM( *value ) );
    }
    break;
    case OXM_OF_MPLS_TC: {
      const uint8_t *value = ( const uint8_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      HASH_SET( r_attributes, "mpls_tc", UINT2NUM( *value ) );
    }
    break;
    case OXM_OF_MPLS_BOS: {
      const uint8_t *value = ( const uint8_t * ) ( ( const char * ) hdr + sizeof( oxm_match_header ) );
      HASH_SET( r_attributes, "mpls_bos", UINT2NUM( *value ) );
    }
    break;
    case OXM_OF_TUNNEL_ID:
    case OXM_OF_TUNNEL_ID_W: {
      unpack_tunnel_id( hdr, r_attributes );
    }
    break;
    case OXM_OF_IPV6_EXTHDR:
    case OXM_OF_IPV6_EXTHDR_W: {
      unpack_ipv6_exthdr( hdr, r_attributes );
    }
    break;
    default:
      error( "Undefined oxm type ( header = %#x, type = %#x, has_mask = %u, length = %u ). ",
              *hdr, OXM_TYPE( *hdr ), OXM_HASMASK( *hdr ), OXM_LENGTH( *hdr ) );
    break;
  }
}


static void
unpack_action_set_field( const struct ofp_action_set_field *src, VALUE r_action_ary ) {
  VALUE r_attributes = rb_hash_new();
  VALUE r_flexible_action = Qnil;
  uint32_t field_length = src->len - offsetof( struct ofp_action_set_field, field );

  if ( field_length > sizeof( oxm_match_header ) ) {
    const oxm_match_header *oxm_src = ( const oxm_match_header * ) src->field;
    unpack_r_match( oxm_src, r_attributes );


    VALUE r_field = UINT2NUM( OXM_FIELD( *oxm_src ) );
    VALUE r_klass = rb_funcall( rb_eval_string( "Trema::FlexibleAction" ), rb_intern( "search" ), 2, rb_str_new_cstr( "OFPXMT_OFB" ), r_field );
    
    r_flexible_action = rb_funcall( r_klass, rb_intern( "new" ), 1, r_attributes );
  }
  VALUE r_action_set = rb_ary_new();
  rb_ary_push( r_action_set, r_flexible_action );
  HASH_SET( r_attributes, "action_set", r_action_set );
  VALUE set_field = rb_funcall( rb_eval_string( "Trema::SetField" ), rb_intern( "new" ), 1, r_attributes ); 
  rb_ary_push( r_action_ary, set_field );
}


static VALUE
find_basic_action( const uint16_t type ) {
  VALUE r_type = UINT2NUM( type );
  VALUE r_klass = rb_funcall( rb_eval_string( "Trema::BasicAction" ), rb_intern( "search" ), 2, rb_str_new_cstr( "OFPAT" ), r_type );
  return r_klass;
}


static void
push_basic_action( const uint16_t type, VALUE r_action_ary, VALUE r_attributes ) {
  VALUE r_klass = find_basic_action( type );
  if ( !NIL_P( r_klass ) ) {
    VALUE r_basic_action = Qnil;
    if ( !NIL_P( r_attributes ) ) {
      r_basic_action = rb_funcall( r_klass, rb_intern( "new" ), 1, r_attributes );
    }
    else {
      r_basic_action = rb_funcall( r_klass, rb_intern( "new" ), 0 );
    }
    rb_ary_push( r_action_ary, r_basic_action );
  }
}


static void
unpack_output_action( const struct ofp_action_output *src, VALUE r_action_ary ) {
  VALUE r_attributes = rb_hash_new();
  HASH_SET( r_attributes, "port_number", UINT2NUM( src->port ) );
  HASH_SET( r_attributes, "max_len", UINT2NUM( src->max_len ) );
  push_basic_action( src->type, r_action_ary, r_attributes );
}


static void
unpack_action_header( const struct ofp_action_header *src, VALUE r_action_ary ) {
  push_basic_action( src->type, r_action_ary, Qnil );
}


static void
unpack_set_mpls_ttl_action( const struct ofp_action_mpls_ttl *src, VALUE r_action_ary ) {
  VALUE r_attributes = rb_hash_new();
  HASH_SET( r_attributes, "mpls_ttl", UINT2NUM( src->mpls_ttl ) );
  push_basic_action( src->type, r_action_ary, r_attributes );
}


static void
unpack_ether_type( const uint16_t ether_type, VALUE r_attributes ) {
  HASH_SET( r_attributes, "ether_type", UINT2NUM( ether_type ) );
}


static void
unpack_push_action( const struct ofp_action_push *src, VALUE r_action_ary ) {
  VALUE r_attributes = rb_hash_new();
  unpack_ether_type( src->ethertype, r_attributes );
  push_basic_action( src->type, r_action_ary, r_attributes );
}


static void
unpack_pop_mpls_action( const struct ofp_action_pop_mpls *src, VALUE r_action_ary ) {
  VALUE r_attributes = rb_hash_new();
  unpack_ether_type( src->ethertype, r_attributes );
  push_basic_action( src->type, r_action_ary, r_attributes );
}


static void
unpack_set_queue_action( const struct ofp_action_set_queue *src, VALUE r_action_ary ) {
  VALUE r_attributes = rb_hash_new();
  HASH_SET( r_attributes, "queue_id", UINT2NUM( src->queue_id ) );
  push_basic_action( src->type, r_action_ary, r_attributes );
}


static void
unpack_group_action( const struct ofp_action_group *src, VALUE r_action_ary ) {
  VALUE r_attributes = rb_hash_new();
  HASH_SET( r_attributes, "group_id", UINT2NUM( src->group_id ) );
  push_basic_action( src->type, r_action_ary, r_attributes );
}


static void
unpack_set_nw_ttl_action( const struct ofp_action_nw_ttl *src, VALUE r_action_ary ) {
  VALUE r_attributes = rb_hash_new();
  HASH_SET( r_attributes, "ip_ttl", UINT2NUM( src->nw_ttl ) );
  push_basic_action( src->type, r_action_ary, r_attributes );
}


static void
unpack_experimenter_action( const struct ofp_action_experimenter_header *src, VALUE r_action_ary ) {
  VALUE r_attributes = rb_hash_new();
  HASH_SET( r_attributes, "experimenter", UINT2NUM( src->experimenter ) );
  push_basic_action( src->type, r_action_ary, r_attributes );
}


void
unpack_action( const struct ofp_action_header *ac_hdr, VALUE r_action_ary ) {
  switch ( ac_hdr->type ) {
    case OFPAT_OUTPUT: {
      unpack_output_action( ( const struct ofp_action_output * ) ac_hdr, r_action_ary );
    }
    break;
    case OFPAT_COPY_TTL_OUT:
    case OFPAT_COPY_TTL_IN:
    case OFPAT_DEC_MPLS_TTL:
    case OFPAT_POP_VLAN:
    case OFPAT_POP_PBB:
    case OFPAT_DEC_NW_TTL: {
      unpack_action_header( ac_hdr, r_action_ary );
    }
    break;
    case OFPAT_SET_FIELD: {
      unpack_action_set_field( ( const struct ofp_action_set_field * ) ac_hdr, r_action_ary );
    }
    break;
    case OFPAT_SET_MPLS_TTL: {
      unpack_set_mpls_ttl_action( ( const struct ofp_action_mpls_ttl * ) ac_hdr, r_action_ary );
    }
    break;
    case OFPAT_PUSH_VLAN:
    case OFPAT_PUSH_MPLS:
    case OFPAT_PUSH_PBB: {
      unpack_push_action( ( const struct ofp_action_push  * ) ac_hdr, r_action_ary );
    }
    break;
    case OFPAT_POP_MPLS: {
      unpack_pop_mpls_action( ( const struct ofp_action_pop_mpls * ) ac_hdr, r_action_ary );
    }
    break;
    case OFPAT_SET_QUEUE: {
      unpack_set_queue_action( ( const struct ofp_action_set_queue * ) ac_hdr, r_action_ary );
    }
    break;
    case OFPAT_GROUP: {
      unpack_group_action( ( const struct ofp_action_group * ) ac_hdr, r_action_ary );
    }
    break;
    case OFPAT_SET_NW_TTL: {
      unpack_set_nw_ttl_action( ( const struct ofp_action_nw_ttl * ) ac_hdr, r_action_ary );
    }
    break;
    case OFPAT_EXPERIMENTER: {
      unpack_experimenter_action( ( const struct ofp_action_experimenter_header * ) ac_hdr, r_action_ary );
    }
    break;
    default: {
      error( "Undefined action type %u", ac_hdr->type );
    }
    break;
  }
}


static void
unpack_instruction_actions( const struct ofp_instruction_actions *instruction_actions, VALUE r_options ) {
  size_t offset = offsetof( struct ofp_instruction_actions, actions );
  size_t actions_length = instruction_actions->len - offset;
  VALUE r_action_ary = rb_ary_new();

  while ( actions_length >= sizeof( struct ofp_action_header ) ) {
    const struct ofp_action_header *ah_src = ( const struct ofp_action_header * ) ( ( const char * ) instruction_actions + offset );
    uint16_t part_length = ah_src->len;
    if ( actions_length < part_length ) {
       break;
    }
    unpack_action( ah_src, r_action_ary );
    actions_length -= part_length;
    offset += part_length;
  }
  HASH_SET( r_options, "actions", r_action_ary );
}


void
unpack_instruction( const struct ofp_instruction *instruction, VALUE r_instruction_ary ) {
  assert( instruction );

  assert( instruction->type <= OFPIT_METER || instruction->type == OFPIT_EXPERIMENTER );

  VALUE r_instruction = Qnil;
  VALUE r_options = rb_hash_new();
  switch ( instruction->type ) {
    case OFPIT_GOTO_TABLE: {
      const struct ofp_instruction_goto_table *instruction_goto_table = ( const struct ofp_instruction_goto_table * ) instruction;
      HASH_SET( r_options, "table_id", UINT2NUM( instruction_goto_table->table_id ) );
      r_instruction = rb_funcall( rb_eval_string( "Trema::GotoTable" ), rb_intern( "new" ), 1, r_options );
    }
    break;
    case OFPIT_WRITE_METADATA: {
      const struct ofp_instruction_write_metadata *instruction_write_metadata = ( const struct ofp_instruction_write_metadata * ) instruction;
      HASH_SET( r_options, "metadata", ULL2NUM( instruction_write_metadata->metadata ) );
      HASH_SET( r_options, "metadata_mask", ULL2NUM( instruction_write_metadata->metadata_mask ) );
      r_instruction = rb_funcall( rb_eval_string( "Trema::WriteMetadata" ), rb_intern( "new" ), 1, r_options );
    }
    break;
    case OFPIT_WRITE_ACTIONS: {
      const struct ofp_instruction_actions *instruction_actions = ( const struct ofp_instruction_actions * ) instruction;
      unpack_instruction_actions( instruction_actions, r_options );
      r_instruction = rb_funcall( rb_eval_string( "Trema::WriteAction" ), rb_intern( "new" ), 1, r_options );
    }
    break;
    case OFPIT_APPLY_ACTIONS: {
      const struct ofp_instruction_actions *instruction_actions = ( const struct ofp_instruction_actions * ) instruction;
      unpack_instruction_actions( instruction_actions, r_options );
      r_instruction = rb_funcall( rb_eval_string( "Trema::ApplyAction" ), rb_intern( "new" ), 1, r_options );
    }
    break;
    case OFPIT_CLEAR_ACTIONS: {
      r_instruction = rb_funcall( rb_eval_string( "Trema::ClearAction" ), rb_intern( "new" ), 0 );
    }
    break;
    case OFPIT_METER: {
      const struct ofp_instruction_meter *instruction_meter = ( const struct ofp_instruction_meter * ) instruction;
      HASH_SET( r_options, "meter_id", UINT2NUM( instruction_meter->meter_id ) );
      r_instruction = rb_funcall( rb_eval_string( "Trema::Meter" ), rb_intern( "new" ), 1, r_options );
    }
    break;
    case OFPIT_EXPERIMENTER: {
      const struct ofp_instruction_experimenter *instruction_experimenter = ( const struct ofp_instruction_experimenter * ) instruction;
      HASH_SET( r_options, "experimenter", UINT2NUM( instruction_experimenter->experimenter ) );
      uint16_t offset = sizeof( *instruction_experimenter );
      if ( instruction_experimenter->len > offset ) {
        size_t data_len = ( size_t ) ( instruction_experimenter->len - offset );
        buffer *body = alloc_buffer_with_length( data_len );
        append_back_buffer( body, data_len );
        memcpy( body->data, ( const char * ) instruction_experimenter + offset, data_len );
        HASH_SET( r_options, "user_data", buffer_to_r_array( body ) );
        free_buffer( body );
      }
      r_instruction = rb_funcall( rb_eval_string( "Trema::Experimenter" ), rb_intern( "new" ), 1, r_options );
      
    }
    break;
    default:
      error( "Invalid instruction type %u", instruction->type );
    break;
  }
  if ( !NIL_P( r_instruction ) ) {
    rb_ary_push( r_instruction_ary, r_instruction );
  }
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
