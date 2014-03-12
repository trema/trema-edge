/*
 * Author: Yasunobu Chiba
 *
 * Copyright (C) 2013 NEC Corporation
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
#include <inttypes.h>
#include <netinet/in.h>
#include <strings.h>
#include "log.h"
#include "oxm_match.h"
#include "oxm_byteorder.h"
#include "wrapper.h"


#ifdef UNIT_TESTING

// Allow static functions to be called from unit tests.
#define static

#ifdef debug
#undef debug
#endif
#define debug mock_debug
void mock_debug( const char *format, ... );

#endif


oxm_matches *
create_oxm_matches() {
  debug( "Creating an empty matches list." );

  oxm_matches *matches = xmalloc( sizeof( oxm_matches ) );

  if ( create_list( &matches->list ) == false ) {
    assert( 0 );
  }

  matches->n_matches = 0;

  return matches;
}


bool
delete_oxm_matches( oxm_matches *matches ) {
  assert( matches != NULL );

  debug( "Deleting an matches list ( n_matches = %d ).", matches->n_matches );

  list_element *element = matches->list;
  while ( element != NULL ) {
    xfree( element->data );
    element = element->next;
  }

  delete_list( matches->list );
  xfree( matches );

  return true;
}


uint16_t
get_oxm_matches_length( const oxm_matches *matches ) {
  debug( "Calculating the total length of matches." );

  int length = 0;
  if ( matches != NULL ) {
    list_element *match = matches->list;
    while ( match != NULL ) {
      oxm_match_header *header = match->data;
      length += ( int ) ( ( uint8_t ) OXM_LENGTH( *header ) + sizeof( oxm_match_header ) );
      match = match->next;
    }
  }

  debug( "Total length of matches = %d.", length );

  assert( length <= UINT16_MAX );

  return ( uint16_t ) length;
}


static bool
append_oxm_match( oxm_matches *matches, oxm_match_header *entry ) {
  assert( matches != NULL );
  assert( entry != NULL );

  bool ret = append_to_tail( &matches->list, entry );
  if ( ret ) {
    matches->n_matches++;
  }

  return ret;
}


static bool
append_oxm_match_8( oxm_matches *matches, oxm_match_header header, uint8_t value ) {
  assert( matches != NULL );
  assert( OXM_LENGTH( header ) == sizeof( uint8_t ) );

  oxm_match_header *buf = xmalloc( sizeof( oxm_match_header ) + sizeof( uint8_t ) );
  *buf = header;
  uint8_t *v = ( uint8_t * ) ( ( char * ) buf + sizeof( oxm_match_header ) );
  *v = value;

  return append_oxm_match( matches, buf );
}


static bool
append_oxm_match_16( oxm_matches *matches, oxm_match_header header, uint16_t value ) {
  assert( matches != NULL );
  assert( OXM_LENGTH( header ) == sizeof( uint16_t ) );

  oxm_match_header *buf = xmalloc( sizeof( oxm_match_header ) + sizeof( uint16_t ) );
  *buf = header;
  uint16_t *v = ( uint16_t * ) ( ( char * ) buf + sizeof( oxm_match_header ) );
  *v = value;

  return append_oxm_match( matches, buf );
}


static bool
append_oxm_match_16w( oxm_matches *matches, oxm_match_header header, uint16_t value, uint16_t mask ) {
  assert( matches != NULL );
  assert( OXM_LENGTH( header ) == ( sizeof( uint16_t ) * 2 ) );

  oxm_match_header *buf = xmalloc( sizeof( oxm_match_header ) + ( sizeof( uint16_t ) * 2 ) );
  *buf = header;
  uint16_t *v = ( uint16_t * ) ( ( char * ) buf + sizeof( oxm_match_header ) );
  *v = value;
  v = ( uint16_t * ) ( ( char * ) v + sizeof( uint16_t ) );
  *v = mask;

  return append_oxm_match( matches, buf );
}


static bool
append_oxm_match_24( oxm_matches *matches, oxm_match_header header, uint32_t value ) {
  assert( matches != NULL );
  assert( OXM_LENGTH( header ) == 3 );

  oxm_match_header *buf = xmalloc( sizeof( oxm_match_header ) + 3 );
  *buf = header;
  uint8_t *v = ( uint8_t * ) ( ( char * ) buf + sizeof( oxm_match_header ) );
  v[ 0 ] = ( uint8_t ) ( value >> 16 ) & 0xFF;
  v[ 1 ] = ( uint8_t ) ( value >>  8 ) & 0xFF;
  v[ 2 ] = ( uint8_t ) ( value >>  0 ) & 0xFF;

  return append_oxm_match( matches, buf );
}


static bool
append_oxm_match_24w( oxm_matches *matches, oxm_match_header header, uint32_t value, uint32_t mask ) {
  assert( matches != NULL );
  assert( OXM_LENGTH( header ) == ( 3 * 2 ) );

  oxm_match_header *buf = xmalloc( sizeof( oxm_match_header ) + 3 * 2 );
  *buf = header;
  uint8_t *v = ( uint8_t * ) ( ( char * ) buf + sizeof( oxm_match_header ) );
  v[ 0 ] = ( uint8_t ) ( value >> 16 ) & 0xFF;
  v[ 1 ] = ( uint8_t ) ( value >>  8 ) & 0xFF;
  v[ 2 ] = ( uint8_t ) ( value >>  0 ) & 0xFF;
  v[ 3 ] = ( uint8_t ) ( mask  >> 16 ) & 0xFF;
  v[ 4 ] = ( uint8_t ) ( mask  >>  8 ) & 0xFF;
  v[ 5 ] = ( uint8_t ) ( mask  >>  0 ) & 0xFF;

  return append_oxm_match( matches, buf );
}

static bool
append_oxm_match_32( oxm_matches *matches, oxm_match_header header, uint32_t value ) {
  assert( matches != NULL );
  assert( OXM_LENGTH( header ) == sizeof( uint32_t ) );

  oxm_match_header *buf = xmalloc( sizeof( oxm_match_header ) + sizeof( uint32_t ) );
  *buf = header;
  uint32_t *v = ( uint32_t * ) ( ( char * ) buf + sizeof( oxm_match_header ) );
  *v = value;

  return append_oxm_match( matches, buf );
}


static bool
append_oxm_match_32w( oxm_matches *matches, oxm_match_header header, uint32_t value, uint32_t mask ) {
  assert( matches != NULL );
  assert( OXM_LENGTH( header ) == ( sizeof( uint32_t ) * 2 ) );

  oxm_match_header *buf = xmalloc( sizeof( oxm_match_header ) + sizeof( uint32_t ) * 2 );
  *buf = header;
  uint32_t *v = ( uint32_t * ) ( ( char * ) buf + sizeof( oxm_match_header ) );
  *v = value;
  v = ( uint32_t * ) ( ( char * ) v + sizeof( uint32_t ) );
  *v = mask;

  return append_oxm_match( matches, buf );
}


static bool
append_oxm_match_64( oxm_matches *matches, oxm_match_header header, uint64_t value ) {
  assert( matches != NULL );
  assert( OXM_LENGTH( header ) == sizeof( uint64_t ) );

  oxm_match_header *buf = xmalloc( sizeof( oxm_match_header ) + sizeof( uint64_t ) );
  *buf = header;
  uint64_t *v = ( uint64_t * ) ( ( char * ) buf + sizeof( oxm_match_header ) );
  *v = value;

  return append_oxm_match( matches, buf );
}


static bool
append_oxm_match_64w( oxm_matches *matches, oxm_match_header header, uint64_t value, uint64_t mask ) {
  assert( matches != NULL );
  assert( OXM_LENGTH( header ) == ( sizeof( uint64_t ) * 2 ) );

  oxm_match_header *buf = xmalloc( sizeof( oxm_match_header ) + sizeof( uint64_t ) * 2 );
  *buf = header;
  uint64_t *v = ( uint64_t * ) ( ( char * ) buf + sizeof( oxm_match_header ) );
  *v = value;
  v = ( uint64_t * ) ( ( char * ) v + sizeof( uint64_t ) );
  *v = mask;

  return append_oxm_match( matches, buf );
}


static bool
append_oxm_match_eth_addr( oxm_matches *matches, oxm_match_header header, uint8_t addr[ OFP_ETH_ALEN ] ) {
  assert( matches != NULL );
  assert( OXM_LENGTH( header ) == ( OFP_ETH_ALEN * sizeof( uint8_t ) ) );

  oxm_match_header *buf = xmalloc( sizeof( oxm_match_header ) + ( OFP_ETH_ALEN * sizeof( uint8_t ) ) );
  *buf = header;
  uint8_t *value = ( uint8_t * ) ( ( char * ) buf + sizeof( oxm_match_header ) );
  memcpy( value, addr, OFP_ETH_ALEN * sizeof( uint8_t ) );

  return append_oxm_match( matches, buf );
}


static bool
append_oxm_match_eth_addr_w( oxm_matches *matches, oxm_match_header header,
                            uint8_t addr[ OFP_ETH_ALEN ], uint8_t mask[ OFP_ETH_ALEN ] ) {
  assert( matches != NULL );
  assert( OXM_LENGTH( header ) == ( 2 * OFP_ETH_ALEN * sizeof( uint8_t ) ) );

  oxm_match_header *buf = xmalloc( sizeof( oxm_match_header ) + ( 2 * OFP_ETH_ALEN * sizeof( uint8_t ) ) );
  *buf = header;
  uint8_t *value = ( uint8_t * ) ( ( char * ) buf + sizeof( oxm_match_header ) );
  memcpy( value, addr, OFP_ETH_ALEN * sizeof( uint8_t ) );
  value = ( uint8_t * ) ( ( char * ) value + ( sizeof( uint8_t ) * OFP_ETH_ALEN ) );
  memcpy( value, mask, OFP_ETH_ALEN * sizeof( uint8_t ) );

  return append_oxm_match( matches, buf );
}


static bool
append_oxm_match_ipv6_addr( oxm_matches *matches, oxm_match_header header, struct in6_addr addr, struct in6_addr mask ) {
  assert( matches != NULL );

  uint8_t length = OXM_LENGTH( header );
  oxm_match_header *buf = xmalloc( sizeof( oxm_match_header ) + length );
  *buf = header;
  void *p = ( char * ) buf + sizeof( oxm_match_header );
  memcpy( p, &addr, sizeof( struct in6_addr ) );

  if ( OXM_HASMASK( header ) ) {
    p = ( char * ) p + sizeof( struct in6_addr );
    memcpy( p, &mask, sizeof( struct in6_addr ) );
  }

  return append_oxm_match( matches, buf );
}


bool
append_oxm_match_in_port( oxm_matches *matches, uint32_t in_port ) {
  assert( matches != NULL );

  return append_oxm_match_32( matches, OXM_OF_IN_PORT, in_port );
}


bool
append_oxm_match_in_phy_port( oxm_matches *matches, uint32_t in_phy_port ) {
  assert( matches != NULL );

  return append_oxm_match_32( matches, OXM_OF_IN_PHY_PORT, in_phy_port );
}


bool
append_oxm_match_metadata( oxm_matches *matches, uint64_t metadata, uint64_t mask ) {
  assert( matches != NULL );

  if ( mask == UINT64_MAX ) {
    return append_oxm_match_64( matches, OXM_OF_METADATA, metadata );
  }

  return append_oxm_match_64w( matches, OXM_OF_METADATA_W, metadata, mask );
}


bool
append_oxm_match_eth_dst( oxm_matches *matches, uint8_t addr[ OFP_ETH_ALEN ], uint8_t mask[ OFP_ETH_ALEN ] ) {
  assert( matches != NULL );

  uint8_t all_one[ OFP_ETH_ALEN ] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  if ( memcmp( mask, all_one, OFP_ETH_ALEN ) == 0 ) {
    return append_oxm_match_eth_addr( matches, OXM_OF_ETH_DST, addr );
  }

  return append_oxm_match_eth_addr_w( matches, OXM_OF_ETH_DST_W, addr, mask );
}


bool
append_oxm_match_eth_src( oxm_matches *matches, uint8_t addr[ OFP_ETH_ALEN ], uint8_t mask[ OFP_ETH_ALEN ] ) {
  assert( matches != NULL );

  uint8_t all_one[ OFP_ETH_ALEN ] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  if ( memcmp( mask, all_one, OFP_ETH_ALEN ) == 0 ) {
    return append_oxm_match_eth_addr( matches, OXM_OF_ETH_SRC, addr );
  }

  return append_oxm_match_eth_addr_w( matches, OXM_OF_ETH_SRC_W, addr, mask );
}


bool
append_oxm_match_eth_type( oxm_matches *matches, uint16_t type ) {
  assert( matches != NULL );

  return append_oxm_match_16( matches, OXM_OF_ETH_TYPE, type );
}


bool
append_oxm_match_vlan_vid( oxm_matches *matches, uint16_t value, uint16_t mask ) {
  assert( matches != NULL );

  if ( mask == UINT16_MAX ) {
    return append_oxm_match_16( matches, OXM_OF_VLAN_VID, value );
  }

  return append_oxm_match_16w( matches, OXM_OF_VLAN_VID_W, value, mask );
}


bool
append_oxm_match_vlan_pcp( oxm_matches *matches, uint8_t value ) {
  assert( matches != NULL );

  return append_oxm_match_8( matches, OXM_OF_VLAN_PCP, value );
}


bool
append_oxm_match_ip_dscp( oxm_matches *matches, uint8_t value ) {
  assert( matches != NULL );

  return append_oxm_match_8( matches, OXM_OF_IP_DSCP, value );
}


bool
append_oxm_match_ip_ecn( oxm_matches *matches, uint8_t value ) {
  assert( matches != NULL );

  return append_oxm_match_8( matches, OXM_OF_IP_ECN, value );
}


bool
append_oxm_match_ip_proto( oxm_matches *matches, uint8_t value ) {
  assert( matches != NULL );

  return append_oxm_match_8( matches, OXM_OF_IP_PROTO, value );
}


bool
append_oxm_match_ipv4_src( oxm_matches *matches, uint32_t addr, uint32_t mask ) {
  assert( matches != NULL );

  if ( mask == UINT32_MAX ) {
    return append_oxm_match_32( matches, OXM_OF_IPV4_SRC, addr );
  }

  return append_oxm_match_32w( matches, OXM_OF_IPV4_SRC_W, addr, mask );
}


bool
append_oxm_match_ipv4_dst( oxm_matches *matches, uint32_t addr, uint32_t mask ) {
  assert( matches != NULL );

  if ( mask == UINT32_MAX ) {
    return append_oxm_match_32( matches, OXM_OF_IPV4_DST, addr );
  }

  return append_oxm_match_32w( matches, OXM_OF_IPV4_DST_W, addr, mask );
}


bool
append_oxm_match_tcp_src( oxm_matches *matches, uint16_t port ) {
  assert( matches != NULL );

  return append_oxm_match_16( matches, OXM_OF_TCP_SRC, port );
}


bool
append_oxm_match_tcp_dst( oxm_matches *matches, uint16_t port ) {
  assert( matches != NULL );

  return append_oxm_match_16( matches, OXM_OF_TCP_DST, port );
}


bool
append_oxm_match_udp_src( oxm_matches *matches, uint16_t port ) {
  assert( matches != NULL );

  return append_oxm_match_16( matches, OXM_OF_UDP_SRC, port );
}


bool
append_oxm_match_udp_dst( oxm_matches *matches, uint16_t port ) {
  assert( matches != NULL );

  return append_oxm_match_16( matches, OXM_OF_UDP_DST, port );
}


bool
append_oxm_match_sctp_src( oxm_matches *matches, uint16_t port ) {
  assert( matches != NULL );

  return append_oxm_match_16( matches, OXM_OF_SCTP_SRC, port );
}


bool
append_oxm_match_sctp_dst( oxm_matches *matches, uint16_t port ) {
  assert( matches != NULL );

  return append_oxm_match_16( matches, OXM_OF_SCTP_DST, port );
}


bool
append_oxm_match_icmpv4_type( oxm_matches *matches, uint8_t type ) {
  assert( matches != NULL );

  return append_oxm_match_8( matches, OXM_OF_ICMPV4_TYPE, type );
}


bool
append_oxm_match_icmpv4_code( oxm_matches *matches, uint8_t code ) {
  assert( matches != NULL );

  return append_oxm_match_8( matches, OXM_OF_ICMPV4_CODE, code );
}


bool
append_oxm_match_arp_op( oxm_matches *matches, uint16_t value ) {
  assert( matches != NULL );

  return append_oxm_match_16( matches, OXM_OF_ARP_OP, value );  
}


bool
append_oxm_match_arp_spa( oxm_matches *matches, uint32_t addr, uint32_t mask ) {
  assert( matches != NULL );

  if ( mask == UINT32_MAX ) {
    return append_oxm_match_32( matches, OXM_OF_ARP_SPA, addr );
  }

  return append_oxm_match_32w( matches, OXM_OF_ARP_SPA_W, addr, mask );  
}


bool
append_oxm_match_arp_tpa( oxm_matches *matches, uint32_t addr, uint32_t mask ) {
  assert( matches != NULL );

  if ( mask == UINT32_MAX ) {
    return append_oxm_match_32( matches, OXM_OF_ARP_TPA, addr );
  }

  return append_oxm_match_32w( matches, OXM_OF_ARP_TPA_W, addr, mask );  
}


bool
append_oxm_match_arp_sha( oxm_matches *matches, uint8_t addr[ OFP_ETH_ALEN ], uint8_t mask[ OFP_ETH_ALEN ] ) {
  assert( matches != NULL );

  uint8_t all_one[ OFP_ETH_ALEN ] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  if ( memcmp( mask, all_one, OFP_ETH_ALEN ) == 0 ) {
    return append_oxm_match_eth_addr( matches, OXM_OF_ARP_SHA, addr );
  }

  return append_oxm_match_eth_addr_w( matches, OXM_OF_ARP_SHA_W, addr, mask );
}


bool
append_oxm_match_arp_tha( oxm_matches *matches, uint8_t addr[ OFP_ETH_ALEN ], uint8_t mask[ OFP_ETH_ALEN ] ) {
  assert( matches != NULL );

  uint8_t all_one[ OFP_ETH_ALEN ] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  if ( memcmp( mask, all_one, OFP_ETH_ALEN ) == 0 ) {
    return append_oxm_match_eth_addr( matches, OXM_OF_ARP_THA, addr );
  }

  return append_oxm_match_eth_addr_w( matches, OXM_OF_ARP_THA_W, addr, mask );
}


bool
append_oxm_match_ipv6_src( oxm_matches *matches, struct in6_addr addr, struct in6_addr mask ) {
  assert( matches != NULL );

  struct in6_addr all_one;
  memset( all_one.s6_addr, 0xff, sizeof( all_one.s6_addr ) );
  if ( memcmp( mask.s6_addr, all_one.s6_addr, sizeof( mask.s6_addr ) ) == 0 ) {
    return append_oxm_match_ipv6_addr( matches, OXM_OF_IPV6_SRC, addr, mask );
  }

  return append_oxm_match_ipv6_addr( matches, OXM_OF_IPV6_SRC_W, addr, mask );
}


bool
append_oxm_match_ipv6_dst( oxm_matches *matches, struct in6_addr addr, struct in6_addr mask ) {
  assert( matches != NULL );

  struct in6_addr all_one;
  memset( all_one.s6_addr, 0xff, sizeof( all_one.s6_addr ) );
  if ( memcmp( mask.s6_addr, all_one.s6_addr, sizeof( mask.s6_addr ) ) == 0 ) {
    return append_oxm_match_ipv6_addr( matches, OXM_OF_IPV6_DST, addr, mask );
  }

  return append_oxm_match_ipv6_addr( matches, OXM_OF_IPV6_DST_W, addr, mask );
}


bool
append_oxm_match_ipv6_flabel( oxm_matches *matches, uint32_t value, uint32_t mask ) {
  assert( matches != NULL );

  if ( mask == UINT32_MAX ) {
    return append_oxm_match_32( matches, OXM_OF_IPV6_FLABEL, value );
  }

  return append_oxm_match_32w( matches, OXM_OF_IPV6_FLABEL_W, value, mask );
}


bool
append_oxm_match_icmpv6_type( oxm_matches *matches, uint8_t type ) {
  assert( matches != NULL );

  return append_oxm_match_8( matches, OXM_OF_ICMPV6_TYPE, type );
}


bool
append_oxm_match_icmpv6_code( oxm_matches *matches, uint8_t code ) {
  assert( matches != NULL );

  return append_oxm_match_8( matches, OXM_OF_ICMPV6_CODE, code );
}


bool
append_oxm_match_ipv6_nd_target( oxm_matches *matches, struct in6_addr addr ) {
  assert( matches != NULL );

  struct in6_addr mask = IN6ADDR_ANY_INIT;
  return append_oxm_match_ipv6_addr( matches, OXM_OF_IPV6_ND_TARGET, addr, mask );
}


bool
append_oxm_match_ipv6_nd_sll( oxm_matches *matches, uint8_t addr[ OFP_ETH_ALEN ] ) {
  assert( matches != NULL );

  return append_oxm_match_eth_addr( matches, OXM_OF_IPV6_ND_SLL, addr );
}


bool
append_oxm_match_ipv6_nd_tll( oxm_matches *matches, uint8_t addr[ OFP_ETH_ALEN ] ) {
  assert( matches != NULL );

  return append_oxm_match_eth_addr( matches, OXM_OF_IPV6_ND_TLL, addr );
}


bool
append_oxm_match_mpls_label( oxm_matches *matches, uint32_t value ) {
  assert( matches != NULL );

  return append_oxm_match_32( matches, OXM_OF_MPLS_LABEL, value );
}


bool
append_oxm_match_mpls_tc( oxm_matches *matches, uint8_t value ) {
  assert( matches != NULL );

  return append_oxm_match_8( matches, OXM_OF_MPLS_TC, value );
}


bool
append_oxm_match_mpls_bos( oxm_matches *matches, uint8_t value ) {
  assert( matches != NULL );

  return append_oxm_match_8( matches, OXM_OF_MPLS_BOS, value );
}


bool
append_oxm_match_pbb_isid( oxm_matches *matches, uint32_t value, uint32_t mask ) {
  assert( matches != NULL );

  if ( mask == UINT32_MAX ) {
    return append_oxm_match_24( matches, OXM_OF_PBB_ISID, value );
  }

  return append_oxm_match_24w( matches, OXM_OF_PBB_ISID_W, value, mask );
}


bool
append_oxm_match_tunnel_id( oxm_matches *matches, uint64_t id, uint64_t mask ) {
  assert( matches != NULL );

  if ( mask == UINT64_MAX ) {
    return append_oxm_match_64( matches, OXM_OF_TUNNEL_ID, id );
  }

  return append_oxm_match_64w( matches, OXM_OF_TUNNEL_ID_W, id, mask );
}


bool
append_oxm_match_ipv6_exthdr( oxm_matches *matches, uint16_t value, uint16_t mask ) {
  assert( matches != NULL );

  if ( mask == UINT16_MAX ) {
    return append_oxm_match_16( matches, OXM_OF_IPV6_EXTHDR, value );
  }

  return append_oxm_match_16w( matches, OXM_OF_IPV6_EXTHDR_W, value, mask );
}


oxm_matches *
parse_ofp_match( struct ofp_match *match ) {
  assert( match != NULL );
  assert( ntohs( match->length ) >= offsetof( struct ofp_match, oxm_fields ) );

  uint16_t oxms_len = 0;
  uint16_t oxm_len = 0;
  oxm_match_header *dst, *src;
  oxm_matches *matches = create_oxm_matches();

  uint16_t offset = offsetof( struct ofp_match, oxm_fields );
  oxms_len = ( uint16_t ) ( ntohs( match->length ) - offset );
  src = ( oxm_match_header * ) ( ( char * ) match + offset );

  while ( oxms_len > sizeof( oxm_match_header ) ) {
    oxm_len = OXM_LENGTH( ntohl( *src ) );
    dst = ( oxm_match_header * ) xcalloc( 1, sizeof( oxm_match_header ) + oxm_len );
    ntoh_oxm_match( dst, src );

    append_oxm_match( matches, dst );

    offset = ( uint16_t ) ( sizeof( oxm_match_header ) + oxm_len );
    if ( oxms_len < offset ) {
      break;
    }
    oxms_len = ( uint16_t ) ( oxms_len - offset );
    src = ( oxm_match_header * ) ( ( char * ) src + offset );
  }

  return matches;
}


void
construct_ofp_match( struct ofp_match *match, const oxm_matches *matches ) {
  assert( match != NULL );

  uint16_t oxm_len = 0;
  uint16_t oxms_len = 0;
  uint16_t ofp_match_len = 0;
  uint16_t pad_len = 0;
  oxm_match_header *dst, *src;

  if ( matches != NULL ) {
    uint16_t offset = offsetof( struct ofp_match, oxm_fields );
    dst = ( oxm_match_header * ) ( ( char * ) match + offset );

    list_element *elem = matches->list;
    while ( elem != NULL ) {
      src = ( oxm_match_header * ) elem->data;
      hton_oxm_match( dst, src );

      oxm_len = ( uint16_t ) ( sizeof( oxm_match_header ) + OXM_LENGTH( *src ) );
      oxms_len = ( uint16_t ) ( oxms_len + oxm_len );
      dst = ( oxm_match_header * ) ( ( char * ) dst + oxm_len );
      elem = elem->next;
    }
  }

  ofp_match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields ) + oxms_len );
  match->type = htons( OFPMT_OXM );
  match->length = htons( ( uint16_t ) ( ofp_match_len ) ); // exclude padding length

  pad_len = ( uint16_t ) PADLEN_TO_64( ofp_match_len );
  if ( pad_len > 0 ) {
    memset( ( char * ) match + ofp_match_len, 0, pad_len );
  }
}


oxm_matches *
duplicate_oxm_matches( oxm_matches *matches ) {
  assert( matches != NULL );

  uint16_t oxm_len = 0;
  oxm_match_header *dst, *src;
  list_element *elem = matches->list;

  oxm_matches *dup = create_oxm_matches();

  while ( elem != NULL ) {
    src = ( oxm_match_header * ) elem->data;
    oxm_len = OXM_LENGTH( *src );
    dst = ( oxm_match_header * ) xcalloc( 1, sizeof( oxm_match_header ) + oxm_len );

    memcpy( dst, src, sizeof( oxm_match_header ) + oxm_len );
    append_oxm_match( dup, dst );

    elem = elem->next;
  }

  return dup;
}


#define MATCH_NUM ( OFPXMT_OFB_IPV6_EXTHDR + 1 ) // MATCH_NUM = 40


static uint64_t
get_vaild_oxm_field_bitmask( oxm_matches *x ) {
  assert( x != NULL );

  oxm_match_header *hdr;
  uint32_t type;
  uint64_t bitmask = 0; // all wildcard

  list_element *elem = x->list;
  while ( elem != NULL ) {
    hdr = ( oxm_match_header * ) elem->data;
    if ( OXM_CLASS( *hdr ) == OFPXMC_OPENFLOW_BASIC ) {
      type = ( uint32_t ) OXM_FIELD( *hdr );
      if ( type < MATCH_NUM ) {
        // set valid oxm_field bitmask
        bitmask = ( uint64_t ) ( bitmask | ( ( ( uint64_t ) 1 ) << type ) );
      }
    }

    elem = elem->next;
  }

  return bitmask;
}


static uint64_t
get_vaild_oxm_field_bitmask_and_tlv( oxm_matches *x, oxm_match_header **x_oxms ) {
  assert( x != NULL );
  assert( x_oxms != NULL );

  oxm_match_header *hdr;
  uint32_t type;
  uint64_t bitmask = 0; // all wildcard

  list_element *elem = x->list;
  while ( elem != NULL ) {
    hdr = ( oxm_match_header * ) elem->data;
    if ( OXM_CLASS( *hdr ) == OFPXMC_OPENFLOW_BASIC ) {
      type = ( uint32_t ) OXM_FIELD( *hdr );
      if ( type < MATCH_NUM ) {
        // set valid oxm_field bitmask and oxm tlv
        bitmask = ( uint64_t ) ( bitmask | ( ( ( uint64_t ) 1 ) << type ) );
        x_oxms[ type ] = hdr;
      }
    }

    elem = elem->next;
  }

  return bitmask;
}


static bool
compare_field( void *x, void *y, void *xm, void *ym, size_t len, bool strict ) {
  assert( x != NULL );
  assert( y != NULL );

  uint8_t x_val, y_val, xm_val, ym_val;

  uint8_t *x_p = ( uint8_t * ) x;
  uint8_t *y_p = ( uint8_t * ) y;
  uint8_t *xm_p = ( uint8_t * ) xm;
  uint8_t *ym_p = ( uint8_t * ) ym;

  // mask all F set( exact match )
  xm_val = ym_val = 0xff;

  for ( int i = 0; i < ( int ) len; i++ ) {
    x_val = *x_p++;
    y_val = *y_p++;

    if ( xm != NULL ) {
      xm_val = *xm_p++;
    }

    if ( ym != NULL ) {
      ym_val = *ym_p++;
    }

    // mask check
    if ( strict ) {
      if ( xm_val != ym_val ) {
        return false;
      }
    }
    else {
      if ( ( ~xm_val | ~ym_val ) != ~xm_val ) {
        return false;
      }
    }

    // val check
    if ( ( x_val & xm_val ) != ( y_val & xm_val ) ) {
      return false;
    }
  }

  return true;
}


static bool
_compare_oxm_match( oxm_matches *x, oxm_matches *y, bool strict ) {
  assert( x != NULL );
  assert( y != NULL );

  oxm_match_header *x_oxm[ MATCH_NUM ] = {};
  oxm_match_header *y_oxm[ MATCH_NUM ] = {};
  uint16_t data_width = 0;
  bool ret;
  void *x_v, *y_v, *x_m, *y_m;

  // get bitmask of valid oxm_field and oxm tlvs
  uint64_t x_valid_bitmask = get_vaild_oxm_field_bitmask_and_tlv( x, x_oxm );
  get_vaild_oxm_field_bitmask_and_tlv( y, y_oxm );

  int i = 0;
  for ( i = 0 ; i < MATCH_NUM ; i++ ) {
    // oxm_field of x which is not valid skips
    if ( !( x_valid_bitmask & ( ( ( uint64_t ) 1 ) << i ) ) ) {
      continue;
    }

    assert( x_oxm[ i ] != NULL );
    assert( y_oxm[ i ] != NULL );

    // get length of oxm_field
    data_width = ( uint16_t ) OXM_LENGTH( *x_oxm[ i ] );
    if ( OXM_HASMASK( *x_oxm[ i ] ) ) {
      data_width = ( uint16_t ) ( data_width / 2 );
    }

    x_v = ( char * ) x_oxm[ i ] + sizeof( oxm_match_header );
    y_v = ( char * ) y_oxm[ i ] + sizeof( oxm_match_header );
    x_m = OXM_HASMASK( *x_oxm[ i ] ) ? ( ( char * ) x_oxm[ i ] + sizeof( oxm_match_header ) + data_width ) : NULL;
    y_m = OXM_HASMASK( *y_oxm[ i ] ) ? ( ( char * ) y_oxm[ i ] + sizeof( oxm_match_header ) + data_width ) : NULL;

    // matching field
    ret = compare_field( x_v, y_v, x_m, y_m, data_width, strict );
    if ( ret != true ) {
      return false;
    }
  }

  return true;
}


bool
compare_oxm_match( oxm_matches *x, oxm_matches *y ) {
  assert( x != NULL );
  assert( y != NULL );

  // get bitmask of valid oxm_field
  uint64_t x_valid_bitmask = get_vaild_oxm_field_bitmask( x );
  uint64_t y_valid_bitmask = get_vaild_oxm_field_bitmask( y );

  // check whether x's bitmask of valid oxm_field is included by y's one
  if ( ( ~x_valid_bitmask | ~y_valid_bitmask ) != ~x_valid_bitmask ) {
    return false;
  }

  return _compare_oxm_match( x, y, false );
}


bool
compare_oxm_match_strict( oxm_matches *x, oxm_matches *y ) {
  assert( x != NULL );
  assert( y != NULL );

  // get bitmask of valid oxm_field
  uint64_t x_valid_bitmask = get_vaild_oxm_field_bitmask( x );
  uint64_t y_valid_bitmask = get_vaild_oxm_field_bitmask( y );

  // check whether x's bitmask of valid oxm_field is the same as y's one
  if ( x_valid_bitmask != y_valid_bitmask ) {
    return false;
  }

  return _compare_oxm_match( x, y, true );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
