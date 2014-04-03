/*
 * Match fields library.
 *
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


#ifndef OXM_MATCH_H
#define OXM_MATCH_H

#include <netinet/in.h>
#include "oxm_tlv.h"
#include "linked_list.h"


// calcurate padding length( 64bit allignment ) macro
#define PADLEN_TO_64( len ) ( uint16_t ) ( ( ( ( len ) + 7 ) / 8 ) * 8 - ( len ) )

#define COMPARE_MAC( _x, _y )                                                      \
  ( ( ( ( uint16_t * ) &( _x ) )[ 0 ] == ( ( uint16_t * ) &( _y ) )[ 0 ] )         \
   && ( ( ( uint16_t * ) &( _x ) )[ 1 ] == ( ( uint16_t * ) &( _y ) )[ 1 ] )       \
   && ( ( ( uint16_t * ) &( _x ) )[ 2 ] == ( ( uint16_t * ) &( _y ) )[ 2 ] ) )

typedef uint32_t oxm_match_header;

typedef struct {
  int n_matches;
  list_element *list;
} oxm_matches;


oxm_matches *create_oxm_matches();
bool delete_oxm_matches( oxm_matches *matches );
uint16_t get_oxm_matches_length( const oxm_matches *matches );
bool append_oxm_match_in_port( oxm_matches *matches, uint32_t in_port );
bool append_oxm_match_in_phy_port( oxm_matches *matches, uint32_t in_phy_port );
bool append_oxm_match_metadata( oxm_matches *matches, uint64_t metadata, uint64_t mask );
bool append_oxm_match_eth_dst( oxm_matches *matches, uint8_t addr[ OFP_ETH_ALEN ], uint8_t mask[ OFP_ETH_ALEN ] );
bool append_oxm_match_eth_src( oxm_matches *matches, uint8_t addr[ OFP_ETH_ALEN ], uint8_t mask[ OFP_ETH_ALEN ] );
bool append_oxm_match_eth_type( oxm_matches *matches, uint16_t type );
bool append_oxm_match_vlan_vid( oxm_matches *matches, uint16_t value, uint16_t mask );
bool append_oxm_match_vlan_pcp( oxm_matches *matches, uint8_t value );
bool append_oxm_match_ip_dscp( oxm_matches *matches, uint8_t value );
bool append_oxm_match_ip_ecn( oxm_matches *matches, uint8_t value );
bool append_oxm_match_ip_proto( oxm_matches *matches, uint8_t value );
bool append_oxm_match_ipv4_src( oxm_matches *matches, uint32_t addr, uint32_t mask );
bool append_oxm_match_ipv4_dst( oxm_matches *matches, uint32_t addr, uint32_t mask );
bool append_oxm_match_tcp_src( oxm_matches *matches, uint16_t port );
bool append_oxm_match_tcp_dst( oxm_matches *matches, uint16_t port );
bool append_oxm_match_udp_src( oxm_matches *matches, uint16_t port );
bool append_oxm_match_udp_dst( oxm_matches *matches, uint16_t port );
bool append_oxm_match_sctp_src( oxm_matches *matches, uint16_t port );
bool append_oxm_match_sctp_dst( oxm_matches *matches, uint16_t port );
bool append_oxm_match_icmpv4_type( oxm_matches *matches, uint8_t type );
bool append_oxm_match_icmpv4_code( oxm_matches *matches, uint8_t code );
bool append_oxm_match_arp_op( oxm_matches *matches, uint16_t value );
bool append_oxm_match_arp_spa( oxm_matches *matches, uint32_t addr, uint32_t mask );
bool append_oxm_match_arp_tpa( oxm_matches *matches, uint32_t addr, uint32_t mask );
bool append_oxm_match_arp_sha( oxm_matches *matches, uint8_t addr[ OFP_ETH_ALEN ], uint8_t mask[ OFP_ETH_ALEN ] );
bool append_oxm_match_arp_tha( oxm_matches *matches, uint8_t addr[ OFP_ETH_ALEN ], uint8_t mask[ OFP_ETH_ALEN ] );
bool append_oxm_match_ipv6_src( oxm_matches *matches, struct in6_addr addr, struct in6_addr mask );
bool append_oxm_match_ipv6_dst( oxm_matches *matches, struct in6_addr addr, struct in6_addr mask );
bool append_oxm_match_ipv6_flabel( oxm_matches *matches, uint32_t value, uint32_t mask );
bool append_oxm_match_icmpv6_type( oxm_matches *matches, uint8_t type );
bool append_oxm_match_icmpv6_code( oxm_matches *matches, uint8_t code );
bool append_oxm_match_ipv6_nd_target( oxm_matches *matches, struct in6_addr addr );
bool append_oxm_match_ipv6_nd_sll( oxm_matches *matches, uint8_t addr[ OFP_ETH_ALEN ] );
bool append_oxm_match_ipv6_nd_tll( oxm_matches *matches, uint8_t addr[ OFP_ETH_ALEN ] );
bool append_oxm_match_mpls_label( oxm_matches *matches, uint32_t value );
bool append_oxm_match_mpls_tc( oxm_matches *matches, uint8_t value );
bool append_oxm_match_mpls_bos( oxm_matches *matches, uint8_t value );
bool append_oxm_match_pbb_isid( oxm_matches *matches, uint32_t value, uint32_t mask );
bool append_oxm_match_tunnel_id( oxm_matches *matches, uint64_t id, uint64_t mask );
bool append_oxm_match_ipv6_exthdr( oxm_matches *matches, uint16_t value, uint16_t mask );
oxm_matches *parse_ofp_match( struct ofp_match *match );
void construct_ofp_match( struct ofp_match *match, const oxm_matches *matches );
oxm_matches *duplicate_oxm_matches( oxm_matches *matches );

bool compare_oxm_match( oxm_matches *x, oxm_matches *y );
bool compare_oxm_match_strict( oxm_matches *x, oxm_matches *y );


#endif // OXM_MATCH_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
