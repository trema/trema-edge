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


#ifndef MATCH_H
#define MATCH_H


#include "ofdp_common.h"


#ifndef ETH_P_8021AH
#define ETH_P_8021AH 0x88E7
#endif

enum {
  MATCH_IN_PORT = 1ULL << OFPXMT_OFB_IN_PORT,
  MATCH_IN_PHY_PORT = 1ULL << OFPXMT_OFB_IN_PHY_PORT,
  MATCH_METADATA = 1ULL << OFPXMT_OFB_METADATA,
  MATCH_ETH_DST = 1ULL << OFPXMT_OFB_ETH_DST,
  MATCH_ETH_SRC = 1ULL << OFPXMT_OFB_ETH_SRC,
  MATCH_ETH_TYPE = 1ULL << OFPXMT_OFB_ETH_TYPE,
  MATCH_VLAN_VID = 1ULL << OFPXMT_OFB_VLAN_VID,
  MATCH_VLAN_PCP = 1ULL << OFPXMT_OFB_VLAN_PCP,
  MATCH_IP_DSCP = 1ULL << OFPXMT_OFB_IP_DSCP,
  MATCH_IP_ECN = 1ULL << OFPXMT_OFB_IP_ECN,
  MATCH_IP_PROTO = 1ULL << OFPXMT_OFB_IP_PROTO,
  MATCH_IPV4_SRC = 1ULL << OFPXMT_OFB_IPV4_SRC,
  MATCH_IPV4_DST = 1ULL << OFPXMT_OFB_IPV4_DST,
  MATCH_TCP_SRC = 1ULL << OFPXMT_OFB_TCP_SRC,
  MATCH_TCP_DST = 1ULL << OFPXMT_OFB_TCP_DST,
  MATCH_UDP_SRC = 1ULL << OFPXMT_OFB_UDP_SRC,
  MATCH_UDP_DST = 1ULL << OFPXMT_OFB_UDP_DST,
  MATCH_SCTP_SRC = 1ULL << OFPXMT_OFB_SCTP_SRC,
  MATCH_SCTP_DST = 1ULL << OFPXMT_OFB_SCTP_DST,
  MATCH_ICMPV4_TYPE = 1ULL << OFPXMT_OFB_ICMPV4_TYPE,
  MATCH_ICMPV4_CODE = 1ULL << OFPXMT_OFB_ICMPV4_CODE,
  MATCH_ARP_OP = 1ULL << OFPXMT_OFB_ARP_OP,
  MATCH_ARP_SPA = 1ULL << OFPXMT_OFB_ARP_SPA,
  MATCH_ARP_TPA = 1ULL << OFPXMT_OFB_ARP_TPA,
  MATCH_ARP_SHA = 1ULL << OFPXMT_OFB_ARP_SHA,
  MATCH_ARP_THA = 1ULL << OFPXMT_OFB_ARP_THA,
  MATCH_IPV6_SRC = 1ULL << OFPXMT_OFB_IPV6_SRC,
  MATCH_IPV6_DST = 1ULL << OFPXMT_OFB_IPV6_DST,
  MATCH_IPV6_FLABEL = 1ULL << OFPXMT_OFB_IPV6_FLABEL,
  MATCH_ICMPV6_TYPE = 1ULL << OFPXMT_OFB_ICMPV6_TYPE,
  MATCH_ICMPV6_CODE = 1ULL << OFPXMT_OFB_ICMPV6_CODE,
  MATCH_IPV6_ND_TARGET = 1ULL << OFPXMT_OFB_IPV6_ND_TARGET,
  MATCH_IPV6_ND_SLL = 1ULL << OFPXMT_OFB_IPV6_ND_SLL,
  MATCH_IPV6_ND_TLL = 1ULL << OFPXMT_OFB_IPV6_ND_TLL,
  MATCH_MPLS_LABEL = 1ULL << OFPXMT_OFB_MPLS_LABEL,
  MATCH_MPLS_TC = 1ULL << OFPXMT_OFB_MPLS_TC,
  MATCH_MPLS_BOS = 1ULL << OFPXMT_OFB_MPLS_BOS,
  MATCH_PBB_ISID = 1ULL << OFPXMT_OFB_PBB_ISID,
  MATCH_TUNNEL_ID = 1ULL << OFPXMT_OFB_TUNNEL_ID,
  MATCH_IPV6_EXTHDR = 1ULL << OFPXMT_OFB_IPV6_EXTHDR,
};

enum {
  SUPPORTED_MATCH = ( MATCH_IN_PORT | MATCH_METADATA | MATCH_ETH_DST | MATCH_ETH_SRC |
                      MATCH_ETH_TYPE | MATCH_VLAN_VID | MATCH_VLAN_PCP | MATCH_IP_DSCP |
                      MATCH_IP_ECN | MATCH_IP_PROTO | MATCH_IPV4_SRC | MATCH_IPV4_DST |
                      MATCH_TCP_SRC | MATCH_TCP_DST | MATCH_UDP_SRC | MATCH_UDP_DST |
                      MATCH_ICMPV4_TYPE | MATCH_ICMPV4_CODE | MATCH_ARP_OP | MATCH_ARP_SPA |
                      MATCH_ARP_TPA | MATCH_ARP_SHA | MATCH_ARP_THA | MATCH_IPV6_SRC |
                      MATCH_IPV6_DST | MATCH_IPV6_FLABEL | MATCH_ICMPV6_TYPE |
                      MATCH_ICMPV6_CODE | MATCH_IPV6_ND_TARGET | MATCH_IPV6_ND_SLL |
                      MATCH_IPV6_ND_TLL | MATCH_MPLS_LABEL | MATCH_MPLS_TC |
                      MATCH_MPLS_BOS | MATCH_PBB_ISID | MATCH_IPV6_EXTHDR ),
};


typedef uint64_t match_capabilities;

typedef struct {
  uint8_t value;
  uint8_t mask;
  bool valid;
} match8;

typedef struct {
  uint16_t value;
  uint16_t mask;
  bool valid;
} match16;

typedef struct {
  uint32_t value;
  uint32_t mask;
  bool valid;
} match32;

typedef struct {
  uint64_t value;
  uint64_t mask;
  bool valid;
} match64;

typedef struct {
  match16 arp_opcode;
  match8 arp_sha[ ETH_ADDRLEN ];
  match32 arp_spa;
  match8 arp_tha[ ETH_ADDRLEN ];
  match32 arp_tpa;
  match8 eth_dst[ ETH_ADDRLEN ];
  match8 eth_src[ ETH_ADDRLEN ];
  match16 eth_type;
  match8 icmpv4_code;
  match8 icmpv4_type;
  match8 icmpv6_code;
  match8 icmpv6_type;
  match32 in_phy_port;
  match32 in_port;
  match8 ip_dscp;
  match8 ip_ecn;
  match8 ip_proto;
  match32 ipv4_dst;
  match32 ipv4_src;
  match8 ipv6_src[ IPV6_ADDRLEN ];
  match8 ipv6_dst[ IPV6_ADDRLEN ];
  match16 ipv6_exthdr;
  match32 ipv6_flabel;
  match8 ipv6_nd_sll[ ETH_ADDRLEN ];
  match8 ipv6_nd_target[ IPV6_ADDRLEN ];
  match8 ipv6_nd_tll[ ETH_ADDRLEN ];
  match64 metadata;
  match8 mpls_bos;
  match32 mpls_label;
  match8 mpls_tc;
  match16 sctp_dst;
  match16 sctp_src;
  match16 tcp_dst;
  match16 tcp_src;
  match64 tunnel_id;
  match16 udp_dst;
  match16 udp_src;
  match8 vlan_pcp;
  match16 vlan_vid;
  match32 pbb_isid;
} match;


match *create_match( void );
void delete_match( match *match );
match *duplicate_match( const match *match );
OFDPE validate_match( match *match );
bool compare_match_strict( const match *x, const match *y );
bool compare_match( const match *key, const match *examinee );
void build_match_from_packet_info( match *match, const packet_info *pinfo );
void build_all_wildcarded_match( match *match );
bool all_wildcarded_match( const match *match );
void dump_match( const match *match, void dump_function( const char *format, ... ) );
void merge_match( match *dst, const match *src);

#endif // MATCH_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/
