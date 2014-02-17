/*
 * Functions for accessing commonly-used header fields values.
 *
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


#ifndef PACKET_INFO_H
#define PACKET_INFO_H


#include <arpa/inet.h>
#include "arp.h"
#include "checks.h"
#include "bool.h"
#include "ether.h"
#include "icmp.h"
#include "igmp.h"
#include "ipv4.h"
#include "ipv6.h"
#include "tcp.h"
#include "udp.h"
#include "etherip.h"
#include "sctp.h"
#include "mpls.h"
#include "icmpv6.h"


enum {
  ETH_DIX = 0x00000001,
  ETH_8023_RAW = 0x00000002,
  ETH_8023_LLC = 0x00000004,
  ETH_8023_SNAP = 0x00000008,
  ETH_8021Q = 0x00000010,
  MPLS = 0x00000020,
  PBB = 0x00000040,
  NW_IPV4 = 0x00000100,
  NW_ICMPV4 = 0x00000200,
  NW_IPV6 = 0x00000400,
  NW_ICMPV6 = 0x00000800,
  NW_ARP = 0x00001000,
  NW_IGMP = 0x00002000,
  NW_LLDP = 0x00004000,
  TP_TCP = 0x00010000,
  TP_UDP = 0x00020000,
  TP_ETHERIP = 0x00040000,
  TP_SCTP = 0x00080000,

  ETH_VTAG_DIX = ETH_8021Q | ETH_DIX,
  ETH_VTAG_RAW = ETH_8021Q | ETH_8023_RAW,
  ETH_VTAG_LLC = ETH_8021Q | ETH_8023_LLC,
  ETH_VTAG_SNAP = ETH_8021Q | ETH_8023_SNAP,
  ETH_ARP = ETH_DIX | NW_ARP,
  ETH_LLDP = ETH_DIX | NW_LLDP,
  ETH_MPLS_IPV4 = ETH_DIX | MPLS | NW_IPV4,
  ETH_IPV4 = ETH_DIX | NW_IPV4,
  ETH_IPV6 = ETH_DIX | NW_IPV6,
  ETH_IPV4_ICMPV4 = ETH_IPV4 | NW_ICMPV4,
  ETH_MPLS_IPV4_ICMPV4 = ETH_MPLS_IPV4 | NW_ICMPV4,
  ETH_IPV4_IGMP = ETH_IPV4 | NW_IGMP,
  ETH_MPLS_IPV4_IGMP = ETH_MPLS_IPV4 | NW_IGMP,
  ETH_IPV4_TCP = ETH_IPV4 | TP_TCP,
  ETH_MPLS_IPV4_TCP = ETH_MPLS_IPV4 | TP_TCP,
  ETH_IPV4_UDP = ETH_IPV4 | TP_UDP,
  ETH_MPLS_IPV4_UDP = ETH_MPLS_IPV4 | TP_UDP,
  ETH_IPV4_ETHERIP = ETH_IPV4 | TP_ETHERIP,
  ETH_MPLS_IPV4_ETHERIP = ETH_MPLS_IPV4 | TP_ETHERIP,
  ETH_VTAG_ARP = ETH_VTAG_DIX | NW_ARP,
  ETH_VTAG_IPV4 = ETH_VTAG_DIX | NW_IPV4,
  ETH_VTAG_IPV4_ICMPV4 = ETH_VTAG_IPV4 | NW_ICMPV4,
  ETH_VTAG_IPV4_TCP = ETH_VTAG_IPV4 | TP_TCP,
  ETH_VTAG_IPV4_UDP = ETH_VTAG_IPV4 | TP_UDP,
  ETH_SNAP_ARP = ETH_8023_SNAP | NW_ARP,
  ETH_SNAP_IPV4 = ETH_8023_SNAP | NW_IPV4,
  ETH_SNAP_IPV4_ICMPV4 = ETH_SNAP_IPV4 | NW_ICMPV4,
  ETH_SNAP_IPV4_TCP = ETH_SNAP_IPV4 | TP_TCP,
  ETH_SNAP_IPV4_UDP = ETH_SNAP_IPV4 | TP_UDP,
  ETH_VTAG_SNAP_ARP = ETH_VTAG_SNAP | NW_ARP,
  ETH_VTAG_SNAP_IPV4 = ETH_VTAG_SNAP | NW_IPV4,
  ETH_VTAG_SNAP_IPV4_ICMPV4 = ETH_VTAG_SNAP_IPV4 | NW_ICMPV4,
  ETH_VTAG_SNAP_IPV4_TCP = ETH_VTAG_SNAP_IPV4 | TP_TCP,
  ETH_VTAG_SNAP_IPV4_UDP = ETH_VTAG_SNAP_IPV4 | TP_UDP,
  ETH_IPV6_ICMPV6 = ETH_IPV6 | NW_ICMPV6,
  ETH_IPV6_TCP = ETH_IPV6 | TP_TCP,
  ETH_IPV6_UDP = ETH_IPV6 | TP_UDP
};


enum {
  SNAP_LLC_LENGTH = 3,
  SNAP_OUI_LENGTH = 3,
};


typedef struct {
  /*
  * TODO to set this field according to openflow spec.
  * Currently not set.
  */
  uint64_t metadata;
  uint32_t format;

  uint8_t eth_macda[ ETH_ADDRLEN ];
  uint8_t eth_macsa[ ETH_ADDRLEN ];
  uint16_t eth_type;

  uint16_t vlan_tci;
  uint16_t vlan_tpid;
  uint8_t vlan_prio; // PCP
  uint8_t vlan_cfi;
  uint16_t vlan_vid;

  uint8_t snap_llc[ SNAP_LLC_LENGTH ];
  uint8_t snap_oui[ SNAP_OUI_LENGTH ];
  uint16_t snap_type;

  uint16_t arp_ar_hrd;
  uint16_t arp_ar_pro;
  uint8_t arp_ar_hln;
  uint8_t arp_ar_pln;
  uint16_t arp_ar_op;
  uint8_t arp_sha[ ETH_ADDRLEN ];
  uint32_t arp_spa;
  uint8_t arp_tha[ ETH_ADDRLEN ];
  uint32_t arp_tpa;

  uint8_t ip_proto;
  uint8_t ip_dscp;
  uint8_t ip_ecn;

  uint8_t ipv4_version;
  uint8_t ipv4_ihl;
  uint8_t ipv4_tos;
  uint8_t ipv4_dscp;
  uint8_t ipv4_ecn;
  uint16_t ipv4_tot_len;
  uint16_t ipv4_id;
  uint16_t ipv4_frag_off;
  uint8_t ipv4_ttl;
  uint8_t ipv4_protocol;
  uint16_t ipv4_checksum;
  uint32_t ipv4_saddr;
  uint32_t ipv4_daddr;

  uint8_t ipv6_version;
  uint8_t ipv6_tc;
  uint8_t ipv6_dscp;
  uint8_t ipv6_ecn;
  uint32_t ipv6_flowlabel;
  uint16_t ipv6_plen;
  uint16_t ipv6_nexthdr;
  uint16_t ipv6_hoplimit;
  struct in6_addr ipv6_saddr;
  struct in6_addr ipv6_daddr;
  struct in6_addr ipv6_nd_target;
  uint8_t ipv6_protocol;

  uint8_t icmpv4_type;
  uint8_t icmpv4_code;
  uint16_t icmpv4_checksum;
  uint16_t icmpv4_id;
  uint16_t icmpv4_seq;
  uint32_t icmpv4_gateway;

  uint8_t igmp_type;
  uint8_t igmp_code;
  uint16_t igmp_checksum;
  uint32_t igmp_group;

  uint16_t tcp_src_port;
  uint16_t tcp_dst_port;
  uint32_t tcp_seq_no;
  uint32_t tcp_ack_no;
  uint8_t tcp_offset;
  uint8_t tcp_flags;
  uint16_t tcp_window;
  uint16_t tcp_checksum;
  uint16_t tcp_urgent;

  uint16_t udp_src_port;
  uint16_t udp_dst_port;
  uint16_t udp_len;
  uint16_t udp_checksum;

  uint16_t etherip_version;
  uint16_t etherip_offset;
  uint32_t eth_in_port;
  uint32_t eth_in_phy_port;

  uint16_t sctp_src_port;
  uint16_t sctp_dst_port;

  uint8_t icmpv6_type;
  uint8_t icmpv6_code;
  struct in6_addr icmpv6_nd_target;
  uint8_t icmpv6_nd_ll_type;
  uint8_t icmpv6_nd_ll_length;
  uint8_t icmpv6_nd_sll[ ETH_ADDRLEN ];
  uint8_t icmpv6_nd_tll[ ETH_ADDRLEN ];

  uint32_t mpls_label;
  uint8_t mpls_tc;
  uint8_t mpls_bos;
  uint32_t pbb_isid;
  uint64_t tunnel_id;

  uint16_t ipv6_exthdr;

  void *l2_header;
  void *l2_payload;
  size_t l2_payload_length;
  void *l3_header;
  void *l3_payload;
  size_t l3_payload_length;
  void *l4_header;
  void *l4_payload;
  size_t l4_payload_length;
  void *l2_vlan_header;
  void *l2_pbb_header;
  void *l2_mpls_header;
} packet_info;


bool parse_packet( buffer *buf );

void calloc_packet_info( buffer *frame );
void free_packet_info( buffer *frame );
void copy_packet_info( buffer *dst, const buffer *src );
packet_info get_packet_info( const buffer *frame );

bool packet_type_eth_dix( const buffer *frame );
bool packet_type_eth_vtag( const buffer *frame );
bool packet_type_eth_raw( const buffer *frame );
bool packet_type_eth_llc( const buffer *frame );
bool packet_type_eth_snap( const buffer *frame );
bool packet_type_eth_mpls( const buffer *frame );
bool packet_type_eth_pbb(const buffer *frame);
bool packet_type_ether( const buffer *frame );
bool packet_type_arp( const buffer *frame );
bool packet_type_ipv4( const buffer *frame );
bool packet_type_ipv6( const buffer *frame );
bool packet_type_lldp( const buffer *frame );
bool packet_type_icmpv4( const buffer *frame );
bool packet_type_igmp( const buffer *frame );
bool packet_type_ipv4_tcp( const buffer *frame );
bool packet_type_ipv6_tcp( const buffer *frame );
bool packet_type_ipv4_udp( const buffer *frame );
bool packet_type_ipv6_udp( const buffer *frame );
bool packet_type_ipv4_sctp( const buffer *frame );
bool packet_type_ipv6_sctp( const buffer *frame );
bool packet_type_ipv4_etherip( const buffer *frame );

bool packet_type_arp_request( const buffer *frame );
bool packet_type_arp_reply( const buffer *frame );

bool packet_type_icmpv4_echo_reply( const buffer *frame );
bool packet_type_icmpv4_dst_unreach( const buffer *frame );
bool packet_type_icmpv4_redirect( const buffer *frame );
bool packet_type_icmpv4_echo_request( const buffer *frame );

bool packet_type_icmpv6( const buffer *frame );

bool packet_type_igmp_membership_query( const buffer *frame );
bool packet_type_igmp_v1_membership_report( const buffer *frame );
bool packet_type_igmp_v2_membership_report( const buffer *frame );
bool packet_type_igmp_v2_leave_group( const buffer *frame );
bool packet_type_igmp_v3_membership_report( const buffer *frame );


#endif // PACKET_INFO_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
