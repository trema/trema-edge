/*
 * Utility functions for converting byteorder.
 *
 * Author: Yasunobu Chiba
 *
 * Copyright (C) 2012 NEC Corporation
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


#ifndef OXM_BYTEORDER_H
#define OXM_BYTEORDER_H

#include "oxm_match.h"


void hton_oxm_match_in_port( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_metadata( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_eth_addr( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_eth_type( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_vlan_vid( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_vlan_pcp( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_ip_dscp( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_ip_ecn( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_ip_proto( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_ipv4_addr( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_tcp_port( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_udp_port( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_sctp_port( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_icmpv4_type( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_icmpv4_code( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_arp_op( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_arp_pa( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_arp_ha( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_ipv6_addr( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_ipv6_flabel( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_icmpv6_type( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_icmpv6_code( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_ipv6_nd_target( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_ipv6_nd_ll( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_mpls_label( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_mpls_tc( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_mpls_bos( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_pbb_isid( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_tunnel_id( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_ipv6_exthdr( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match( oxm_match_header *dst, const oxm_match_header *src );
void hton_match( struct ofp_match *dst, struct ofp_match *src );


void ntoh_oxm_match_in_port( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_metadata( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_eth_addr( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_eth_type( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_vlan_vid( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_vlan_pcp( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_ip_dscp( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_ip_ecn( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_ip_proto( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_ipv4_addr( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_tcp_port( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_udp_port( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_sctp_port( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_icmpv4_type( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_icmpv4_code( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_arp_op( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_arp_pa( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_arp_ha( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_ipv6_addr( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_ipv6_flabel( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_icmpv6_type( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_icmpv6_code( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_ipv6_nd_target( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_ipv6_nd_ll( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_mpls_label( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_mpls_tc( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_mpls_bos( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_pbb_isid( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_tunnel_id( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match_ipv6_exthdr( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_oxm_match( oxm_match_header *dst, const oxm_match_header *src );
void ntoh_match( struct ofp_match *dst, struct ofp_match *src );


#endif // OXM_BYTEORDER_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
