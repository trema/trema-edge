/*
 * Match fields values.
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


#ifndef OXM_TLV_H
#define OXM_TLV_H

#include <openflow.h>

#define OXM_HEADER__(CLASS, FIELD, HASMASK, LENGTH) \
    (uint32_t)(((CLASS) << 16) | ((FIELD) << 9) | ((HASMASK) << 8) | (LENGTH))
#define OXM_HEADER(CLASS, FIELD, LENGTH) \
    OXM_HEADER__(CLASS, FIELD, 0, LENGTH)
#define OXM_HEADER_W(CLASS, FIELD, LENGTH) \
    OXM_HEADER__(CLASS, FIELD, 1, (LENGTH) * 2)
#define OXM_CLASS(HEADER) ((HEADER) >> 16)
#define OXM_FIELD(HEADER) (((HEADER) >> 9) & 0x7f)
#define OXM_TYPE(HEADER) (((HEADER) >> 9) & 0x7fffff)
#define OXM_HASMASK(HEADER) (((HEADER) >> 8) & 1)
#define OXM_LENGTH(HEADER) ((HEADER) & 0xff)

#define OXM_MAKE_WILD_HEADER(HEADER) \
        OXM_HEADER_W(OXM_CLASS(HEADER), OXM_FIELD(HEADER), OXM_LENGTH(HEADER))

/* OpenFlow port on which the packet was received.
 * May be a physical port, a logical port, or the reserved port OFPP_LOCAL
 *
 * Prereqs: None.
 *
 * Format: 32-bit integer in network byte order.
 *
 * Masking: Not maskable. */
#define OXM_OF_IN_PORT        OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IN_PORT, 4)

/* Physical port on which the packet was received.
 *
 * Consider a packet received on a tunnel interface defined over a link
 * aggregation group (LAG) with two physical port members. If the tunnel
 * interface is the logical port bound to OpenFlow. In this case,
 * OFPXMT_OF_IN_PORT is the tunnel's port number and OFPXMT_OF_IN_PHY_PORT is
 * the physical port number of the LAG on which the tunnel is configured.
 *
 * When a packet is received directly on a physical port and not processed by a
 * logical port, OFPXMT_OF_IN_PORT and OFPXMT_OF_IN_PHY_PORT have the same
 * value.
 *
 * This field is usually not available in a regular match and only available
 * in ofp_packet_in messages when it's different from OXM_OF_IN_PORT.
 *
 * Prereqs: OXM_OF_IN_PORT must be present.
 *
 * Format: 32-bit integer in network byte order.
 *
 * Masking: Not maskable. */
#define OXM_OF_IN_PHY_PORT    OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IN_PHY_PORT, 4)

/* Table metadata.
 *
 * Prereqs: None.
 *
 * Format: 64-bit integer in network byte order.
 *
 * Masking: Arbitrary masks. */
#define OXM_OF_METADATA       OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_METADATA, 8)
#define OXM_OF_METADATA_W     OXM_HEADER_W(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_METADATA, 8)

/* Source or destination address in Ethernet header.
 *
 * Prereqs: None.
 *
 * Format: 48-bit Ethernet MAC address.
 *
 * Masking: Arbitrary masks. */
#define OXM_OF_ETH_DST        OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_ETH_DST, 6)
#define OXM_OF_ETH_DST_W      OXM_HEADER_W(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_ETH_DST, 6)
#define OXM_OF_ETH_SRC        OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_ETH_SRC, 6)
#define OXM_OF_ETH_SRC_W      OXM_HEADER_W(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_ETH_SRC, 6)

/* Packet's Ethernet type.
 *
 * Prereqs: None.
 *
 * Format: 16-bit integer in network byte order.
 *
 * Masking: Not maskable. */
#define OXM_OF_ETH_TYPE       OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_ETH_TYPE, 2)

/* 802.1Q VID.
 *
 * For a packet with an 802.1Q header, this is the VLAN-ID (VID) from the
 * outermost tag, with the CFI bit forced to 1. For a packet with no 802.1Q
 * header, this has value OFPVID_NONE.
 *
 * Prereqs: None.
 *
 * Format: 16-bit integer in network byte order with bit 13 indicating
 * presence of VLAN header and 3 most-significant bits forced to 0.
 * Only the lower 13 bits have meaning.
 *
 * Masking: Arbitrary masks.
 *
 * This field can be used in various ways:
 *
 * - If it is not constrained at all, the nx_match matches packets without
 * an 802.1Q header or with an 802.1Q header that has any VID value.
 *
 * - Testing for an exact match with 0x0 matches only packets without
 * an 802.1Q header.
 *
 * - Testing for an exact match with a VID value with CFI=1 matches packets
 * that have an 802.1Q header with a specified VID.
 *
 * - Testing for an exact match with a nonzero VID value with CFI=0 does
 * not make sense. The switch may reject this combination.
 *
 * - Testing with nxm_value=0, nxm_mask=0x0fff matches packets with no 802.1Q
 * header or with an 802.1Q header with a VID of 0.
 *
 * - Testing with nxm_value=0x1000, nxm_mask=0x1000 matches packets with
 * an 802.1Q header that has any VID value.
 */
#define OXM_OF_VLAN_VID       OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_VLAN_VID, 2)
#define OXM_OF_VLAN_VID_W     OXM_HEADER_W(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_VLAN_VID, 2)

/* 802.1Q PCP.
 *
 * For a packet with an 802.1Q header, this is the VLAN-PCP from the
 * outermost tag. For a packet with no 802.1Q header, this has value
 * 0.
 *
 * Prereqs: OXM_OF_VLAN_VID must be different from OFPVID_NONE.
 *
 * Format: 8-bit integer with 5 most-significant bits forced to 0.
 * Only the lower 3 bits have meaning.
 *
 * Masking: Not maskable. */
#define OXM_OF_VLAN_PCP       OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_VLAN_PCP, 1)

/* The Diff Serv Code Point (DSCP) bits of the IP header.
 * Part of the IPv4 ToS field or the IPv6 Traffic Class field.
 *
 * Prereqs: OXM_OF_ETH_TYPE must be either 0x0800 or 0x86dd.
 *
 * Format: 8-bit integer with 2 most-significant bits forced to 0.
 * Only the lower 6 bits have meaning.
 *
 * Masking: Not maskable. */
#define OXM_OF_IP_DSCP        OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IP_DSCP, 1)

/* The ECN bits of the IP header.
 * Part of the IPv4 ToS field or the IPv6 Traffic Class field.
 *
 * Prereqs: OXM_OF_ETH_TYPE must be either 0x0800 or 0x86dd.
 *
 * Format: 8-bit integer with 6 most-significant bits forced to 0.
 * Only the lower 2 bits have meaning.
 *
 * Masking: Not maskable. */
#define OXM_OF_IP_ECN         OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IP_ECN, 1)

/* The "protocol" byte in the IP header.
 *
 * Prereqs: OXM_OF_ETH_TYPE must be either 0x0800 or 0x86dd.
 *
 * Format: 8-bit integer.
 *
 * Masking: Not maskable. */
#define OXM_OF_IP_PROTO       OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IP_PROTO, 1)

/* The source or destination address in the IP header.
 *
 * Prereqs: OXM_OF_ETH_TYPE must match 0x0800 exactly.
 *
 * Format: 32-bit integer in network byte order.
 *
 * Masking: Arbitrary masks. */
#define OXM_OF_IPV4_SRC       OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IPV4_SRC, 4)
#define OXM_OF_IPV4_SRC_W     OXM_HEADER_W(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IPV4_SRC, 4)
#define OXM_OF_IPV4_DST       OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IPV4_DST, 4)
#define OXM_OF_IPV4_DST_W     OXM_HEADER_W(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IPV4_DST, 4)

/* The source or destination port in the TCP header.
 *
 * Prereqs:
 * OXM_OF_ETH_TYPE must be either 0x0800 or 0x86dd.
 * OXM_OF_IP_PROTO must match 6 exactly.
 *
 * Format: 16-bit integer in network byte order.
 *
 * Masking: Not maskable. */
#define OXM_OF_TCP_SRC        OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_TCP_SRC, 2)
#define OXM_OF_TCP_DST        OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_TCP_DST, 2)

/* The source or destination port in the UDP header.
 *
 * Prereqs:
 * OXM_OF_ETH_TYPE must match either 0x0800 or 0x86dd.
 * OXM_OF_IP_PROTO must match 17 exactly.
 *
 * Format: 16-bit integer in network byte order.
 *
 * Masking: Not maskable. */
#define OXM_OF_UDP_SRC        OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_UDP_SRC, 2)
#define OXM_OF_UDP_DST        OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_UDP_DST, 2)

/* The source or destination port in the SCTP header.
 *
 * Prereqs:
 * OXM_OF_ETH_TYPE must match either 0x0800 or 0x86dd.
 * OXM_OF_IP_PROTO must match 132 exactly.
 *
 * Format: 16-bit integer in network byte order.
 *
 * Masking: Not maskable. */
#define OXM_OF_SCTP_SRC       OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_SCTP_SRC, 2)
#define OXM_OF_SCTP_DST       OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_SCTP_DST, 2)

/* The type or code in the ICMP header.
 *
 * Prereqs:
 * OXM_OF_ETH_TYPE must match 0x0800 exactly.
 * OXM_OF_IP_PROTO must match 1 exactly.
 *
 * Format: 8-bit integer.
 *
 * Masking: Not maskable. */
#define OXM_OF_ICMPV4_TYPE    OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_ICMPV4_TYPE, 1)
#define OXM_OF_ICMPV4_CODE    OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_ICMPV4_CODE, 1)

/* ARP opcode.
 *
 * For an Ethernet+IP ARP packet, the opcode in the ARP header. Always 0
 * otherwise.
 *
 * Prereqs: OXM_OF_ETH_TYPE must match 0x0806 exactly.
 *
 * Format: 16-bit integer in network byte order.
 *
 * Masking: Not maskable. */
#define OXM_OF_ARP_OP         OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_ARP_OP, 2)

/* For an Ethernet+IP ARP packet, the source or target protocol address
 * in the ARP header. Always 0 otherwise.
 *
 * Prereqs: OXM_OF_ETH_TYPE must match 0x0806 exactly.
 *
 * Format: 32-bit integer in network byte order.
 *
 * Masking: Arbitrary masks. */
#define OXM_OF_ARP_SPA        OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_ARP_SPA, 4)
#define OXM_OF_ARP_SPA_W      OXM_HEADER_W(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_ARP_SPA, 4)
#define OXM_OF_ARP_TPA        OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_ARP_TPA, 4)
#define OXM_OF_ARP_TPA_W      OXM_HEADER_W(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_ARP_TPA, 4)

/* For an Ethernet+IP ARP packet, the source or target hardware address
 * in the ARP header. Always 0 otherwise.
 *
 * Prereqs: OXM_OF_ETH_TYPE must match 0x0806 exactly.
 *
 * Format: 48-bit Ethernet MAC address.
 *
 * Masking: Not maskable. */
/* XXX: Arbitrary masks or Not maskable
 * OpenFlow Switch Specification Version 1.3.3
 *
 * p.56
 * Field          Bits Bytes Mask Pre-requisite   Description
 * OXM_OF_ARP_SHA   48     6  Yes ETH TYPE=0x0806 Source Ethernet address in the ARP payload.
 * OXM_OF_ARP_THA   48     6  Yes ETH TYPE=0x0806 Target Ethernet address in the ARP payload.
 *       Table 12: Match fields details.
 * p.119
 * Masking: Not maskable.
 */
#define OXM_OF_ARP_SHA        OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_ARP_SHA, 6)
#define OXM_OF_ARP_SHA_W      OXM_HEADER_W(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_ARP_SHA, 6) // XXX
#define OXM_OF_ARP_THA        OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_ARP_THA, 6)
#define OXM_OF_ARP_THA_W      OXM_HEADER_W(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_ARP_THA, 6) // XXX

/* The source or destination address in the IPv6 header.
 *
 * Prereqs: OXM_OF_ETH_TYPE must match 0x86dd exactly.
 *
 * Format: 128-bit IPv6 address.
 *
 * Masking: Arbitrary masks.
 */
#define OXM_OF_IPV6_SRC       OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IPV6_SRC, 16)
#define OXM_OF_IPV6_SRC_W     OXM_HEADER_W(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IPV6_SRC, 16)
#define OXM_OF_IPV6_DST       OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IPV6_DST, 16)
#define OXM_OF_IPV6_DST_W     OXM_HEADER_W(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IPV6_DST, 16)

/* The IPv6 Flow Label
 *
 * Prereqs:
 * OXM_OF_ETH_TYPE must match 0x86dd exactly
 *
 * Format: 32-bit integer with 12 most-significant bits forced to 0.
 * Only the lower 20 bits have meaning.
 *
 * Masking: Not maskable. */
#define OXM_OF_IPV6_FLABEL    OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IPV6_FLABEL, 4)
#define OXM_OF_IPV6_FLABEL_W  OXM_HEADER_W(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IPV6_FLABEL, 4)

/* The type or code in the ICMPv6 header.
 *
 * Prereqs:
 * OXM_OF_ETH_TYPE must match 0x86dd exactly.
 * OXM_OF_IP_PROTO must match 58 exactly.
 *
 * Format: 8-bit integer.
 *
 * Masking: Not maskable. */
#define OXM_OF_ICMPV6_TYPE    OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_ICMPV6_TYPE, 1)
#define OXM_OF_ICMPV6_CODE    OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_ICMPV6_CODE, 1)

/* The target address in an IPv6 Neighbor Discovery message.
 *
 * Prereqs:
 * OXM_OF_ETH_TYPE must match 0x86dd exactly.
 * OXM_OF_IP_PROTO must match 58 exactly.
 * OXM_OF_ICMPV6_TYPE must be either 135 or 136.
 *
 * Format: 128-bit IPv6 address.
 *
 * Masking: Not maskable. */
#define OXM_OF_IPV6_ND_TARGET OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IPV6_ND_TARGET, 16)

/* The source link-layer address option in an IPv6 Neighbor Discovery
 * message.
 *
 * Prereqs:
 * OXM_OF_ETH_TYPE must match 0x86dd exactly.
 * OXM_OF_IP_PROTO must match 58 exactly.
 * OXM_OF_ICMPV6_TYPE must be exactly 135.
 *
 * Format: 48-bit Ethernet MAC address.
 *
 * Masking: Not maskable. */
#define OXM_OF_IPV6_ND_SLL    OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IPV6_ND_SLL, 6)

/* The target link-layer address option in an IPv6 Neighbor Discovery
 * message.
 *
 * Prereqs:
 * OXM_OF_ETH_TYPE must match 0x86dd exactly.
 * OXM_OF_IP_PROTO must match 58 exactly.
 * OXM_OF_ICMPV6_TYPE must be exactly 136.
 *
 * Format: 48-bit Ethernet MAC address.
 *
 * Masking: Not maskable. */
#define OXM_OF_IPV6_ND_TLL    OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IPV6_ND_TLL, 6)

/* The LABEL in the first MPLS shim header.
 *
 * Prereqs:
 * OXM_OF_ETH_TYPE must match 0x8847 or 0x8848 exactly.
 *
 * Format: 32-bit integer in network byte order with 12 most-significant
 * bits forced to 0. Only the lower 20 bits have meaning.
 *
 * Masking: Not maskable. */
#define OXM_OF_MPLS_LABEL     OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_MPLS_LABEL, 4)

/* The TC in the first MPLS shim header.
 *
 * Prereqs:
 * OXM_OF_ETH_TYPE must match 0x8847 or 0x8848 exactly.
 *
 * Format: 8-bit integer with 5 most-significant bits forced to 0.
 * Only the lower 3 bits have meaning.
 *
 * Masking: Not maskable. */
#define OXM_OF_MPLS_TC        OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_MPLS_TC, 1)

/* The BoS bit in the first MPLS shim header.
 *
 * Prereqs:
 * OXM_OF_ETH_TYPE must match 0x8847 or 0x8848 exactly.
 *
 * Format: 8-bit integer with 7 most-significant bits forced to 0.
 * Only the lowest bit have a meaning.
 *
 * Masking: Not maskable. */
#define OXM_OF_MPLS_BOS       OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_MPLS_BOS, 1)

/* IEEE 802.1ah I-SID.
 *
 * For a packet with a PBB header, this is the I-SID from the
 * outermost service tag.
 *
 * Prereqs:
 * OXM_OF_ETH_TYPE must match 0x88E7 exactly.
 *
 * Format: 24-bit integer in network byte order.
 *
 * Masking: Arbitrary masks. */
#define OXM_OF_PBB_ISID       OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_PBB_ISID, 3)
#define OXM_OF_PBB_ISID_W     OXM_HEADER_W(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_PBB_ISID, 3)

/* Logical Port Metadata.
 *
 * Metadata associated with a logical port.
 * If the logical port performs encapsulation and decapsulation, this
 * is the demultiplexing field from the encapsulation header.
 * For example, for a packet received via GRE tunnel including a (32-bit) key,
 * the key is stored in the low 32-bits and the high bits are zeroed.
 * For a MPLS logical port, the low 20 bits represent the MPLS Label.
 * For a VxLAN logical port, the low 24 bits represent the VNI.
 * If the packet is not received through a logical port, the value is 0.
 *
 * Prereqs: None.
 *
 * Format: 64-bit integer in network byte order.
 *
 * Masking: Arbitrary masks. */
#define OXM_OF_TUNNEL_ID      OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_TUNNEL_ID, 8)
#define OXM_OF_TUNNEL_ID_W    OXM_HEADER_W(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_TUNNEL_ID, 8)

/* The IPv6 Extension Header pseudo-field.
 *
 * Prereqs:
 * OXM_OF_ETH_TYPE must match 0x86dd exactly
 *
 * Format: 16-bit integer with 7 most-significant bits forced to 0.
 * Only the lower 9 bits have meaning.
 *
 * Masking: Maskable. */
#define OXM_OF_IPV6_EXTHDR    OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IPV6_EXTHDR, 2)
#define OXM_OF_IPV6_EXTHDR_W  OXM_HEADER_W(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IPV6_EXTHDR, 2)


#endif // OXM_TLV_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
