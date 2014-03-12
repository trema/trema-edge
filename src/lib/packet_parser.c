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
#include <stdint.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include "packet_info.h"
#include "log.h"
#include "wrapper.h"


#define REMAINED_BUFFER_LENGTH( buf, ptr )  \
  ( buf->length - ( size_t ) ( ( char * ) ptr - ( char * ) buf->data ) )


static void
parse_ether( buffer *buf ) {
  assert( buf != NULL );

  packet_info *packet_info = buf->user_data;
  void *ptr = packet_info->l2_header;
  assert( ptr != NULL );

  // Check the length of remained buffer
  size_t length = REMAINED_BUFFER_LENGTH( buf, ptr );
  if ( length < sizeof( ether_header_t ) ) {
    debug("incomplete ether_header_t");
    return;
  }

  // Ethernet header
  ether_header_t *ether_header = ptr;
  memcpy( packet_info->eth_macsa, ether_header->macsa, ETH_ADDRLEN );
  memcpy( packet_info->eth_macda, ether_header->macda, ETH_ADDRLEN );
  uint16_t ethertype = ntohs( ether_header->type );

  ptr = ( void * ) ( ether_header + 1 );

  int tagged = 0;
  do {
    tagged = 0;
    length = REMAINED_BUFFER_LENGTH( buf, ptr );

    if ( ethertype <= ETH_MTU ) {
      snap_header_t *snap_header = ptr;
      if ( length > sizeof( snap_header_t ) &&
           snap_header->llc[0]==0xAA &&
           snap_header->llc[1]==0xAA &&
           snap_header->oui[0]==0 &&
           snap_header->oui[1]==0 &&
           snap_header->oui[2]==0 ) {

        memcpy( packet_info->snap_llc, snap_header->llc, SNAP_LLC_LENGTH );
        memcpy( packet_info->snap_oui, snap_header->oui, SNAP_OUI_LENGTH );
        packet_info->snap_type = ntohs( snap_header->type );
        packet_info->format |= ETH_8023_SNAP;

        ethertype = ntohs( snap_header->type );
        ptr = ( void * ) ( snap_header + 1 );
        tagged = 1;
      }
      else{
        ethertype = 0x05FF; // beacon
      }
    }
    else {
      packet_info->format |= ETH_DIX;

      if ( ethertype == ETH_ETHTYPE_TPID  ||
           ethertype == ETH_ETHTYPE_TPID1 ||
           ethertype == ETH_ETHTYPE_TPID2 ||
           ethertype == ETH_ETHTYPE_TPID3 ||
           ethertype == ETH_ETHTYPE_TPID4 ) {
        if ( length < sizeof( vlantag_header_t ) ) {
          debug("incomplete vlantag_header_t");
          return;
        }
        vlantag_header_t *vlantag_header = ptr;

        if ( packet_info->l2_vlan_header == NULL ) {
          // capture the outermost information
          packet_info->vlan_tci  = ntohs( vlantag_header->tci );
          packet_info->vlan_tpid = ethertype;
          packet_info->vlan_prio = TCI_GET_PRIO( packet_info->vlan_tci );
          packet_info->vlan_cfi  = TCI_GET_CFI( packet_info->vlan_tci );
          packet_info->vlan_vid  = TCI_GET_VID( packet_info->vlan_tci );
          packet_info->format |= ETH_8021Q;
          packet_info->l2_vlan_header = vlantag_header;
        }

        ethertype = ntohs( vlantag_header->type );
        ptr = ( void * ) ( vlantag_header + 1 );
        tagged = 1;
      }
    }
  } while ( tagged == 1 );

  packet_info->eth_type = ethertype;

  size_t payload_length = REMAINED_BUFFER_LENGTH( buf, ptr );
  if ( payload_length > 0 ) {
    packet_info->l2_payload = ptr;
    packet_info->l2_payload_length = payload_length;
  }

  return;
}


static void
parse_arp( buffer *buf ) {
  assert( buf != NULL );

  packet_info *packet_info = buf->user_data;
  void *ptr = packet_info->l3_header;
  assert( ptr != NULL );

  // Check the length of remained buffer
  size_t length = REMAINED_BUFFER_LENGTH( buf, ptr );
  if ( length < sizeof( arp_header_t ) ) {
    return;
  }

  // Ethernet header
  arp_header_t *arp_header = ptr;
  packet_info->arp_ar_hrd = ntohs( arp_header->ar_hrd );
  packet_info->arp_ar_pro = ntohs( arp_header->ar_pro );
  packet_info->arp_ar_hln = arp_header->ar_hln;
  packet_info->arp_ar_pln = arp_header->ar_pln;
  packet_info->arp_ar_op = ntohs( arp_header->ar_op );
  memcpy( packet_info->arp_sha, arp_header->sha, ETH_ADDRLEN );
  packet_info->arp_spa = ntohl( arp_header->sip );
  memcpy( packet_info->arp_tha, arp_header->tha, ETH_ADDRLEN );
  packet_info->arp_tpa = ntohl( arp_header->tip );

  packet_info->format |= NW_ARP;

  return;
};


static void
parse_ipv4( buffer *buf ) {
  assert( buf != NULL );

  packet_info *packet_info = buf->user_data;
  void *ptr = packet_info->l3_header;
  assert( ptr != NULL );

  // Check the length of remained buffer for an ipv4 header without options.
  size_t length = REMAINED_BUFFER_LENGTH( buf, ptr );
  if ( length < sizeof( ipv4_header_t ) ) {
    return;
  }

  // Check the length of remained buffer for an ipv4 header with options.
  ipv4_header_t *ipv4_header = ptr;
  if ( ipv4_header->ihl < 5 ) {
    return;
  }
  if ( length < ( size_t ) ipv4_header->ihl * 4 ) {
    return;
  }

  // Parses IPv4 header
  packet_info->ipv4_version = ipv4_header->version;
  packet_info->ipv4_ihl = ipv4_header->ihl;
  packet_info->ipv4_tos = ipv4_header->tos;
  packet_info->ipv4_dscp = ( IPTOS_DSCP_MASK & ipv4_header->tos ) >> IPTOS_DSCP_SHIFT;
  packet_info->ipv4_ecn = IPTOS_ECN_MASK & ipv4_header->tos;
  packet_info->ipv4_tot_len = ntohs( ipv4_header->tot_len );
  packet_info->ipv4_id = ntohs( ipv4_header->id );
  packet_info->ipv4_frag_off = ntohs( ipv4_header->frag_off );
  packet_info->ipv4_ttl = ipv4_header->ttl;
  packet_info->ipv4_protocol = ipv4_header->protocol;
  packet_info->ipv4_checksum = ntohs( ipv4_header->csum );
  packet_info->ipv4_saddr = ntohl( ipv4_header->saddr );
  packet_info->ipv4_daddr = ntohl( ipv4_header->daddr );

  ptr = ( char * ) ipv4_header + packet_info->ipv4_ihl * 4;
  size_t payload_length = REMAINED_BUFFER_LENGTH( buf, ptr );
  if ( payload_length > 0 ) {
    packet_info->l3_payload = ptr;
    packet_info->l3_payload_length = payload_length;
  }

  packet_info->format |= NW_IPV4;

  return;
}


static void
parse_ipv6( buffer *buf ) {
  assert( buf != NULL );

  packet_info *packet_info = buf->user_data;
  void *ptr = packet_info->l3_header;
  assert( ptr != NULL );

  // Check the length of remained buffer for an ipv6 header without nexthdr.
  size_t length = REMAINED_BUFFER_LENGTH( buf, ptr );
  if ( length < sizeof( ipv6_header_t ) ) {
    return;
  }

  // Parses IPv6 header
  ipv6_header_t *ipv6_header = ptr;
  uint32_t hdrctl = ntohl( ipv6_header->hdrctl );
  packet_info->ipv6_version = ( uint8_t )( hdrctl >> 28 );
  packet_info->ipv6_tc = ( uint8_t )( hdrctl >> 20 & 0xFF );
  packet_info->ipv6_dscp = ( IPTOS_DSCP_MASK & packet_info->ipv6_tc ) >> IPTOS_DSCP_SHIFT;
  packet_info->ipv6_ecn = IPTOS_ECN_MASK & packet_info->ipv6_tc;
  packet_info->ipv6_flowlabel = hdrctl & 0xFFFFF;
  packet_info->ipv6_plen = ntohs( ipv6_header->plen );
  packet_info->ipv6_nexthdr = ipv6_header->nexthdr;
  packet_info->ipv6_hoplimit = ipv6_header->hoplimit;
  memcpy( packet_info->ipv6_saddr.s6_addr, ipv6_header->saddr, IPV6_ADDRLEN );
  memcpy( packet_info->ipv6_daddr.s6_addr, ipv6_header->daddr, IPV6_ADDRLEN );

  uint8_t nexthdr = ipv6_header->nexthdr;
  packet_info->ipv6_protocol = nexthdr;
  ptr = ( void * ) ( ipv6_header + 1 );
  ipv6_ext_t *ipv6_ext = ptr;
  size_t payload_length = 0;

  while ( 1 ) {
    switch ( nexthdr ) {
    case IPV6_NEXTHDR_HOPOPT:
      packet_info->ipv6_exthdr |= OFPIEH_HOP;
      break;

    case IPV6_NEXTHDR_OPTS:
      packet_info->ipv6_exthdr |= OFPIEH_DEST;
      break;

    case IPV6_NEXTHDR_ROUTE:
      packet_info->ipv6_exthdr |= OFPIEH_ROUTER;
      break;

    case IPV6_NEXTHDR_FLAG:
      packet_info->ipv6_exthdr |= OFPIEH_FRAG;
      break;

    case IPV6_NEXTHDR_AH:
      packet_info->ipv6_exthdr |= OFPIEH_AUTH;
      break;

    case IPV6_NEXTHDR_ESP:
      packet_info->ipv6_exthdr |= OFPIEH_ESP;
      packet_info->ipv6_protocol = nexthdr;
      goto END;

    case IPV6_NEXTHDR_NONXT:
      packet_info->ipv6_exthdr |= OFPIEH_NONEXT;
      packet_info->ipv6_protocol = nexthdr;
      goto END;

    default:
      packet_info->ipv6_protocol = nexthdr;
      goto END;
    }

    uint16_t nextlen;
    if ( nexthdr == IPV6_NEXTHDR_FLAG ) {
      nextlen = 8;
    } else if ( nexthdr == IPV6_NEXTHDR_AH ) {
      nextlen = ( uint16_t ) ( ( ipv6_ext->exthdrlen + 2 ) * 4 );
    } else {
      nextlen = ( uint16_t ) ( ( ipv6_ext->exthdrlen + 1 ) * 8 );
    }
    nexthdr = ipv6_ext->nexthdr;
    ptr = ( void * ) ( ( char * ) ptr + nextlen );
    ipv6_ext = ptr;
  }

END:
  payload_length = REMAINED_BUFFER_LENGTH( buf, ptr );
  if ( payload_length > 0 ) {
    packet_info->l3_payload = ptr;
    packet_info->l3_payload_length = payload_length;
  }

  packet_info->format |= NW_IPV6;

  return;
}


static void
parse_lldp( buffer *buf ) {
  assert( buf != NULL );

  packet_info *packet_info = buf->user_data;
  void *ptr = packet_info->l3_header;
  assert( ptr != NULL );

  size_t payload_length = REMAINED_BUFFER_LENGTH( buf, ptr );
  if ( payload_length > 0 ) {
    packet_info->l3_payload = ptr;
    packet_info->l3_payload_length = payload_length;
  }

  packet_info->format |= NW_LLDP;

  return;
}


static void
parse_mpls( buffer *buf ) {
  assert( buf != NULL );

  packet_info *packet_info = buf->user_data;
  void *ptr = packet_info->l2_payload;
  assert( ptr != NULL );

  // Check the length of remained buffer
  size_t length = REMAINED_BUFFER_LENGTH( buf, ptr );
  if ( length < sizeof( mpls_header_t ) ) {
    debug("incomplete mpls");
    return;
  }

  // We only parse the outer most one.
  mpls_header_t *mpls_header = ptr;
  uint32_t mpls = ntohl( mpls_header->label );
  packet_info->mpls_label =             ( ( mpls & 0xFFFFF000 ) >> 12 );
  packet_info->mpls_tc    = ( uint8_t ) ( ( mpls & 0x00000E00 ) >>  9 );
  packet_info->mpls_bos   = ( uint8_t ) ( ( mpls & 0x00000100 ) >>  8 );
  packet_info->format |= MPLS;
  packet_info->l2_mpls_header = ptr;

  return;
}


static void
parse_pbb( buffer *buf ) {
  assert( buf != NULL );

  packet_info *packet_info = buf->user_data;
  void *ptr = packet_info->l2_payload;
  assert( ptr != NULL );

  // Check the length of remained buffer
  size_t length = REMAINED_BUFFER_LENGTH( buf, ptr );
  if ( length < sizeof( pbb_header_t ) ) {
    debug("incomplete pbb_header_t");
    return;
  }

  pbb_header_t *pbb_header = ptr;
  packet_info->pbb_isid = ntohl( pbb_header->isid ) & 0x00FFFFFF;
  packet_info->l2_pbb_header = ptr;
  packet_info->format |= PBB;

  return;
}


static void
parse_icmp( buffer *buf ) {
  assert( buf != NULL );

  packet_info *packet_info = buf->user_data;
  void *ptr = packet_info->l4_header;
  assert( ptr != NULL );

  // Check the length of remained buffer
  size_t length = REMAINED_BUFFER_LENGTH( buf, ptr );
  if ( length < sizeof( icmp_header_t ) ) {
    return;
  }

  // ICMPV4 header
  icmp_header_t *icmp_header = ptr;
  packet_info->icmpv4_type = icmp_header->type;
  packet_info->icmpv4_code = icmp_header->code;
  packet_info->icmpv4_checksum = ntohs( icmp_header->csum );

  switch ( packet_info->icmpv4_type ) {
  case ICMP_TYPE_ECHOREP:
  case ICMP_TYPE_ECHOREQ:
    packet_info->icmpv4_id = ntohs( icmp_header->icmp_data.echo.ident );
    packet_info->icmpv4_seq = ntohs( icmp_header->icmp_data.echo.seq );
    break;

  case ICMP_TYPE_REDIRECT:
    packet_info->icmpv4_gateway = ntohl( icmp_header->icmp_data.gateway );
    break;

  default:
    break;
  }

  ptr = ( void * ) ( icmp_header + 1 );
  size_t payload_length = REMAINED_BUFFER_LENGTH( buf, ptr );
  if ( payload_length > 0 ) {
    packet_info->l4_payload = ptr;
    packet_info->l4_payload_length = payload_length;
  }

  packet_info->format |= NW_ICMPV4;

  return;
};


static void
parse_icmpv6( buffer *buf ) {
  assert( buf != NULL );

  packet_info *packet_info = buf->user_data;
  void *ptr = packet_info->l4_header;
  assert( ptr != NULL );

  // Check the length of remained buffer
  size_t length = REMAINED_BUFFER_LENGTH( buf, ptr );
  if ( length < sizeof( icmpv6_header_t ) ) {
    return;
  }

  // ICMPv6 header
  icmpv6_header_t *icmpv6_header = ptr;
  packet_info->icmpv6_type = icmpv6_header->type;
  packet_info->icmpv6_code = icmpv6_header->code;

  icmpv6data_ndp_t *icmpv6data_ndp = NULL;
  switch ( packet_info->icmpv6_type ) {
  case ICMPV6_TYPE_NEIGHBOR_SOL:
    icmpv6data_ndp = ( icmpv6data_ndp_t * ) icmpv6_header->data;
    memcpy( packet_info->icmpv6_nd_target.s6_addr, icmpv6data_ndp->nd_target, IPV6_ADDRLEN );
    if ( length >= ( size_t ) ( sizeof( icmpv6_header_t ) + sizeof( icmpv6data_ndp_t ) ) ) {
      // ICMPv6 option(Source link-layer address)
      if ( ( icmpv6data_ndp->ll_type == 1 ) && ( icmpv6data_ndp->length == 1 ) ) {
        packet_info->icmpv6_nd_ll_type = 1;
        packet_info->icmpv6_nd_ll_length = 1;
        memcpy( packet_info->icmpv6_nd_sll, icmpv6data_ndp->ll_addr, ETH_ADDRLEN );
      } else {
        packet_info->icmpv6_nd_ll_type = 0;
        packet_info->icmpv6_nd_ll_length = 0;
      }
    }
    break;

  case ICMPV6_TYPE_NEIGHBOR_ADV:
    icmpv6data_ndp = ( icmpv6data_ndp_t * ) icmpv6_header->data;
    memcpy( packet_info->icmpv6_nd_target.s6_addr, icmpv6data_ndp->nd_target, IPV6_ADDRLEN );
    if ( length >= ( size_t ) ( sizeof( icmpv6_header_t ) + sizeof( icmpv6data_ndp_t ) ) ) {
      // ICMPv6 option(Target link-layer address)
      if ( ( icmpv6data_ndp->ll_type == 2 ) && ( icmpv6data_ndp->length == 1 ) ) {
        packet_info->icmpv6_nd_ll_type = 2;
        packet_info->icmpv6_nd_ll_length = 1;
        memcpy( packet_info->icmpv6_nd_tll, icmpv6data_ndp->ll_addr, ETH_ADDRLEN );
      } else {
        packet_info->icmpv6_nd_ll_type = 0;
        packet_info->icmpv6_nd_ll_length = 0;
      }
    }
    break;

  default:
    break;
  }

  ptr = ( void * ) ( icmpv6_header + 1 );
  size_t payload_length = REMAINED_BUFFER_LENGTH( buf, ptr );
  if ( payload_length > 0 ) {
    packet_info->l4_payload = ptr;
    packet_info->l4_payload_length = payload_length;
  }
  packet_info->format |= NW_ICMPV6;

  return;
};


static void
parse_udp( buffer *buf ) {
  assert( buf != NULL );

  packet_info *packet_info = buf->user_data;
  void *ptr = packet_info->l4_header;
  assert( ptr != NULL );

  // Check the length of remained buffer
  size_t length = REMAINED_BUFFER_LENGTH( buf, ptr );
  if ( length < sizeof( udp_header_t ) ) {
    return;
  }

  // UDP header
  udp_header_t *udp_header = ptr;
  packet_info->udp_src_port = ntohs( udp_header->src_port );
  packet_info->udp_dst_port = ntohs( udp_header->dst_port );
  packet_info->udp_len = ntohs( udp_header->len );
  packet_info->udp_checksum = ntohs( udp_header->csum );

  ptr = ( void * ) ( udp_header + 1 );
  size_t payload_length = REMAINED_BUFFER_LENGTH( buf, ptr );
  if ( payload_length > 0 ) {
    packet_info->l4_payload = ptr;
    packet_info->l4_payload_length = payload_length;
  }

  packet_info->format |= TP_UDP;

  return;
};


static void
parse_tcp( buffer *buf ) {
  assert( buf != NULL );

  packet_info *packet_info = buf->user_data;
  void *ptr = packet_info->l4_header;
  assert( ptr != NULL );

  // Check the length of remained buffer for the tcp header without options
  size_t length = REMAINED_BUFFER_LENGTH( buf, ptr );
  if ( length < sizeof( tcp_header_t ) ) {
    return;
  }

  // Check the length of remained buffer for the tcp header with options
  tcp_header_t *tcp_header = ptr;
  if ( tcp_header->offset < 5 ) {
    return;
  }
  if ( length < ( size_t ) tcp_header->offset * 4 ) {
    return;
  }

  // TCP header
  packet_info->tcp_src_port = ntohs( tcp_header->src_port );
  packet_info->tcp_dst_port = ntohs( tcp_header->dst_port );
  packet_info->tcp_seq_no = ntohl( tcp_header->seq_no );
  packet_info->tcp_ack_no = ntohl( tcp_header->ack_no );
  packet_info->tcp_offset = tcp_header->offset;
  packet_info->tcp_flags = tcp_header->flags;
  packet_info->tcp_window = ntohs( tcp_header->window );
  packet_info->tcp_checksum = ntohs( tcp_header->csum );
  packet_info->tcp_urgent = ntohs( tcp_header->urgent );

  ptr = ( char * ) tcp_header + packet_info->tcp_offset * 4;
  size_t payload_length = REMAINED_BUFFER_LENGTH( buf, ptr );
  if ( payload_length > 0 ) {
    packet_info->l4_payload = ptr;
    packet_info->l4_payload_length = payload_length;
  }

  packet_info->format |= TP_TCP;

  return;
};



static void
parse_igmp( buffer *buf ) {
  assert( buf != NULL );

  packet_info *packet_info = buf->user_data;
  void *ptr = packet_info->l4_header;
  assert( ptr != NULL );

  // Check the length of remained buffer
  size_t length = REMAINED_BUFFER_LENGTH( buf, ptr );
  if ( length < sizeof( igmp_header_t ) ) {
    return;
  }

  igmp_header_t *igmp = ptr;
  packet_info->igmp_type = igmp->type;
  packet_info->igmp_code = igmp->code;
  packet_info->igmp_checksum = ntohs( igmp->csum );
  packet_info->igmp_group = ntohl( igmp->group );

  packet_info->format |= NW_IGMP;

  return;
}


static void
parse_sctp( buffer *buf ) {
  assert( buf != NULL );

  packet_info *packet_info = buf->user_data;
  void *ptr = packet_info->l4_header;
  assert( ptr != NULL );

  // Check the length of remained buffer
  size_t length = REMAINED_BUFFER_LENGTH( buf, ptr );
  if ( length < sizeof( sctp_header_t ) ) {
    return;
  }

  // SCTP header
  sctp_header_t *sctp_header = ptr;
  packet_info->sctp_src_port = ntohs( sctp_header->src_port );
  packet_info->sctp_dst_port = ntohs( sctp_header->dst_port );

  ptr = ( void * ) ( sctp_header + 1 );
  size_t payload_length = REMAINED_BUFFER_LENGTH( buf, ptr );
  if ( payload_length > 0 ) {
    packet_info->l4_payload = ptr;
    packet_info->l4_payload_length = payload_length;
  }

  packet_info->format |= TP_SCTP;

  return;
};


static void
parse_etherip( buffer *buf ) {
  assert( buf != NULL );

  packet_info *packet_info = buf->user_data;
  void *ptr = packet_info->l4_header;
  assert( ptr != NULL );

  // Check the length of remained buffer
  size_t length = REMAINED_BUFFER_LENGTH( buf, ptr );
  if ( length < sizeof( etherip_header ) ) {
    return;
  }

  // Ether header
  etherip_header *etherip_header = ptr;
  packet_info->etherip_version = ntohs( etherip_header->version );
  packet_info->etherip_offset = 0;

  ptr = ( void * ) ( etherip_header + 1 );
  size_t payload_length = REMAINED_BUFFER_LENGTH( buf, ptr );
  if ( payload_length > 0 ) {
    packet_info->l4_payload = ptr;
    packet_info->l4_payload_length = payload_length;
    packet_info->etherip_offset = ( uint16_t ) ( ( char * ) ptr - ( char *) buf->data );
  }

  packet_info->format |= TP_ETHERIP;

  return;
}


bool
parse_packet( buffer *buf ) {
  assert( buf != NULL );
  assert( buf->data != NULL );

  calloc_packet_info( buf );
  if ( buf->user_data == NULL ) {
    error( "Can't alloc memory for packet_info." );
    return false;
  }

  // Parse the L2 header.
  packet_info *packet_info = buf->user_data;
  packet_info->l2_header = buf->data;
  parse_ether( buf );

  // Parse the L3 header.
  switch ( packet_info->eth_type ) {
  case ETH_ETHTYPE_ARP:
    packet_info->l3_header = packet_info->l2_payload;
    parse_arp( buf );
    break;

  case ETH_ETHTYPE_IPV4:
    packet_info->l3_header = packet_info->l2_payload;
    parse_ipv4( buf );
    break;

  case ETH_ETHTYPE_IPV6:
    packet_info->l3_header = packet_info->l2_payload;
    parse_ipv6( buf );
    break;

  case ETH_ETHTYPE_LLDP:
    packet_info->l3_header = packet_info->l2_payload;
    parse_lldp( buf );
    break;

  case ETH_ETHTYPE_MPLS_UNI:
  case ETH_ETHTYPE_MPLS_MLT:
    parse_mpls( buf );
    return true;

  case ETH_ETHTYPE_PBB:
    parse_pbb( buf );
    return true;

  default:
    // Unknown L3 type
    return true;
  }

  // Get L4 protocol num.
  if ( packet_info->format & NW_IPV4 ) {
    if ( packet_info->ipv4_frag_off & IP_OFFMASK ) {
      // The ipv4 packet is fragmented.
      return true;
    }
    packet_info->ip_proto = packet_info->ipv4_protocol;
    packet_info->ip_dscp = packet_info->ipv4_dscp;
    packet_info->ip_ecn = packet_info->ipv4_ecn;
  }
  else if ( packet_info->format & NW_IPV6 ) {
    packet_info->ip_proto = packet_info->ipv6_protocol;
    packet_info->ip_dscp = packet_info->ipv6_dscp;
    packet_info->ip_ecn = packet_info->ipv6_ecn;
  }
  else {
    // Not IPv4/v6 type
    return true;
  }

  // Parse the L4 header.
  switch ( packet_info->ip_proto ) {
  case IPPROTO_ICMP:
    packet_info->l4_header = packet_info->l3_payload;
    parse_icmp( buf );
    break;

  case IPPROTO_ICMPV6:
    packet_info->l4_header = packet_info->l3_payload;
    parse_icmpv6( buf );
    break;

  case IPPROTO_TCP:
    packet_info->l4_header = packet_info->l3_payload;
    parse_tcp( buf );
    break;

  case IPPROTO_UDP:
    packet_info->l4_header = packet_info->l3_payload;
    parse_udp( buf );
    break;

  case IPPROTO_IGMP:
    packet_info->l4_header = packet_info->l3_payload;
    parse_igmp( buf );
    break;

  case IPPROTO_SCTP:
    packet_info->l4_header = packet_info->l3_payload;
    parse_sctp( buf );
    break;

  case IPPROTO_ETHERIP:
    packet_info->l4_header = packet_info->l3_payload;
    parse_etherip( buf );
    break;

  default:
    // Unknown L4 type
    break;
  }

  return true;

}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
