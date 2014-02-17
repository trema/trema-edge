/*
 * Author: Yasunobu Chiba
 *
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


#include <assert.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <strings.h>
#include "oxm_byteorder.h"
#include "byteorder.h"
#include "log.h"
#include "wrapper.h"


#ifdef UNIT_TESTING

#define static

#endif


static void
hton_oxm_match_header( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  *dst = htonl( *src );
}


static void
hton_oxm_match_8( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  hton_oxm_match_header( dst, src );

  const uint8_t *h = ( const uint8_t * ) ( ( const char * ) src + sizeof( oxm_match_header ) );
  uint8_t *n = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
  *n = *h;
}


static void
hton_oxm_match_16( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  hton_oxm_match_header( dst, src );

  const uint16_t *h = ( const uint16_t * ) ( ( const char * ) src + sizeof( oxm_match_header ) );
  uint16_t *n = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
  *n = htons( *h );
}


static void
hton_oxm_match_16w( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  hton_oxm_match_header( dst, src );

  const uint16_t *value_h = ( const uint16_t * ) ( ( const char * ) src + sizeof( oxm_match_header ) );
  uint16_t *value_n = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
  *value_n = htons( *value_h );

  const uint16_t *mask_h = ( const uint16_t * ) ( ( const char * ) value_h + sizeof( uint16_t ) );
  uint16_t *mask_n = ( uint16_t * ) ( ( char * ) value_n + sizeof( uint16_t ) );
  *mask_n = htons( *mask_h );
}


static void
hton_oxm_match_32( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  hton_oxm_match_header( dst, src );

  const uint32_t *h = ( const uint32_t * ) ( ( const char * ) src + sizeof( oxm_match_header ) );
  uint32_t *n = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
  *n = htonl( *h );
}


static void
hton_oxm_match_32w( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  hton_oxm_match_header( dst, src );

  const uint32_t *value_h = ( const uint32_t * ) ( ( const char * ) src + sizeof( oxm_match_header ) );
  uint32_t *value_n = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
  *value_n = htonl( *value_h );

  const uint32_t *mask_h = ( const uint32_t * ) ( ( const char * ) value_h + sizeof( uint32_t ) );
  uint32_t *mask_n = ( uint32_t * ) ( ( char * ) value_n + sizeof( uint32_t ) );
  *mask_n = htonl( *mask_h );
}


static void
hton_oxm_match_64( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  hton_oxm_match_header( dst, src );

  const uint64_t *h = ( const uint64_t * ) ( ( const char * ) src + sizeof( oxm_match_header ) );
  uint64_t *n = ( uint64_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
  *n = htonll( *h );
}


static void
hton_oxm_match_64w( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  hton_oxm_match_header( dst, src );

  const uint64_t *value_h = ( const uint64_t * ) ( ( const char * ) src + sizeof( oxm_match_header ) );
  uint64_t *value_n = ( uint64_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
  *value_n = htonll( *value_h );

  const uint64_t *mask_h = ( const uint64_t * ) ( ( const char * ) value_h + sizeof( uint64_t ) );
  uint64_t *mask_n = ( uint64_t * ) ( ( char * ) value_n + sizeof( uint64_t ) );
  *mask_n = htonll( *mask_h );
}


void hton_oxm_match_in_port( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_IN_PORT || *src == OXM_OF_IN_PHY_PORT );

  hton_oxm_match_32( dst, src );
}


void hton_oxm_match_metadata( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_METADATA || *src == OXM_OF_METADATA_W );

  if ( OXM_HASMASK( *src ) ) {
    return hton_oxm_match_64w( dst, src );
  }

  hton_oxm_match_64( dst, src );
}


void hton_oxm_match_eth_addr( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_ETH_DST || *src == OXM_OF_ETH_DST_W ||
          *src == OXM_OF_ETH_SRC || *src == OXM_OF_ETH_SRC_W ||
          *src == OXM_OF_ARP_SHA || *src == OXM_OF_ARP_SHA_W ||
          *src == OXM_OF_ARP_THA || *src == OXM_OF_ARP_THA_W ||
          *src == OXM_OF_IPV6_ND_SLL || *src == OXM_OF_IPV6_ND_TLL );

  uint8_t length = OXM_LENGTH( *src );
  hton_oxm_match_header( dst, src );
  memmove( ( char * ) dst + sizeof( oxm_match_header ), ( const char * ) src + sizeof( oxm_match_header ), length );
}


void hton_oxm_match_eth_type( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_ETH_TYPE );

  hton_oxm_match_16( dst, src );
}


void hton_oxm_match_vlan_vid( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_VLAN_VID || *src == OXM_OF_VLAN_VID_W );

  if ( OXM_HASMASK( *src ) ) {
    return hton_oxm_match_16w( dst, src );
  }

  hton_oxm_match_16( dst, src );
}


void hton_oxm_match_vlan_pcp( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_VLAN_PCP );

  hton_oxm_match_8( dst, src );
}


void hton_oxm_match_ip_dscp( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_IP_DSCP );

  hton_oxm_match_8( dst, src );
}


void hton_oxm_match_ip_ecn( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_IP_ECN );

  hton_oxm_match_8( dst, src );
}


void hton_oxm_match_ip_proto( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_IP_PROTO );

  hton_oxm_match_8( dst, src );
}


void hton_oxm_match_ipv4_addr( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_IPV4_SRC || *src == OXM_OF_IPV4_SRC_W ||
          *src == OXM_OF_IPV4_DST || *src == OXM_OF_IPV4_DST_W );

  if ( OXM_HASMASK( *src ) ) {
    return hton_oxm_match_32w( dst, src );
  }

  hton_oxm_match_32( dst, src );
}


void hton_oxm_match_tcp_port( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_TCP_SRC || *src == OXM_OF_TCP_DST );

  hton_oxm_match_16( dst, src );
}


void hton_oxm_match_udp_port( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_UDP_SRC || *src == OXM_OF_UDP_DST );

  hton_oxm_match_16( dst, src );
}


void hton_oxm_match_sctp_port( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_SCTP_SRC || *src == OXM_OF_SCTP_DST );

  hton_oxm_match_16( dst, src );
}


void hton_oxm_match_icmpv4_type( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_ICMPV4_TYPE );

  hton_oxm_match_8( dst, src );
}


void hton_oxm_match_icmpv4_code( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_ICMPV4_CODE );

  hton_oxm_match_8( dst, src );
}


void hton_oxm_match_arp_op( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_ARP_OP );

  hton_oxm_match_16( dst, src );
}


void hton_oxm_match_arp_pa( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_ARP_SPA || *src == OXM_OF_ARP_SPA_W ||
          *src == OXM_OF_ARP_TPA || *src == OXM_OF_ARP_TPA_W );

  if ( OXM_HASMASK( *src ) ) {
    return hton_oxm_match_32w( dst, src );
  }

  hton_oxm_match_32( dst, src );
}


void hton_oxm_match_arp_ha( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_ARP_SHA || *src == OXM_OF_ARP_SHA_W ||
          *src == OXM_OF_ARP_THA || *src == OXM_OF_ARP_THA_W );

  hton_oxm_match_eth_addr( dst, src );
}


void hton_oxm_match_ipv6_addr( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_IPV6_SRC || *src == OXM_OF_IPV6_SRC_W ||
          *src == OXM_OF_IPV6_DST || *src == OXM_OF_IPV6_DST_W ||
          *src == OXM_OF_IPV6_ND_TARGET );

  uint8_t length = OXM_LENGTH( *src );
  hton_oxm_match_header( dst, src );
  memmove( ( char * ) dst + sizeof( oxm_match_header ), ( const char * ) src + sizeof( oxm_match_header ), length );
}


void hton_oxm_match_ipv6_flabel( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_IPV6_FLABEL || *src == OXM_OF_IPV6_FLABEL_W );

  if ( OXM_HASMASK( *src ) ) {
    return hton_oxm_match_32w( dst, src );
  }

  hton_oxm_match_32( dst, src );
}


void hton_oxm_match_icmpv6_type( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_ICMPV6_TYPE );

  hton_oxm_match_8( dst, src );
}


void hton_oxm_match_icmpv6_code( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_ICMPV6_CODE );

  hton_oxm_match_8( dst, src );
}


void hton_oxm_match_ipv6_nd_target( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_IPV6_ND_TARGET );

  hton_oxm_match_ipv6_addr( dst, src );
}


void hton_oxm_match_ipv6_nd_ll( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_IPV6_ND_SLL || *src == OXM_OF_IPV6_ND_TLL );

  hton_oxm_match_eth_addr( dst, src );
}


void hton_oxm_match_mpls_label( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_MPLS_LABEL );

  hton_oxm_match_32( dst, src );
}


void hton_oxm_match_mpls_tc( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_MPLS_TC );

  hton_oxm_match_8( dst, src );
}


void hton_oxm_match_mpls_bos( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_MPLS_BOS );

  hton_oxm_match_8( dst, src );
}


void hton_oxm_match_pbb_isid( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_PBB_ISID || *src == OXM_OF_PBB_ISID_W );

  hton_oxm_match_header( dst, src );
  if ( dst != src ) {
    if ( OXM_HASMASK( *src ) ) {
      memcpy(( ( char * ) dst + sizeof( oxm_match_header ) ), ( ( const char * ) src + sizeof( oxm_match_header ) ), 6);
    }
    else {
      memcpy(( ( char * ) dst + sizeof( oxm_match_header ) ), ( ( const char * ) src + sizeof( oxm_match_header ) ), 3);
    }
  }
}


void hton_oxm_match_tunnel_id( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_TUNNEL_ID || *src == OXM_OF_TUNNEL_ID_W );

  if ( OXM_HASMASK( *src ) ) {
    return hton_oxm_match_64w( dst, src );
  }

  hton_oxm_match_64( dst, src );
}


void hton_oxm_match_ipv6_exthdr( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );
  assert( *src == OXM_OF_IPV6_EXTHDR || *src == OXM_OF_IPV6_EXTHDR_W );

  if ( OXM_HASMASK( *src ) ) {
    return hton_oxm_match_16w( dst, src );
  }

  hton_oxm_match_16( dst, src );
}


void hton_oxm_match( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  switch ( *src ) {
    case OXM_OF_IN_PORT:
    case OXM_OF_IN_PHY_PORT:
    {
      hton_oxm_match_in_port( dst, src );
    }
    break;

    case OXM_OF_METADATA:
    case OXM_OF_METADATA_W:
    {
      hton_oxm_match_metadata( dst, src );
    }
    break;

    case OXM_OF_ETH_DST:
    case OXM_OF_ETH_DST_W:
    case OXM_OF_ETH_SRC:
    case OXM_OF_ETH_SRC_W:
    {
      hton_oxm_match_eth_addr( dst, src );
    }
    break;

    case OXM_OF_ETH_TYPE:
    {
      hton_oxm_match_eth_type( dst, src );
    }
    break;

    case OXM_OF_VLAN_VID:
    case OXM_OF_VLAN_VID_W:
    {
      hton_oxm_match_vlan_vid( dst, src );
    }
    break;

    case OXM_OF_VLAN_PCP:
    {
      hton_oxm_match_vlan_pcp( dst, src );
    }
    break;

    case OXM_OF_IP_DSCP:
    {
      hton_oxm_match_ip_dscp( dst, src );
    }
    break;

    case OXM_OF_IP_ECN:
    {
      hton_oxm_match_ip_ecn( dst, src );
    }
    break;

    case OXM_OF_IP_PROTO:
    {
      hton_oxm_match_ip_proto( dst, src );
    }
    break;

    case OXM_OF_IPV4_SRC:
    case OXM_OF_IPV4_SRC_W:
    case OXM_OF_IPV4_DST:
    case OXM_OF_IPV4_DST_W:
    {
      hton_oxm_match_ipv4_addr( dst, src );
    }
    break;

    case OXM_OF_TCP_SRC:
    case OXM_OF_TCP_DST:
    {
      hton_oxm_match_tcp_port( dst, src );
    }
    break;

    case OXM_OF_UDP_SRC:
    case OXM_OF_UDP_DST:
    {
      hton_oxm_match_udp_port( dst, src );
    }
    break;

    case OXM_OF_SCTP_SRC:
    case OXM_OF_SCTP_DST:
    {
      hton_oxm_match_sctp_port( dst, src );
    }
    break;

    case OXM_OF_ICMPV4_TYPE:
    {
      hton_oxm_match_icmpv4_type( dst, src );
    }
    break;

    case OXM_OF_ICMPV4_CODE:
    {
      hton_oxm_match_icmpv4_code( dst, src );
    }
    break;

    case OXM_OF_ARP_OP:
    {
      hton_oxm_match_arp_op( dst, src );
    }
    break;

    case OXM_OF_ARP_SPA:
    case OXM_OF_ARP_SPA_W:
    case OXM_OF_ARP_TPA:
    case OXM_OF_ARP_TPA_W:
    {
      hton_oxm_match_arp_pa( dst, src );
    }
    break;

    case OXM_OF_ARP_SHA:
    case OXM_OF_ARP_SHA_W:
    case OXM_OF_ARP_THA:
    case OXM_OF_ARP_THA_W:
    {
      hton_oxm_match_arp_ha( dst, src );
    }
    break;

    case OXM_OF_IPV6_SRC:
    case OXM_OF_IPV6_SRC_W:
    case OXM_OF_IPV6_DST:
    case OXM_OF_IPV6_DST_W:
    {
      hton_oxm_match_ipv6_addr( dst, src );
    }
    break;

    case OXM_OF_IPV6_FLABEL:
    case OXM_OF_IPV6_FLABEL_W:
    {
      hton_oxm_match_ipv6_flabel( dst, src );
    }
    break;

    case OXM_OF_ICMPV6_TYPE:
    {
      hton_oxm_match_icmpv6_type( dst, src );
    }
    break;

    case OXM_OF_ICMPV6_CODE:
    {
      hton_oxm_match_icmpv6_code( dst, src );
    }
    break;

    case OXM_OF_IPV6_ND_TARGET:
    {
      hton_oxm_match_ipv6_nd_target( dst, src );
    }
    break;

    case OXM_OF_IPV6_ND_SLL:
    case OXM_OF_IPV6_ND_TLL:
    {
      hton_oxm_match_ipv6_nd_ll( dst, src );
    }
    break;

    case OXM_OF_MPLS_LABEL:
    {
      hton_oxm_match_mpls_label( dst, src );
    }
    break;

    case OXM_OF_MPLS_TC:
    {
      hton_oxm_match_mpls_tc( dst, src );
    }
    break;

    case OXM_OF_MPLS_BOS:
    {
      hton_oxm_match_mpls_bos( dst, src );
    }
    break;

    case OXM_OF_PBB_ISID:
    case OXM_OF_PBB_ISID_W:
    {
      hton_oxm_match_pbb_isid( dst, src );
    }
    break;

    case OXM_OF_TUNNEL_ID:
    case OXM_OF_TUNNEL_ID_W:
    {
      hton_oxm_match_tunnel_id( dst, src );
    }
    break;

    case OXM_OF_IPV6_EXTHDR:
    case OXM_OF_IPV6_EXTHDR_W:
    {
      hton_oxm_match_ipv6_exthdr( dst, src );
    }
    break;

    default:
    {
      die( "Undefined match type ( header = %#x, type = %#x, hash_mask = %u, length = %u ).",
             *src, OXM_TYPE( *src ), OXM_HASMASK( *src ), OXM_LENGTH( *src ) );
    }
    break;
  }
}


void hton_match( struct ofp_match *dst, const struct ofp_match *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  uint16_t total_len = src->length;
  uint16_t oxms_length = 0;
  uint16_t oxm_length = 0;
  uint16_t pad_len = 0;

  dst->type = htons( src->type );
  dst->length = htons( src->length );

  if ( total_len >= offsetof( struct ofp_match, oxm_fields ) ) {
    oxms_length = ( uint16_t ) ( total_len - offsetof( struct ofp_match, oxm_fields ) );

    const oxm_match_header *s_oxm = ( const oxm_match_header * ) src->oxm_fields;
    oxm_match_header *d_oxm = ( oxm_match_header * ) dst->oxm_fields;

    while ( oxms_length > sizeof( oxm_match_header ) ) {
      oxm_length = ( uint16_t ) ( sizeof( oxm_match_header ) + OXM_LENGTH( *s_oxm ) );
      if ( oxms_length < oxm_length ) {
        break;
      }

      hton_oxm_match( d_oxm, s_oxm );

      oxms_length = ( uint16_t ) ( oxms_length - oxm_length );
      s_oxm = ( const oxm_match_header * ) ( ( const char * ) s_oxm + oxm_length );
      d_oxm = ( oxm_match_header * ) ( ( char * ) d_oxm + oxm_length );
    }
  }

  pad_len = ( uint16_t ) PADLEN_TO_64( total_len );
  if ( pad_len > 0 ) {
    memset( ( char * ) dst + total_len, 0, pad_len );
  }
}


#define ntoh_oxm_match_header hton_oxm_match_header
#define ntoh_oxm_match_8 hton_oxm_match_8
#define ntoh_oxm_match_16 hton_oxm_match_16
#define ntoh_oxm_match_16w hton_oxm_match_16w
#define ntoh_oxm_match_32 hton_oxm_match_32
#define ntoh_oxm_match_32w hton_oxm_match_32w
#define ntoh_oxm_match_64 hton_oxm_match_64
#define ntoh_oxm_match_64w hton_oxm_match_64w


void ntoh_oxm_match_in_port( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  ntoh_oxm_match_32( dst, src );
  assert( *dst == OXM_OF_IN_PORT || *dst == OXM_OF_IN_PHY_PORT );
}


void ntoh_oxm_match_metadata( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  if ( OXM_HASMASK( ntohl( *src ) ) ) {
    ntoh_oxm_match_64w( dst, src );
    assert( *dst == OXM_OF_METADATA_W );
    return;
  }

  ntoh_oxm_match_64( dst, src );
  assert( *dst == OXM_OF_METADATA );
}


void ntoh_oxm_match_eth_addr( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  ntoh_oxm_match_header( dst, src );
  assert( *dst == OXM_OF_ETH_DST || *dst == OXM_OF_ETH_DST_W ||
          *dst == OXM_OF_ETH_SRC || *dst == OXM_OF_ETH_SRC_W ||
          *dst == OXM_OF_ARP_SHA || *dst == OXM_OF_ARP_SHA_W ||
          *dst == OXM_OF_ARP_THA || *dst == OXM_OF_ARP_THA_W ||
          *dst == OXM_OF_IPV6_ND_SLL || *dst == OXM_OF_IPV6_ND_TLL );
  uint8_t length = OXM_LENGTH( *dst );

  memmove( ( char * ) dst + sizeof( oxm_match_header ), ( const char * ) src + sizeof( oxm_match_header ), length );
}


void ntoh_oxm_match_eth_type( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  ntoh_oxm_match_16( dst, src );
  assert( *dst == OXM_OF_ETH_TYPE );
}


void ntoh_oxm_match_vlan_vid( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  if ( OXM_HASMASK( ntohl( *src ) ) ) {
    ntoh_oxm_match_16w( dst, src );
    assert( *dst == OXM_OF_VLAN_VID_W );
    return;
  }

  ntoh_oxm_match_16( dst, src );
  assert( *dst == OXM_OF_VLAN_VID );
}


void ntoh_oxm_match_vlan_pcp( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  ntoh_oxm_match_8( dst, src );
  assert( *dst == OXM_OF_VLAN_PCP );
}


void ntoh_oxm_match_ip_dscp( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  ntoh_oxm_match_8( dst, src );
  assert( *dst == OXM_OF_IP_DSCP );
}


void ntoh_oxm_match_ip_ecn( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  ntoh_oxm_match_8( dst, src );
  assert( *dst == OXM_OF_IP_ECN );
}


void ntoh_oxm_match_ip_proto( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  ntoh_oxm_match_8( dst, src );
  assert( *dst == OXM_OF_IP_PROTO );
}


void ntoh_oxm_match_ipv4_addr( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  if ( OXM_HASMASK( ntohl( *src ) ) ) {
    ntoh_oxm_match_32w( dst, src );
    assert( *dst == OXM_OF_IPV4_SRC_W || *dst == OXM_OF_IPV4_DST_W );
    return;
  }

  ntoh_oxm_match_32( dst, src );
  assert( *dst == OXM_OF_IPV4_SRC || *dst == OXM_OF_IPV4_DST );
}


void ntoh_oxm_match_tcp_port( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  ntoh_oxm_match_16( dst, src );
  assert( *dst == OXM_OF_TCP_SRC || *dst == OXM_OF_TCP_DST );
}


void ntoh_oxm_match_udp_port( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  ntoh_oxm_match_16( dst, src );
  assert( *dst == OXM_OF_UDP_SRC || *dst == OXM_OF_UDP_DST );
}


void ntoh_oxm_match_sctp_port( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  ntoh_oxm_match_16( dst, src );
  assert( *dst == OXM_OF_SCTP_SRC || *dst == OXM_OF_SCTP_DST );
}


void ntoh_oxm_match_icmpv4_type( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  ntoh_oxm_match_8( dst, src );
  assert( *dst == OXM_OF_ICMPV4_TYPE );
}


void ntoh_oxm_match_icmpv4_code( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  ntoh_oxm_match_8( dst, src );
  assert( *dst == OXM_OF_ICMPV4_CODE );
}


void ntoh_oxm_match_arp_op( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  ntoh_oxm_match_16( dst, src );
  assert( *dst == OXM_OF_ARP_OP );
}


void ntoh_oxm_match_arp_pa( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  if ( OXM_HASMASK( ntohl( *src ) ) ) {
    ntoh_oxm_match_32w( dst, src );
  assert( *dst == OXM_OF_ARP_SPA_W || *dst == OXM_OF_ARP_TPA_W );
    return;
  }

  ntoh_oxm_match_32( dst, src );
  assert( *dst == OXM_OF_ARP_SPA || *dst == OXM_OF_ARP_TPA );
}


void ntoh_oxm_match_arp_ha( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  ntoh_oxm_match_eth_addr( dst, src );
  assert( *dst == OXM_OF_ARP_SHA || *dst == OXM_OF_ARP_SHA_W ||
          *dst == OXM_OF_ARP_THA || *dst == OXM_OF_ARP_THA_W );
}


void ntoh_oxm_match_ipv6_addr( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  ntoh_oxm_match_header( dst, src );
  assert( *dst == OXM_OF_IPV6_SRC || *dst == OXM_OF_IPV6_SRC_W ||
          *dst == OXM_OF_IPV6_DST || *dst == OXM_OF_IPV6_DST_W ||
          *dst == OXM_OF_IPV6_ND_TARGET );
  uint8_t length = OXM_LENGTH( *dst );

  memmove( ( char * ) dst + sizeof( oxm_match_header ), ( const char * ) src + sizeof( oxm_match_header ), length );
}


void ntoh_oxm_match_ipv6_flabel( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  if ( OXM_HASMASK( ntohl( *src ) ) ) {
    ntoh_oxm_match_32w( dst, src );
    assert( *dst == OXM_OF_IPV6_FLABEL_W );
    return;
  }

  ntoh_oxm_match_32( dst, src );
  assert( *dst == OXM_OF_IPV6_FLABEL );
}


void ntoh_oxm_match_icmpv6_type( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  ntoh_oxm_match_8( dst, src );
  assert( *dst == OXM_OF_ICMPV6_TYPE );
}


void ntoh_oxm_match_icmpv6_code( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  ntoh_oxm_match_8( dst, src );
  assert( *dst == OXM_OF_ICMPV6_CODE );
}


void ntoh_oxm_match_ipv6_nd_target( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  ntoh_oxm_match_ipv6_addr( dst, src );
  assert( *dst == OXM_OF_IPV6_ND_TARGET );
}


void ntoh_oxm_match_ipv6_nd_ll( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  ntoh_oxm_match_eth_addr( dst, src );
  assert( *dst == OXM_OF_IPV6_ND_SLL || *dst == OXM_OF_IPV6_ND_TLL );
}


void ntoh_oxm_match_mpls_label( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  ntoh_oxm_match_32( dst, src );
  assert( *dst == OXM_OF_MPLS_LABEL );
}


void ntoh_oxm_match_mpls_tc( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  ntoh_oxm_match_8( dst, src );
  assert( *dst == OXM_OF_MPLS_TC );
}


void ntoh_oxm_match_mpls_bos( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  ntoh_oxm_match_8( dst, src );
  assert( *dst == OXM_OF_MPLS_BOS );
}


void ntoh_oxm_match_pbb_isid( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  ntoh_oxm_match_header( dst, src );
  if ( OXM_HASMASK( ntohl( *src ) ) ) {
    assert( *dst == OXM_OF_PBB_ISID_W );
    memcpy(( ( char * ) dst + sizeof( oxm_match_header ) ), ( ( const char * ) src + sizeof( oxm_match_header ) ), 6);
  }
  else {
    assert( *dst == OXM_OF_PBB_ISID );
    memcpy(( ( char * ) dst + sizeof( oxm_match_header ) ), ( ( const char * ) src + sizeof( oxm_match_header ) ), 3);
  }
}


void ntoh_oxm_match_tunnel_id( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  if ( OXM_HASMASK( ntohl( *src ) ) ) {
    ntoh_oxm_match_64w( dst, src );
    assert( *dst == OXM_OF_TUNNEL_ID_W );
    return;
  }

  ntoh_oxm_match_64( dst, src );
  assert( *dst == OXM_OF_TUNNEL_ID );
}


void ntoh_oxm_match_ipv6_exthdr( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  if ( OXM_HASMASK( ntohl( *src ) ) ) {
    ntoh_oxm_match_16w( dst, src );
    assert( *dst == OXM_OF_IPV6_EXTHDR_W );
    return;
  }

  ntoh_oxm_match_16( dst, src );
  assert( *dst == OXM_OF_IPV6_EXTHDR );
}


void ntoh_oxm_match( oxm_match_header *dst, const oxm_match_header *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  switch ( ntohl( *src ) ) {
    case OXM_OF_IN_PORT:
    case OXM_OF_IN_PHY_PORT:
    {
      ntoh_oxm_match_in_port( dst, src );
    }
    break;

    case OXM_OF_METADATA:
    case OXM_OF_METADATA_W:
    {
      ntoh_oxm_match_metadata( dst, src );
    }
    break;

    case OXM_OF_ETH_DST:
    case OXM_OF_ETH_DST_W:
    case OXM_OF_ETH_SRC:
    case OXM_OF_ETH_SRC_W:
    {
      ntoh_oxm_match_eth_addr( dst, src );
    }
    break;

    case OXM_OF_ETH_TYPE:
    {
      ntoh_oxm_match_eth_type( dst, src );
    }
    break;

    case OXM_OF_VLAN_VID:
    case OXM_OF_VLAN_VID_W:
    {
      ntoh_oxm_match_vlan_vid( dst, src );
    }
    break;

    case OXM_OF_VLAN_PCP:
    {
      ntoh_oxm_match_vlan_pcp( dst, src );
    }
    break;

    case OXM_OF_IP_DSCP:
    {
      ntoh_oxm_match_ip_dscp( dst, src );
    }
    break;

    case OXM_OF_IP_ECN:
    {
      ntoh_oxm_match_ip_ecn( dst, src );
    }
    break;

    case OXM_OF_IP_PROTO:
    {
      ntoh_oxm_match_ip_proto( dst, src );
    }
    break;

    case OXM_OF_IPV4_SRC:
    case OXM_OF_IPV4_SRC_W:
    case OXM_OF_IPV4_DST:
    case OXM_OF_IPV4_DST_W:
    {
      ntoh_oxm_match_ipv4_addr( dst, src );
    }
    break;

    case OXM_OF_TCP_SRC:
    case OXM_OF_TCP_DST:
    {
      ntoh_oxm_match_tcp_port( dst, src );
    }
    break;

    case OXM_OF_UDP_SRC:
    case OXM_OF_UDP_DST:
    {
      ntoh_oxm_match_udp_port( dst, src );
    }
    break;

    case OXM_OF_SCTP_SRC:
    case OXM_OF_SCTP_DST:
    {
      ntoh_oxm_match_sctp_port( dst, src );
    }
    break;

    case OXM_OF_ICMPV4_TYPE:
    {
      ntoh_oxm_match_icmpv4_type( dst, src );
    }
    break;

    case OXM_OF_ICMPV4_CODE:
    {
      ntoh_oxm_match_icmpv4_code( dst, src );
    }
    break;

    case OXM_OF_ARP_OP:
    {
      ntoh_oxm_match_arp_op( dst, src );
    }
    break;

    case OXM_OF_ARP_SPA:
    case OXM_OF_ARP_SPA_W:
    case OXM_OF_ARP_TPA:
    case OXM_OF_ARP_TPA_W:
    {
      ntoh_oxm_match_arp_pa( dst, src );
    }
    break;

    case OXM_OF_ARP_SHA:
    case OXM_OF_ARP_SHA_W:
    case OXM_OF_ARP_THA:
    case OXM_OF_ARP_THA_W:
    {
      ntoh_oxm_match_arp_ha( dst, src );
    }
    break;

    case OXM_OF_IPV6_SRC:
    case OXM_OF_IPV6_SRC_W:
    case OXM_OF_IPV6_DST:
    case OXM_OF_IPV6_DST_W:
    {
      ntoh_oxm_match_ipv6_addr( dst, src );
    }
    break;

    case OXM_OF_IPV6_FLABEL:
    case OXM_OF_IPV6_FLABEL_W:
    {
      ntoh_oxm_match_ipv6_flabel( dst, src );
    }
    break;

    case OXM_OF_ICMPV6_TYPE:
    {
      ntoh_oxm_match_icmpv6_type( dst, src );
    }
    break;

    case OXM_OF_ICMPV6_CODE:
    {
      ntoh_oxm_match_icmpv6_code( dst, src );
    }
    break;

    case OXM_OF_IPV6_ND_TARGET:
    {
      ntoh_oxm_match_ipv6_nd_target( dst, src );
    }
    break;

    case OXM_OF_IPV6_ND_SLL:
    case OXM_OF_IPV6_ND_TLL:
    {
      ntoh_oxm_match_ipv6_nd_ll( dst, src );
    }
    break;

    case OXM_OF_MPLS_LABEL:
    {
      ntoh_oxm_match_mpls_label( dst, src );
    }
    break;

    case OXM_OF_MPLS_TC:
    {
      ntoh_oxm_match_mpls_tc( dst, src );
    }
    break;

    case OXM_OF_MPLS_BOS:
    {
      ntoh_oxm_match_mpls_bos( dst, src );
    }
    break;

    case OXM_OF_PBB_ISID:
    case OXM_OF_PBB_ISID_W:
    {
      ntoh_oxm_match_pbb_isid( dst, src );
    }
    break;

    case OXM_OF_TUNNEL_ID:
    case OXM_OF_TUNNEL_ID_W:
    {
      ntoh_oxm_match_tunnel_id( dst, src );
    }
    break;

    case OXM_OF_IPV6_EXTHDR:
    case OXM_OF_IPV6_EXTHDR_W:
    {
      ntoh_oxm_match_ipv6_exthdr( dst, src );
    }
    break;

    default:
    {
      die( "Undefined match type ( header = %#x, type = %#x, hash_mask = %u, length = %u ).",
           ntohl( *src ), OXM_TYPE( ntohl( *src ) ), OXM_HASMASK( ntohl( *src ) ), OXM_LENGTH( ntohl( *src ) ) );
    }
    break;
  }
}


void ntoh_match( struct ofp_match *dst, const struct ofp_match *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  uint16_t oxms_length = 0;
  uint16_t oxm_length = 0;
  uint16_t pad_len = 0;

  dst->type = ntohs( src->type );
  dst->length = ntohs( src->length );

  if ( dst->length >= offsetof( struct ofp_match, oxm_fields ) ) {
    oxms_length = ( uint16_t ) ( dst->length - offsetof( struct ofp_match, oxm_fields ) );
    const oxm_match_header *s_oxm = ( const oxm_match_header * ) src->oxm_fields;
    oxm_match_header *d_oxm = ( oxm_match_header * ) dst->oxm_fields;

    while ( oxms_length > sizeof( oxm_match_header ) ) {
      oxm_length = ( uint16_t ) ( sizeof( oxm_match_header ) + OXM_LENGTH( ntohl( *s_oxm ) ) );
      if ( oxms_length < oxm_length ) {
        break;
      }

      ntoh_oxm_match( d_oxm, s_oxm );

      oxms_length = ( uint16_t ) ( oxms_length - oxm_length );
      s_oxm = ( const oxm_match_header * ) ( ( const char * ) s_oxm + oxm_length );
      d_oxm = ( oxm_match_header * ) ( ( char * ) d_oxm + oxm_length );
    }
  }

  pad_len = ( uint16_t ) PADLEN_TO_64( dst->length );
  if ( pad_len > 0 ) {
    memset( ( char * ) dst + dst->length, 0, pad_len );
  }
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
