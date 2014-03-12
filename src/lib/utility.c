/*
 * Author: Yasuhito Takamiya <yasuhito@gmail.com>
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


#include <arpa/inet.h>
#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <inttypes.h>
#include <stddef.h>
#include "bool.h"
#include "checks.h"
#include "log.h"
#include "trema_wrapper.h"
#include "utility.h"


static void
_die( const char *format, ... ) {
  char err[ 1024 ];

  assert( format != NULL );
  va_list args;
  va_start( args, format );
  vsnprintf( err, sizeof( err ), format, args );
  va_end( args );

  critical( err );
  trema_abort();
}
void ( *die )( const char *format, ... ) = _die;


bool
compare_string( const void *x, const void *y ) {
  return strcmp( x, y ) == 0 ? true : false;
}


/**
 * Generates a hash value
 *
 * FNV-1a is used for hashing. See http://isthe.com/chongo/tech/comp/fnv/index.html.
 */
unsigned int
hash_core( const void *key, int size ) {
  // 32 bit offset_basis
  uint32_t hash_value = 0x811c9dc5UL;
  // 32 bit FNV_prime
  const uint32_t prime = 0x01000193UL;
  const unsigned char *c = key;

  for ( int i = 0; i < size; i++ ) {
    hash_value ^= ( unsigned char ) c[ i ];
    hash_value *= prime;
  }

  return ( unsigned int ) hash_value;
}


unsigned int
hash_string( const void *key ) {
  return hash_core( key, ( int ) strlen( key ) );
}


bool
compare_mac( const void *x, const void *y ) {
  return memcmp( x, y, OFP_ETH_ALEN ) == 0 ? true : false;
}


unsigned int
hash_mac( const void *mac ) {
  return hash_core( mac, OFP_ETH_ALEN );
}


uint64_t
mac_to_uint64( const uint8_t *mac ) {
  return ( ( uint64_t ) mac[ 0 ] << 40 ) +
         ( ( uint64_t ) mac[ 1 ] << 32 ) +
         ( ( uint64_t ) mac[ 2 ] << 24 ) +
         ( ( uint64_t ) mac[ 3 ] << 16 ) +
         ( ( uint64_t ) mac[ 4 ] << 8 ) +
         ( ( uint64_t ) mac[ 5 ] );
}


bool
compare_uint32( const void *x, const void *y ) {
  return *( ( const uint32_t * ) x ) == *( ( const uint32_t * ) y ) ? true : false;
}


unsigned int
hash_uint32( const void *key ) {
  return ( *( ( const uint32_t * ) key ) % UINT_MAX );
}


bool
compare_datapath_id( const void *x, const void *y ) {
  return *( ( const uint64_t * ) x ) == *( ( const uint64_t * ) y ) ? true : false;
}


unsigned int
hash_datapath_id( const void *key ) {
  return hash_core( key, ( int ) sizeof( uint64_t ) );
}


bool
string_to_datapath_id( const char *str, uint64_t *datapath_id ) {
  char *endp = NULL;
  *datapath_id = ( uint64_t ) strtoull( str, &endp, 0 );
  if ( *endp != '\0' ) {
    return false;
  }
  return true;
}


static bool
oxm_match_8_to_hex_string( const oxm_match_header *header, char *str, size_t length, const char *key ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( key != NULL );

  const uint8_t *value = ( const uint8_t * ) header + sizeof( oxm_match_header );
  int ret = snprintf( str, length, "%s = 0x%02x", key, *value );
  if ( ( ret >= ( int ) length ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
oxm_match_16_to_dec_string( const oxm_match_header *header, char *str, size_t length, const char *key ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( key != NULL );

  const uint16_t *value = ( const uint16_t * ) ( ( const char * ) header + sizeof( oxm_match_header ) );
  int ret = snprintf( str, length, "%s = %u", key, *value );
  if ( ( ret >= ( int ) length ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
oxm_match_16_to_hex_string( const oxm_match_header *header, char *str, size_t length, const char *key ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( key != NULL );

  const uint16_t *value = ( const uint16_t * ) ( ( const char * ) header + sizeof( oxm_match_header ) );
  int ret = snprintf( str, length, "%s = 0x%04x", key, *value );
  if ( ( ret >= ( int ) length ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
oxm_match_16w_to_hex_string( const oxm_match_header *header, char *str, size_t length, const char *key ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( key != NULL );

  const uint16_t *value = ( const uint16_t * ) ( ( const char * ) header + sizeof( oxm_match_header ) );
  const uint16_t *mask = ( const uint16_t * ) ( ( const char * ) value + sizeof( uint16_t ) );
  int ret = snprintf( str, length, "%s = 0x%04x/0x%04x", key, *value, *mask );
  if ( ( ret >= ( int ) length ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


#if 0
static bool
oxm_match_24_to_dec_string( const oxm_match_header *header, char *str, size_t length, const char *key ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( key != NULL );

  const uint8_t *v = ( const uint8_t * ) ( ( const char * ) header + sizeof( oxm_match_header ) );
  int ret = snprintf( str, length, "%s = %u", key, (v[0]<<16)+(v[1]<<8)+v[2] );
  if ( ( ret >= ( int ) length ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}
#endif


static bool
oxm_match_24_to_hex_string( const oxm_match_header *header, char *str, size_t length, const char *key ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( key != NULL );

  const uint8_t *v = ( const uint8_t * ) ( ( const char * ) header + sizeof( oxm_match_header ) );
  int ret = snprintf( str, length, "%s = 0x%06x", key, (v[0]<<16)+(v[1]<<8)+v[2] );
  if ( ( ret >= ( int ) length ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


#if 0
static bool
oxm_match_24w_to_dec_string( const oxm_match_header *header, char *str, size_t length, const char *key ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( key != NULL );

  const uint8_t *v = ( const uint8_t * ) ( ( const char * ) header + sizeof( oxm_match_header ) );
  int ret = snprintf( str, length, "%s = %u/%u", key, (v[0]<<16)+(v[1]<<8)+v[2], (v[3]<<16)+(v[4]<<8)+v[5] );
  if ( ( ret >= ( int ) length ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}
#endif


static bool
oxm_match_24w_to_hex_string( const oxm_match_header *header, char *str, size_t length, const char *key ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( key != NULL );

  const uint8_t *v = ( const uint8_t * ) ( ( const char * ) header + sizeof( oxm_match_header ) );
  int ret = snprintf( str, length, "%s = 0x%06x/0x%06x", key, (v[0]<<16)+(v[1]<<8)+v[2], (v[3]<<16)+(v[4]<<8)+v[5] );
  if ( ( ret >= ( int ) length ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
oxm_match_32_to_dec_string( const oxm_match_header *header, char *str, size_t length, const char *key ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( key != NULL );

  const uint32_t *value = ( const uint32_t * ) ( ( const char * ) header + sizeof( oxm_match_header ) );
  int ret = snprintf( str, length, "%s = %u", key, *value );
  if ( ( ret >= ( int ) length ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
oxm_match_32_to_hex_string( const oxm_match_header *header, char *str, size_t length, const char *key ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( key != NULL );

  const uint32_t *value = ( const uint32_t * ) ( ( const char * ) header + sizeof( oxm_match_header ) );
  int ret = snprintf( str, length, "%s = 0x%08x", key, *value );
  if ( ( ret >= ( int ) length ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
oxm_match_32w_to_hex_string( const oxm_match_header *header, char *str, size_t length, const char *key ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( key != NULL );

  const uint32_t *value = ( const uint32_t * ) ( ( const char * ) header + sizeof( oxm_match_header ) );
  const uint32_t *mask = ( const uint32_t * ) ( ( const char * ) value + sizeof( uint32_t ) );
  int ret = snprintf( str, length, "%s = 0x%08x/0x%08x", key, *value, *mask );
  if ( ( ret >= ( int ) length ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
oxm_match_64_to_hex_string( const oxm_match_header *header, char *str, size_t length, const char *key ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( key != NULL );

  const uint64_t *value = ( const uint64_t * ) ( ( const char * ) header + sizeof( oxm_match_header ) );
  int ret = snprintf( str, length, "%s = 0x%016" PRIx64, key, *value );
  if ( ( ret >= ( int ) length ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
oxm_match_64w_to_hex_string( const oxm_match_header *header, char *str, size_t length, const char *key ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( key != NULL );

  const uint64_t *value = ( const uint64_t * ) ( ( const char * ) header + sizeof( oxm_match_header ) );
  const uint64_t *mask = ( const uint64_t * ) ( ( const char * ) value + sizeof( uint64_t ) );
  int ret = snprintf( str, length, "%s = 0x%016" PRIx64 "/0x%016" PRIx64, key, *value, *mask );
  if ( ( ret >= ( int ) length ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
oxm_match_eth_addr_to_hex_string( const oxm_match_header *header, char *str, size_t length, const char *key ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( key != NULL );

  const uint8_t *addr = ( const uint8_t * ) header + sizeof( oxm_match_header );
  int ret = snprintf( str, length, "%s = %02x:%02x:%02x:%02x:%02x:%02x",
                      key, addr[ 0 ], addr[ 1 ], addr[ 2 ], addr[ 3 ], addr[ 4 ], addr[ 5 ] );
  if ( ( ret >= ( int ) length ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
oxm_match_eth_addr_w_to_hex_string( const oxm_match_header *header, char *str, size_t length, const char *key ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( key != NULL );

  const uint8_t *addr = ( const uint8_t * ) header + sizeof( oxm_match_header );
  const uint8_t *mask = addr + ( sizeof( uint8_t ) * OFP_ETH_ALEN );
  int ret = snprintf( str, length, "%s = %02x:%02x:%02x:%02x:%02x:%02x/%02x:%02x:%02x:%02x:%02x:%02x",
                      key, addr[ 0 ], addr[ 1 ], addr[ 2 ], addr[ 3 ], addr[ 4 ], addr[ 5 ],
                      mask[ 0 ], mask[ 1 ], mask[ 2 ], mask[ 3 ], mask[ 4 ], mask[ 5 ] );
  if ( ( ret >= ( int ) length ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
oxm_match_ip_addr_to_dec_string( const oxm_match_header *header, char *str, size_t length, const char *key ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( key != NULL );

  const uint32_t *addr = ( const uint32_t * ) ( ( const uint8_t * ) header + sizeof( oxm_match_header ) );
  int ret = snprintf( str, length, "%s = %u.%u.%u.%u",
                      key, ( *addr >> 24 ) & 0xff, ( *addr >> 16 ) & 0xff, ( *addr >> 8 ) & 0xff, *addr & 0xff );
  if ( ( ret >= ( int ) length ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
oxm_match_ip_addr_w_to_dec_string( const oxm_match_header *header, char *str, size_t length, const char *key ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( key != NULL );

  const uint32_t *addr = ( const uint32_t * ) ( ( const uint8_t * ) header + sizeof( oxm_match_header ) );
  const uint32_t *mask = ( const uint32_t * ) ( ( const uint8_t * ) addr + sizeof( uint32_t ) );

  int ret = snprintf( str, length, "%s = %u.%u.%u.%u/%u.%u.%u.%u",
                      key,
                      ( *addr >> 24 ) & 0xff, ( *addr >> 16 ) & 0xff, ( *addr >> 8 ) & 0xff, *addr & 0xff,
                      ( *mask >> 24 ) & 0xff, ( *mask >> 16 ) & 0xff, ( *mask >> 8 ) & 0xff, *mask & 0xff );
  if ( ( ret >= ( int ) length ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
oxm_match_ipv6_addr_to_hex_string( const oxm_match_header *header, char *str, size_t length, const char *key ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( key != NULL );

  const struct in6_addr *addr = ( const struct in6_addr * ) ( ( const char * ) header + sizeof( oxm_match_header ) );
  char addr_str[ INET6_ADDRSTRLEN ];
  inet_ntop( AF_INET6, addr, addr_str, sizeof( addr_str ) );

  int ret = snprintf( str, length, "%s = %s", key, addr_str );
  if ( ( ret >= ( int ) length ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
oxm_match_ipv6_addr_w_to_hex_string( const oxm_match_header *header, char *str, size_t length, const char *key ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( key != NULL );

  const struct in6_addr *addr = ( const struct in6_addr * ) ( ( const char * ) header + sizeof( oxm_match_header ) );
  const struct in6_addr *mask = ( const struct in6_addr * ) ( ( const char * ) addr + sizeof( struct in6_addr ) );
  char addr_str[ INET6_ADDRSTRLEN ];
  inet_ntop( AF_INET6, addr, addr_str, sizeof( addr_str ) );
  char mask_str[ INET6_ADDRSTRLEN ];
  inet_ntop( AF_INET6, mask, mask_str, sizeof( mask_str ) );

  int ret = snprintf( str, length, "%s = %s/%s", key, addr_str, mask_str );
  if ( ( ret >= ( int ) length ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
oxm_match_in_port_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( *header == OXM_OF_IN_PORT );

  return oxm_match_32_to_dec_string( header, str, length, "in_port" );
}


static bool
oxm_match_in_phy_port_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( *header == OXM_OF_IN_PHY_PORT );

  return oxm_match_32_to_dec_string( header, str, length, "in_phy_port" );
}


static bool
oxm_match_metadata_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );

  switch ( *header ) {
    case OXM_OF_METADATA:
      return oxm_match_64_to_hex_string( header, str, length, "metadata" );

    case OXM_OF_METADATA_W:
      return oxm_match_64w_to_hex_string( header, str, length, "metadata" );

    default:
      assert( 0 );
      break;
  }

  return false;
}


static bool
oxm_match_eth_addr_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );

  switch ( *header ) {
    case OXM_OF_ETH_DST:
      return oxm_match_eth_addr_to_hex_string( header, str, length, "eth_dst" );

    case OXM_OF_ETH_DST_W:
      return oxm_match_eth_addr_w_to_hex_string( header, str, length, "eth_dst" );

    case OXM_OF_ETH_SRC:
      return oxm_match_eth_addr_to_hex_string( header, str, length, "eth_src" );

    case OXM_OF_ETH_SRC_W:
      return oxm_match_eth_addr_w_to_hex_string( header, str, length, "eth_src" );

    default:
      assert( 0 );
      break;
  }

  return false;
}


static bool
oxm_match_eth_type_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( *header == OXM_OF_ETH_TYPE );

  return oxm_match_16_to_hex_string( header, str, length, "eth_type" );
}


static bool
oxm_match_vlan_vid_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );

  switch ( *header ) {
    case OXM_OF_VLAN_VID:
      return oxm_match_16_to_hex_string( header, str, length, "vlan_vid" );

    case OXM_OF_VLAN_VID_W:
      return oxm_match_16w_to_hex_string( header, str, length, "vlan_vid" );

    default:
      assert( 0 );
      break;
  }

  return false;
}


static bool
oxm_match_vlan_pcp_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( *header == OXM_OF_VLAN_PCP );

  return oxm_match_8_to_hex_string( header, str, length, "vlan_pcp" );
}


static bool
oxm_match_ip_dscp_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( *header == OXM_OF_IP_DSCP );

  return oxm_match_8_to_hex_string( header, str, length, "ip_dscp" );
}


static bool
oxm_match_ip_ecn_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( *header == OXM_OF_IP_ECN );

  return oxm_match_8_to_hex_string( header, str, length, "ip_ecn" );
}


static bool
oxm_match_ip_proto_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( *header == OXM_OF_IP_PROTO );

  return oxm_match_8_to_hex_string( header, str, length, "ip_proto" );
}


static bool
oxm_match_ip_addr_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );

  switch ( *header ) {
    case OXM_OF_IPV4_SRC:
      return oxm_match_ip_addr_to_dec_string( header, str, length, "ipv4_src" );

    case OXM_OF_IPV4_SRC_W:
      return oxm_match_ip_addr_w_to_dec_string( header, str, length, "ipv4_src" );

    case OXM_OF_IPV4_DST:
      return oxm_match_ip_addr_to_dec_string( header, str, length, "ipv4_dst" );

    case OXM_OF_IPV4_DST_W:
      return oxm_match_ip_addr_w_to_dec_string( header, str, length, "ipv4_dst" );

    default:
      assert( 0 );
      break;
  }

  return false;
}


static bool
oxm_match_tcp_port_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );

  switch ( *header ) {
    case OXM_OF_TCP_SRC:
      return oxm_match_16_to_dec_string( header, str, length, "tcp_src" );

    case OXM_OF_TCP_DST:
      return oxm_match_16_to_dec_string( header, str, length, "tcp_dst" );

    default:
      assert( 0 );
      break;
  }

  return false;
}


static bool
oxm_match_udp_port_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );

  switch ( *header ) {
    case OXM_OF_UDP_SRC:
      return oxm_match_16_to_dec_string( header, str, length, "udp_src" );

    case OXM_OF_UDP_DST:
      return oxm_match_16_to_dec_string( header, str, length, "udp_dst" );

    default:
      assert( 0 );
      break;
  }

  return false;
}


static bool
oxm_match_sctp_port_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );

  switch ( *header ) {
    case OXM_OF_SCTP_SRC:
      return oxm_match_16_to_dec_string( header, str, length, "sctp_src" );

    case OXM_OF_SCTP_DST:
      return oxm_match_16_to_dec_string( header, str, length, "sctp_dst" );

    default:
      assert( 0 );
      break;
  }

  return false;
}


static bool
oxm_match_icmpv4_type_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( *header == OXM_OF_ICMPV4_TYPE );

  return oxm_match_8_to_hex_string( header, str, length, "icmpv4_type" );
}


static bool
oxm_match_icmpv4_code_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( *header == OXM_OF_ICMPV4_CODE );

  return oxm_match_8_to_hex_string( header, str, length, "icmpv4_code" );
}


static bool
oxm_match_arp_op_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( *header == OXM_OF_ARP_OP );

  return oxm_match_16_to_hex_string( header, str, length, "arp_op" );
}


static bool
oxm_match_arp_pa_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );

  switch ( *header ) {
    case OXM_OF_ARP_SPA:
      return oxm_match_ip_addr_to_dec_string( header, str, length, "arp_spa" );

    case OXM_OF_ARP_SPA_W:
      return oxm_match_ip_addr_w_to_dec_string( header, str, length, "arp_spa" );

    case OXM_OF_ARP_TPA:
      return oxm_match_ip_addr_to_dec_string( header, str, length, "arp_tpa" );

    case OXM_OF_ARP_TPA_W:
      return oxm_match_ip_addr_w_to_dec_string( header, str, length, "arp_tpa" );

    default:
      assert( 0 );
      break;
  }

  return false;
}


static bool
oxm_match_arp_ha_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );

  switch ( *header ) {
    case OXM_OF_ARP_SHA:
      return oxm_match_eth_addr_to_hex_string( header, str, length, "arp_sha" );

    case OXM_OF_ARP_SHA_W:
      return oxm_match_eth_addr_w_to_hex_string( header, str, length, "arp_sha" );

    case OXM_OF_ARP_THA:
      return oxm_match_eth_addr_to_hex_string( header, str, length, "arp_tha" );

    case OXM_OF_ARP_THA_W:
      return oxm_match_eth_addr_w_to_hex_string( header, str, length, "arp_tha" );

    default:
      assert( 0 );
      break;
  }

  return false;
}


static bool
oxm_match_ipv6_addr_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );

  switch ( *header ) {
    case OXM_OF_IPV6_SRC:
      return oxm_match_ipv6_addr_to_hex_string( header, str, length, "ipv6_src" );

    case OXM_OF_IPV6_SRC_W:
      return oxm_match_ipv6_addr_w_to_hex_string( header, str, length, "ipv6_src" );

    case OXM_OF_IPV6_DST:
      return oxm_match_ipv6_addr_to_hex_string( header, str, length, "ipv6_dst" );

    case OXM_OF_IPV6_DST_W:
      return oxm_match_ipv6_addr_w_to_hex_string( header, str, length, "ipv6_dst" );

    default:
      assert( 0 );
      break;
  }

  return false;
}


static bool
oxm_match_ipv6_flabel_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );

  switch ( *header ) {
    case OXM_OF_IPV6_FLABEL:
      return oxm_match_32_to_hex_string( header, str, length, "ipv6_flabel" );

    case OXM_OF_IPV6_FLABEL_W:
      return oxm_match_32w_to_hex_string( header, str, length, "ipv6_flabel" );

    default:
      assert( 0 );
      break;
  }

  return false;
}


static bool
oxm_match_icmpv6_type_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( *header == OXM_OF_ICMPV6_TYPE );

  return oxm_match_8_to_hex_string( header, str, length, "icmpv6_type" );
}


static bool
oxm_match_icmpv6_code_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( *header == OXM_OF_ICMPV6_CODE );

  return oxm_match_8_to_hex_string( header, str, length, "icmpv6_code" );
}


static bool
oxm_match_ipv6_nd_target_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( *header == OXM_OF_IPV6_ND_TARGET );

  return oxm_match_ipv6_addr_to_hex_string( header, str, length, "ipv6_nd_target" );
}


static bool
oxm_match_ipv6_nd_ll_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );

  switch ( *header ) {
    case OXM_OF_IPV6_ND_SLL:
      return oxm_match_eth_addr_to_hex_string( header, str, length, "ipv6_nd_sll" );

    case OXM_OF_IPV6_ND_TLL:
      return oxm_match_eth_addr_to_hex_string( header, str, length, "ipv6_nd_tll" );

    default:
      assert( 0 );
      break;
  }

  return false;
}


static bool
oxm_match_mpls_label_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( *header == OXM_OF_MPLS_LABEL );

  return oxm_match_32_to_hex_string( header, str, length, "mpls_label" );
}


static bool
oxm_match_mpls_tc_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( *header == OXM_OF_MPLS_TC );

  return oxm_match_8_to_hex_string( header, str, length, "mpls_tc" );
}


static bool
oxm_match_mpls_bos_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );
  assert( *header == OXM_OF_MPLS_BOS );

  return oxm_match_8_to_hex_string( header, str, length, "mpls_bos" );
}


static bool
oxm_match_pbb_isid_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );

  switch ( *header ) {
    case OXM_OF_PBB_ISID:
      return oxm_match_24_to_hex_string( header, str, length, "pbb_isid" );

    case OXM_OF_PBB_ISID_W:
      return oxm_match_24w_to_hex_string( header, str, length, "pbb_isid" );

    default:
      assert( 0 );
      break;
  }

  return false;
}


static bool
oxm_match_tunnel_id_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );

  switch ( *header ) {
    case OXM_OF_TUNNEL_ID:
      return oxm_match_64_to_hex_string( header, str, length, "tunnel_id" );

    case OXM_OF_TUNNEL_ID_W:
      return oxm_match_64w_to_hex_string( header, str, length, "tunnel_id" );

    default:
      assert( 0 );
      break;
  }

  return false;
}


static bool
oxm_match_ipv6_exthdr_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );

  switch ( *header ) {
    case OXM_OF_IPV6_EXTHDR:
      return oxm_match_16_to_hex_string( header, str, length, "ipv6_exthdr" );

    case OXM_OF_IPV6_EXTHDR_W:
      return oxm_match_16w_to_hex_string( header, str, length, "ipv6_exthdr" );

    default:
      assert( 0 );
      break;
  }

  return false;
}


static bool
oxm_match_to_string( const oxm_match_header *header, char *str, size_t length ) {
  assert( header != NULL );
  assert( str != NULL );
  assert( length > 0 );

  bool ret = true;

  switch ( *header ) {
    case OXM_OF_IN_PORT:
      ret = oxm_match_in_port_to_string( header, str, length );
      break;

    case OXM_OF_IN_PHY_PORT:
      ret = oxm_match_in_phy_port_to_string( header, str, length );
      break;

    case OXM_OF_METADATA:
    case OXM_OF_METADATA_W:
      ret = oxm_match_metadata_to_string( header, str, length );
      break;

    case OXM_OF_ETH_DST:
    case OXM_OF_ETH_DST_W:
    case OXM_OF_ETH_SRC:
    case OXM_OF_ETH_SRC_W:
      ret = oxm_match_eth_addr_to_string( header, str, length );
      break;

    case OXM_OF_ETH_TYPE:
      ret = oxm_match_eth_type_to_string( header, str, length );
      break;

    case OXM_OF_VLAN_VID:
    case OXM_OF_VLAN_VID_W:
      ret = oxm_match_vlan_vid_to_string( header, str, length );
      break;

    case OXM_OF_VLAN_PCP:
      ret = oxm_match_vlan_pcp_to_string( header, str, length );
      break;

    case OXM_OF_IP_DSCP:
      ret = oxm_match_ip_dscp_to_string( header, str, length );
      break;

    case OXM_OF_IP_ECN:
      ret = oxm_match_ip_ecn_to_string( header, str, length );
      break;

    case OXM_OF_IP_PROTO:
      ret = oxm_match_ip_proto_to_string( header, str, length );
      break;

    case OXM_OF_IPV4_SRC:
    case OXM_OF_IPV4_SRC_W:
    case OXM_OF_IPV4_DST:
    case OXM_OF_IPV4_DST_W:
      ret = oxm_match_ip_addr_to_string( header, str, length );
      break;

    case OXM_OF_TCP_SRC:
    case OXM_OF_TCP_DST:
      ret = oxm_match_tcp_port_to_string( header, str, length );
      break;

    case OXM_OF_UDP_SRC:
    case OXM_OF_UDP_DST:
      ret = oxm_match_udp_port_to_string( header, str, length );
      break;

    case OXM_OF_SCTP_SRC:
    case OXM_OF_SCTP_DST:
      ret = oxm_match_sctp_port_to_string( header, str, length );
      break;

    case OXM_OF_ICMPV4_TYPE:
      ret = oxm_match_icmpv4_type_to_string( header, str, length );
      break;

    case OXM_OF_ICMPV4_CODE:
      ret = oxm_match_icmpv4_code_to_string( header, str, length );
      break;

    case OXM_OF_ARP_OP:
      ret = oxm_match_arp_op_to_string( header, str, length );
      break;

    case OXM_OF_ARP_SPA:
    case OXM_OF_ARP_SPA_W:
    case OXM_OF_ARP_TPA:
    case OXM_OF_ARP_TPA_W:
      ret = oxm_match_arp_pa_to_string( header, str, length );
      break;

    case OXM_OF_ARP_SHA:
    case OXM_OF_ARP_SHA_W:
    case OXM_OF_ARP_THA:
    case OXM_OF_ARP_THA_W:
      ret = oxm_match_arp_ha_to_string( header, str, length );
      break;

    case OXM_OF_IPV6_SRC:
    case OXM_OF_IPV6_SRC_W:
    case OXM_OF_IPV6_DST:
    case OXM_OF_IPV6_DST_W:
      ret = oxm_match_ipv6_addr_to_string( header, str, length );
      break;

    case OXM_OF_IPV6_FLABEL:
    case OXM_OF_IPV6_FLABEL_W:
      ret = oxm_match_ipv6_flabel_to_string( header, str, length );
      break;

    case OXM_OF_ICMPV6_TYPE:
      ret = oxm_match_icmpv6_type_to_string( header, str, length );
      break;

    case OXM_OF_ICMPV6_CODE:
      ret = oxm_match_icmpv6_code_to_string( header, str, length );
      break;

    case OXM_OF_IPV6_ND_TARGET:
      ret = oxm_match_ipv6_nd_target_to_string( header, str, length );
      break;

    case OXM_OF_IPV6_ND_SLL:
    case OXM_OF_IPV6_ND_TLL:
      ret = oxm_match_ipv6_nd_ll_to_string( header, str, length );
      break;

    case OXM_OF_MPLS_LABEL:
      ret = oxm_match_mpls_label_to_string( header, str, length );
      break;

    case OXM_OF_MPLS_TC:
      ret = oxm_match_mpls_tc_to_string( header, str, length );
      break;

    case OXM_OF_MPLS_BOS:
      ret = oxm_match_mpls_bos_to_string( header, str, length );
      break;

    case OXM_OF_PBB_ISID:
    case OXM_OF_PBB_ISID_W:
      ret = oxm_match_pbb_isid_to_string( header, str, length );
      break;

    case OXM_OF_TUNNEL_ID:
    case OXM_OF_TUNNEL_ID_W:
      ret = oxm_match_tunnel_id_to_string( header, str, length );
      break;

    case OXM_OF_IPV6_EXTHDR:
    case OXM_OF_IPV6_EXTHDR_W:
      ret = oxm_match_ipv6_exthdr_to_string( header, str, length );
      break;

    default:
    {
      ret = false;
      error( "Undefined match type ( header = %#x, type = %#x, hash_mask = %u, length = %u ).",
             *header, OXM_TYPE( *header ), OXM_HASMASK( *header ), OXM_LENGTH( *header ) );
    }
    break;
  }

  return ret;
}


bool
match_to_string( const oxm_matches *matches, char *str, size_t length ) {
  assert( str != NULL );
  assert( length > 0 );

  memset( str, '\0', length );

  bool ret = true;
  if ( ( matches != NULL ) && ( matches->n_matches > 0 ) ) {
    for ( list_element *e = matches->list; e != NULL; e = e->next ) {
      size_t current_length = strlen( str );
      size_t remaining_length = length - current_length;
      if ( current_length > 0 && remaining_length > 2 ) {
        snprintf( str + current_length, remaining_length, ", " );
        remaining_length -= 2;
        current_length += 2;
      }
      char *p = str + current_length;
      const oxm_match_header *header = e->data;
      ret = oxm_match_to_string( header, p, remaining_length );
      if ( !ret ) {
        break;
      }
    }
  }
  else {
    int ret_val = snprintf( str, length, "all" );
    if ( ( ret_val >= ( int ) length ) || ( ret_val < 0 ) ) {
      ret = false;
    }
  }

  str[ length - 1 ] = '\0';

  return ret;
}


bool
port_to_string( const struct ofp_port *phy_port, char *str, size_t size ) {
  assert( phy_port != NULL );
  assert( str != NULL );

  memset( str, '\0', size );

  int ret = snprintf(
              str,
              size,
              "port_no = %u, hw_addr = %02x:%02x:%02x:%02x:%02x:%02x, "
              "name = %s, config = %#x, state = %#x, "
              "curr = %#x, advertised = %#x, supported = %#x, peer = %#x, "
              "curr_speed = %#x, max_speed = %#x",
              phy_port->port_no,
              phy_port->hw_addr[ 0 ], phy_port->hw_addr[ 1 ], phy_port->hw_addr[ 2 ],
              phy_port->hw_addr[ 3 ], phy_port->hw_addr[ 4 ], phy_port->hw_addr[ 5 ],
              phy_port->name, phy_port->config, phy_port->state,
              phy_port->curr, phy_port->advertised, phy_port->supported, phy_port->peer,
              phy_port->curr_speed, phy_port->max_speed
            );

  if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
action_output_to_string( const struct ofp_action_output *action, char *str, size_t size ) {
  assert( action != NULL );
  assert( str != NULL );

  int ret = snprintf( str, size, "output: port=%u max_len=%u", action->port, action->max_len );
  if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
action_set_field_to_string( const struct ofp_action_set_field *action, char *str, size_t size ) {
  assert( action != NULL );
  assert( str != NULL );

  char oxm_str[ 128 ];

  memset( oxm_str, '\0', sizeof( oxm_str ) );

  uint16_t offset = offsetof( struct ofp_action_set_field, field );
  const oxm_match_header *header = ( const oxm_match_header * ) ( ( const char * ) action + offset );
  oxm_match_to_string( header, oxm_str, sizeof( oxm_str ) );
  int ret = snprintf( str, size, "set_field: field=[%s]", oxm_str );
  if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
action_set_queue_to_string( const struct ofp_action_set_queue *action, char *str, size_t size ) {
  assert( action != NULL );
  assert( str != NULL );

  int ret = snprintf( str, size, "set_queue: queue_id=%u", action->queue_id );
  if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
action_experimenter_to_string( const struct ofp_action_experimenter_header *action, char *str, size_t size ) {
  assert( action != NULL );
  assert( str != NULL );

  int ret = snprintf( str, size, "experimenter: experimenter=%#x", action->experimenter );
  if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
action_copy_ttl_out_to_string( const struct ofp_action_header *action, char *str, size_t size ) {
  assert( action != NULL );
  assert( str != NULL );

  int ret = snprintf( str, size, "copy_ttl_out" );
  if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
action_copy_ttl_in_to_string( const struct ofp_action_header *action, char *str, size_t size ) {
  assert( action != NULL );
  assert( str != NULL );

  int ret = snprintf( str, size, "copy_ttl_in" );
  if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
action_set_mpls_ttl_to_string( const struct ofp_action_mpls_ttl *action, char *str, size_t size ) {
  assert( action != NULL );
  assert( str != NULL );

  int ret = snprintf( str, size, "set_mpls_ttl: mpls_ttl=%u", action->mpls_ttl );
  if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
action_dec_mpls_ttl_to_string( const struct ofp_action_header *action, char *str, size_t size ) {
  assert( action != NULL );
  assert( str != NULL );

  int ret = snprintf( str, size, "dec_mpls_ttl" );
  if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
action_push_vlan_to_string( const struct ofp_action_push *action, char *str, size_t size ) {
  assert( action != NULL );
  assert( str != NULL );

  int ret = snprintf( str, size, "push_vlan: ethertype=%#x", action->ethertype );
  if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
action_pop_vlan_to_string( const struct ofp_action_header *action, char *str, size_t size ) {
  assert( action != NULL );
  assert( str != NULL );

  int ret = snprintf( str, size, "pop_vlan" );
  if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
action_push_mpls_to_string( const struct ofp_action_push *action, char *str, size_t size ) {
  assert( action != NULL );
  assert( str != NULL );

  int ret = snprintf( str, size, "push_mpls: ethertype=%#x", action->ethertype );
  if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
action_pop_mpls_to_string( const struct ofp_action_pop_mpls *action, char *str, size_t size ) {
  assert( action != NULL );
  assert( str != NULL );

  int ret = snprintf( str, size, "pop_mpls: ethertype=%#x", action->ethertype );
  if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
action_group_to_string( const struct ofp_action_group *action, char *str, size_t size ) {
  assert( action != NULL );
  assert( str != NULL );

  int ret = snprintf( str, size, "group: group_id=%#x", action->group_id );
  if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
action_set_nw_ttl_to_string( const struct ofp_action_nw_ttl *action, char *str, size_t size ) {
  assert( action != NULL );
  assert( str != NULL );

  int ret = snprintf( str, size, "set_nw_ttl: nw_ttl=%u", action->nw_ttl );
  if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
action_dec_nw_ttl_to_string( const struct ofp_action_header *action, char *str, size_t size ) {
  assert( action != NULL );
  assert( str != NULL );

  int ret = snprintf( str, size, "dec_nw_ttl" );
  if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
action_push_pbb_to_string( const struct ofp_action_push *action, char *str, size_t size ) {
  assert( action != NULL );
  assert( str != NULL );

  int ret = snprintf( str, size, "push_pbb: ethertype=%#x", action->ethertype );
  if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
action_pop_pbb_to_string( const struct ofp_action_header *action, char *str, size_t size ) {
  assert( action != NULL );
  assert( str != NULL );

  int ret = snprintf( str, size, "pop_pbb" );
  if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


bool
actions_to_string( const struct ofp_action_header *actions, uint16_t actions_length, char *str, size_t str_length ) {
  assert( actions != NULL );
  assert( str != NULL );
  assert( actions_length > 0 );
  assert( str_length > 0 );

  memset( str, '\0', str_length );

  bool ret = true;
  size_t offset = 0;
  while ( ( actions_length - offset ) >= sizeof( struct ofp_action_header ) ) {
    size_t current_str_length = strlen( str );
    size_t remaining_str_length = str_length - current_str_length;
    if ( current_str_length > 0 && remaining_str_length > 2 ) {
      snprintf( str + current_str_length, remaining_str_length, ", " );
      remaining_str_length -= 2;
      current_str_length += 2;
    }
    char *p = str + current_str_length;
    const struct ofp_action_header *header = ( const struct ofp_action_header * ) ( ( const char * ) actions + offset );
    switch( header->type ) {
      case OFPAT_OUTPUT:
        ret = action_output_to_string( ( const struct ofp_action_output * ) header, p, remaining_str_length );
        break;
      case OFPAT_COPY_TTL_OUT:
        ret = action_copy_ttl_out_to_string( ( const struct ofp_action_header * ) header, p, remaining_str_length );
        break;
      case OFPAT_COPY_TTL_IN:
        ret = action_copy_ttl_in_to_string( ( const struct ofp_action_header * ) header, p, remaining_str_length );
        break;
      case OFPAT_SET_MPLS_TTL:
        ret = action_set_mpls_ttl_to_string( ( const struct ofp_action_mpls_ttl * ) header, p, remaining_str_length );
        break;
      case OFPAT_DEC_MPLS_TTL:
        ret = action_dec_mpls_ttl_to_string( ( const struct ofp_action_header * ) header, p, remaining_str_length );
        break;
      case OFPAT_PUSH_VLAN:
        ret = action_push_vlan_to_string( ( const struct ofp_action_push * ) header, p, remaining_str_length );
        break;
      case OFPAT_POP_VLAN:
        ret = action_pop_vlan_to_string( ( const struct ofp_action_header * ) header, p, remaining_str_length );
        break;
      case OFPAT_PUSH_MPLS:
        ret = action_push_mpls_to_string( ( const struct ofp_action_push * ) header, p, remaining_str_length );
        break;
      case OFPAT_POP_MPLS:
        ret = action_pop_mpls_to_string( ( const struct ofp_action_pop_mpls * ) header, p, remaining_str_length );
        break;
      case OFPAT_SET_QUEUE:
        ret = action_set_queue_to_string( ( const struct ofp_action_set_queue * ) header, p, remaining_str_length );
        break;
      case OFPAT_GROUP:
        ret = action_group_to_string( ( const struct ofp_action_group * ) header, p, remaining_str_length );
        break;
      case OFPAT_SET_NW_TTL:
        ret = action_set_nw_ttl_to_string( ( const struct ofp_action_nw_ttl * ) header, p, remaining_str_length );
        break;
      case OFPAT_DEC_NW_TTL:
        ret = action_dec_nw_ttl_to_string( ( const struct ofp_action_header * ) header, p, remaining_str_length );
        break;
      case OFPAT_SET_FIELD:
        ret = action_set_field_to_string( ( const struct ofp_action_set_field * ) header, p, remaining_str_length );
        break;
      case OFPAT_PUSH_PBB:
        ret = action_push_pbb_to_string( ( const struct ofp_action_push * ) header, p, remaining_str_length );
        break;
      case OFPAT_POP_PBB:
        ret = action_pop_pbb_to_string( ( const struct ofp_action_header * ) header, p, remaining_str_length );
        break;
      case OFPAT_EXPERIMENTER:
        ret = action_experimenter_to_string( ( const struct ofp_action_experimenter_header * ) header, p, remaining_str_length );
        break;
      default:
        {
          int ret_val = snprintf( p, remaining_str_length, "undefined: type=%#x", header->type );
          if ( ( ret_val >= ( int ) remaining_str_length ) || ( ret_val < 0 ) ) {
            ret = false;
          }
        }
        break;
    }

    if ( ret == false ) {
      break;
    } 
    offset += header->len;
  }

  str[ str_length - 1 ] = '\0';

  return ret;
}


static bool
instruction_goto_table_to_string( const struct ofp_instruction_goto_table *instruction, char *str, size_t size ) {
  assert( instruction != NULL );
  assert( str != NULL );

  int ret = snprintf( str, size, "goto_table: table_id=%#x", instruction->table_id );
  if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
instruction_write_metadata_to_string( const struct ofp_instruction_write_metadata *instruction, char *str, size_t size ) {
  assert( instruction != NULL );
  assert( str != NULL );

  int ret = snprintf( str, size, "write_metadata: metadata=%#" PRIx64 " metadata_mask=%#" PRIx64, instruction->metadata, instruction->metadata_mask );
  if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
instruction_write_actions_to_string( const struct ofp_instruction_actions *instruction, char *str, size_t size ) {
  assert( instruction != NULL );
  assert( str != NULL );

  char act_str[ 1024 ];

  memset( act_str, '\0', sizeof( act_str ) );

  uint16_t offset = offsetof( struct ofp_instruction_actions, actions );
  const struct ofp_action_header *actions = ( const struct ofp_action_header * ) ( ( const char * ) instruction + offset );
  uint16_t actions_len = ( uint16_t ) ( instruction->len - offset );
  if ( actions_len > 0 ) {
    actions_to_string( actions, actions_len, act_str, sizeof( act_str ) );
    int ret = snprintf( str, size, "write_actions: actions=[%s]", act_str );
    if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
      return false;
    }
  } else {
    int ret = snprintf( str, size, "write_actions: actions=[no action]" );
    if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
      return false;
    }
  }

  return true;
}


static bool
instruction_apply_actions_to_string( const struct ofp_instruction_actions *instruction, char *str, size_t size ) {
  assert( instruction != NULL );
  assert( str != NULL );

  char act_str[ 1024 ];

  uint16_t offset = offsetof( struct ofp_instruction_actions, actions );
  const struct ofp_action_header *actions = ( const struct ofp_action_header * ) ( ( const char * ) instruction + offset );
  uint16_t actions_len = ( uint16_t ) ( instruction->len - offset );
  if ( actions_len > 0 ) {
    actions_to_string( actions, actions_len, act_str, sizeof( act_str ) );
    int ret = snprintf( str, size, "apply_actions: actions=[%s]", act_str );
    if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
      return false;
    }
  } else {
    int ret = snprintf( str, size, "apply_actions: actions=[no action]" );
    if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
      return false;
    }
  }

  return true;
}


static bool
instruction_clear_actions_to_string( const struct ofp_instruction_actions *instruction, char *str, size_t size ) {
  assert( instruction != NULL );
  assert( str != NULL );

  int ret = snprintf( str, size, "clear_actions" );
  if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
instruction_meter_to_string( const struct ofp_instruction_meter *instruction, char *str, size_t size ) {
  assert( instruction != NULL );
  assert( str != NULL );

  int ret = snprintf( str, size, "meter: meter_id=%#x", instruction->meter_id );
  if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


static bool
instruction_experimenter_to_string( const struct ofp_instruction_experimenter *instruction, char *str, size_t size ) {
  assert( instruction != NULL );
  assert( str != NULL );

  int ret = snprintf( str, size, "experimenter: experimenter=%#x", instruction->experimenter );
  if ( ( ret >= ( int ) size ) || ( ret < 0 ) ) {
    return false;
  }

  return true;
}


bool
instructions_to_string( const struct ofp_instruction *instructions, uint16_t instructions_length, char *str, size_t str_length ) {
  assert( instructions != NULL );
  assert( str != NULL );
  assert( instructions_length > 0 );
  assert( str_length > 0 );

  memset( str, '\0', str_length );

  bool ret = true;
  size_t offset = 0;
  while ( ( instructions_length - offset ) >= sizeof( struct ofp_instruction ) ) {
    size_t current_str_length = strlen( str );
    size_t remaining_str_length = str_length - current_str_length;
    if ( current_str_length > 0 && remaining_str_length > 2 ) {
      snprintf( str + current_str_length, remaining_str_length, ", " );
      remaining_str_length -= 2;
      current_str_length += 2;
    }
    char *p = str + current_str_length;
    const struct ofp_instruction *header = ( const struct ofp_instruction * ) ( ( const char * ) instructions + offset );
    switch( header->type ) {
      case OFPIT_GOTO_TABLE:
        ret = instruction_goto_table_to_string( ( const struct ofp_instruction_goto_table * ) header, p, remaining_str_length );
        break;
      case OFPIT_WRITE_METADATA:
        ret = instruction_write_metadata_to_string( ( const struct ofp_instruction_write_metadata * ) header, p, remaining_str_length );
        break;
      case OFPIT_WRITE_ACTIONS:
        ret = instruction_write_actions_to_string( ( const struct ofp_instruction_actions * ) header, p, remaining_str_length );
        break;
      case OFPIT_APPLY_ACTIONS:
        ret = instruction_apply_actions_to_string( ( const struct ofp_instruction_actions * ) header, p, remaining_str_length );
        break;
      case OFPIT_CLEAR_ACTIONS:
        ret = instruction_clear_actions_to_string( ( const struct ofp_instruction_actions * ) header, p, remaining_str_length );
        break;
      case OFPIT_METER:
        ret = instruction_meter_to_string( ( const struct ofp_instruction_meter * ) header, p, remaining_str_length );
        break;
      case OFPIT_EXPERIMENTER:
        ret = instruction_experimenter_to_string( ( const struct ofp_instruction_experimenter * ) header, p, remaining_str_length );
        break;
      default:
        {
          int ret_val = snprintf( p, remaining_str_length, "undefined: type=%#x", header->type );
          if ( ( ret_val >= ( int ) remaining_str_length ) || ( ret_val < 0 ) ) {
            ret = false;
          }
        }
        break;
    }

    if ( ret == false ) {
      break;
    }
    offset += header->len;
  }

  str[ str_length - 1 ] = '\0';

  return ret;
}


uint16_t
get_checksum( uint16_t *pos, uint32_t size ) {
  assert( pos != NULL );

  uint32_t csum = 0;
  for (; 2 <= size; pos++, size -= 2 ) {
    csum += *pos;
  }
  if ( size == 1 ) {
    union {
     uint8_t bytes[ 2 ];
     uint16_t num;
    } tmp = { .bytes = { * ( uint8_t * ) pos, 0 } };
    csum += tmp.num;
  }
  // ones' complement: sum up carry
  while ( csum & 0xffff0000 ) {
    csum = ( csum & 0x0000ffff ) + ( csum >> 16 );
  }

  return ( uint16_t ) ~csum;
}


uint32_t
get_in_port_from_oxm_matches( const oxm_matches *match ) {
  assert( match != NULL );

  uint32_t in_port = 0;

  for ( list_element *list = match->list; list != NULL; list = list->next ) {
    oxm_match_header *oxm = list->data;
    if ( *oxm == OXM_OF_IN_PORT ) {
      uint32_t *value = ( uint32_t * ) ( ( char * ) oxm + sizeof( oxm_match_header ) );
      in_port = *value;
      break;
    }
  }
  if ( in_port == 0 ) {
    debug( "in_port not found ( in_port = %u )", in_port );
  }
  if ( in_port > OFPP_MAX ) {
    if ( in_port != OFPP_CONTROLLER && in_port != OFPP_LOCAL ) {
      warn( "invalid in_port ( in_port = %u )", in_port );
      in_port = 0;
    }
  }

  return in_port;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
