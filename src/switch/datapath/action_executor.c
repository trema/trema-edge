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


#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "action_executor.h"
#include "async_event_notifier.h"
#include "flow_entry.h"
#include "group_table.h"
#include "packet_buffer.h"
#include "port_manager.h"
#include "table_manager.h"
#include "pipeline.h"

#define REMAINED_BUFFER_LENGTH( buf, ptr )  \
  ( buf->length - ( size_t ) ( ( char * ) ptr - ( char * ) buf->data ) )

OFDPE
init_action_executor() {
  return OFDPE_SUCCESS;
}


OFDPE
finalize_action_executor() {
  return OFDPE_SUCCESS;
}


static void
set_ipv4_checksum( ipv4_header_t *header ) {
  assert( header != NULL );

  header->csum = 0;
  header->csum = get_checksum( ( uint16_t * ) header, ( uint32_t ) sizeof( ipv4_header_t ) );
}


static uint32_t
get_sum( uint16_t *pos, size_t size ) {
  assert( pos != NULL );

  uint32_t sum = 0;

  for (; 2 <= size; pos++, size -= 2 ) {
    sum += *pos;
  }
  if ( size == 1 ) {
    uint8_t buf[2] = { *( uint8_t * ) pos, 0 };
    sum += * ( uint16_t * ) buf;
  }

  return sum;
}


static uint16_t
get_checksum_from_sum( uint32_t sum ) {
  // ones' complement: sum up carry
  while ( sum & 0xffff0000 ) {
    sum = ( sum & 0x0000ffff ) + ( sum >> 16 );
  }

  return ( uint16_t ) ~sum;
}


static uint32_t
get_ipv4_pseudo_header_sum( ipv4_header_t *header, uint8_t protocol, size_t payload_size ) {
  assert( header != NULL );

  uint32_t sum = 0;

  sum += get_sum( ( uint16_t * ) &header->saddr, sizeof( header->saddr ) );
  sum += get_sum( ( uint16_t * ) &header->daddr, sizeof( header->saddr ) );
  uint8_t protocol_field[2] = { 0, protocol };
  sum += * ( uint16_t * ) protocol_field;
  sum += ( uint16_t ) htons(payload_size);

  return sum;
}


static uint32_t
get_ipv6_pseudo_header_sum( ipv6_header_t *header, uint8_t protocol, size_t payload_size ) {
  assert( header != NULL );

  uint32_t sum = 0;

  sum += get_sum( ( uint16_t * ) &header->saddr[ 0 ], sizeof( header->saddr ) );
  sum += get_sum( ( uint16_t * ) &header->daddr[ 0 ], sizeof( header->saddr ) );
  uint8_t protocol_field[2] = { 0, protocol };
  sum += * ( uint16_t * ) protocol_field;
  sum += ( uint16_t ) htons(payload_size);

  return sum;
}


static uint32_t
get_icmpv6_pseudo_header_sum( ipv6_header_t *header, size_t payload_size ) {
  assert( header != NULL );

  uint32_t sum = 0;

  sum += get_sum( ( uint16_t * ) &header->saddr[ 0 ], sizeof( header->saddr ) );
  sum += get_sum( ( uint16_t * ) &header->daddr[ 0 ], sizeof( header->saddr ) );
  uint8_t protocol_field[2] = { 0, IPPROTO_ICMPV6 };
  sum += * ( uint16_t * ) protocol_field;
  sum += ( uint16_t ) htons(payload_size);

  return sum;
}


static void
set_ipv4_udp_checksum( ipv4_header_t *ipv4_header, udp_header_t *udp_header, void *payload ) {
  assert( ipv4_header != NULL );
  assert( udp_header != NULL );

  uint32_t sum = 0;

  sum += get_ipv4_pseudo_header_sum( ipv4_header, IPPROTO_UDP, ntohs( udp_header->len ) );
  udp_header->csum = 0;
  sum += get_sum( ( uint16_t * ) udp_header, sizeof( udp_header_t ) );
  if ( payload != NULL ) {
    sum += get_sum( payload, ntohs( udp_header->len ) - sizeof( udp_header_t ) );
  }
  udp_header->csum = get_checksum_from_sum( sum );
}


static void
set_ipv6_udp_checksum( ipv6_header_t *ipv6_header, udp_header_t *udp_header, void *payload ) {
  assert( ipv6_header != NULL );
  assert( udp_header != NULL );

  uint32_t sum = 0;

  sum += get_ipv6_pseudo_header_sum( ipv6_header, IPPROTO_UDP, ntohs( udp_header->len ) );
  udp_header->csum = 0;
  sum += get_sum( ( uint16_t * ) udp_header, sizeof( udp_header_t ) );
  if ( payload != NULL ) {
    sum += get_sum( payload, ntohs( udp_header->len ) - sizeof( udp_header_t ) );
  }
  udp_header->csum = get_checksum_from_sum( sum );
}


static void
set_ipv4_tcp_checksum( ipv4_header_t *ipv4_header, tcp_header_t *tcp_header, void *tcp_payload, size_t tcp_payload_length ) {
  assert( ipv4_header != NULL );
  assert( tcp_header != NULL );

  uint32_t sum = 0;

  sum += get_ipv4_pseudo_header_sum( ipv4_header, IPPROTO_TCP, tcp_header->offset * 4 + tcp_payload_length );
  tcp_header->csum = 0;
  sum += get_sum( ( uint16_t * ) tcp_header, sizeof( tcp_header_t ) );
  if ( tcp_payload != NULL && tcp_payload_length > 0 ) {
    sum += get_sum( tcp_payload, tcp_payload_length );
  }
  tcp_header->csum = get_checksum_from_sum( sum );
}


static void
set_ipv6_tcp_checksum( ipv6_header_t *ipv6_header, tcp_header_t *tcp_header, void *tcp_payload, size_t tcp_payload_length ) {
  assert( ipv6_header != NULL );
  assert( tcp_header != NULL );

  uint32_t sum = 0;

  sum += get_ipv6_pseudo_header_sum( ipv6_header, IPPROTO_TCP, tcp_header->offset * 4 + tcp_payload_length );
  tcp_header->csum = 0;
  sum += get_sum( ( uint16_t * ) tcp_header, sizeof( tcp_header_t ) );
  if ( tcp_payload != NULL && tcp_payload_length > 0 ) {
    sum += get_sum( tcp_payload, tcp_payload_length );
  }
  tcp_header->csum = get_checksum_from_sum( sum );
}


static void
set_icmpv4_checksum( icmp_header_t *icmp_header, size_t icmp_length ) {
  assert( icmp_header != NULL );

  icmp_header->csum = 0;
  icmp_header->csum = get_checksum( ( uint16_t * ) icmp_header, ( uint32_t ) icmp_length );
}


static void
set_icmpv6_checksum( ipv6_header_t *ipv6_header, icmpv6_header_t *icmp_header, size_t length ) {
  assert( ipv6_header != NULL );
  assert( icmp_header != NULL );

  uint32_t sum = 0;

  sum += get_icmpv6_pseudo_header_sum( ipv6_header, sizeof( icmpv6_header_t ) + length );
  icmp_header->csum = 0;
  sum += get_sum( ( uint16_t * ) icmp_header, sizeof( icmpv6_header_t ) + length );
  icmp_header->csum = get_checksum_from_sum( sum );
}


static bool
parse_frame( buffer *frame ) {
  assert( frame != NULL );

  uint32_t eth_in_port = 0;
  uint64_t metadata = 0;
  uint64_t tunnel_id = 0;

  if ( frame->user_data != NULL ) {
    packet_info *info =  ( packet_info * ) frame->user_data;
    eth_in_port = info->eth_in_port;
    metadata    = info->metadata;
    tunnel_id   = info->tunnel_id;
    free_packet_info( frame );
  }

  bool ret = parse_packet( frame );
  if ( !ret ) {
    error( "Failed to parse an Ethernet frame." );
    return false;
  }

  assert( frame->user_data != NULL );

  {
    packet_info *info =  ( packet_info * ) frame->user_data;
    info->eth_in_port = eth_in_port;
    info->metadata = metadata;
    info->tunnel_id = tunnel_id;
  }

  return true;
}


static packet_info *
get_packet_info_data( const buffer *frame ) {
  assert( frame != NULL );

  return ( packet_info * ) frame->user_data;
}


static void
set_address( void *dst, match8 *value, size_t size ) {
  assert( dst != NULL );
  assert( value != NULL );

  uint8_t *tmp = ( uint8_t * ) dst;
  for ( size_t i = 0; i < size; i++ ) {
    tmp[ i ] = value->value;
    value++;
  }
}


static void
set_dl_address( void *dst, match8 *value ) {
  assert( dst != NULL );
  assert( value != NULL );

  set_address( dst, value, ETH_ADDRLEN );
}


static void
set_ipv6_address( void *dst, match8 *value ) {
  assert( dst != NULL );
  assert( value != NULL );

  set_address( dst, value, IPV6_ADDRLEN );
}


static bool
set_dl_dst( buffer *frame, match8 *value ) {
  assert( frame != NULL );
  assert( value != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_ether( frame ) ) {
    warn( "A non-ethernet frame (%#x) found while setting the destination data link address.", info->format );
    return true;
  }

  ether_header_t *header = info->l2_header;
  set_dl_address( header->macda, value );

  return parse_frame( frame );
}


static bool
set_dl_src( buffer *frame, match8 *value  ) {
  assert( frame != NULL );
  assert( value != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_ether( frame ) ) {
    warn( "A non-ethernet frame (%#x) found while setting the source data link address.", info->format );
    return true;
  }

  ether_header_t *header = info->l2_header;
  set_dl_address( header->macsa, value );

  return parse_frame( frame );
}


static bool
set_dl_type( buffer *frame, uint16_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_ether( frame ) ) {
    warn( "A non-ethernet frame (%#x) found while setting the data link type.", info->format );
    return true;
  }

  ether_header_t *header = info->l2_header;
  header->type = htons( value );

  return parse_frame( frame );
}


static bool
set_vlan_vid( buffer *frame, uint16_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_eth_vtag( frame ) ) {
    warn( "A non-vlan frame (%#x) found while setting the vlan-id.", info->format );
    return true;
  }

  vlantag_header_t *header = info->l2_vlan_header;
  header->tci = ( uint16_t ) ( ( header->tci & htons( 0xf000 ) ) | htons( value & 0x0fff ) );

  return parse_frame( frame );
}


static bool
set_vlan_pcp( buffer *frame, uint8_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_eth_vtag( frame ) ) {
    warn( "A non-vlan frame (%#x) found while setting the priority code point.", info->format );
    return true;
  }

  vlantag_header_t *header = info->l2_vlan_header;
  uint16_t tci = ( uint16_t ) ( ( value & 0x07 ) << 13 );
  header->tci = ( uint16_t ) ( ( header->tci & htons( 0x1fff ) ) | htons( tci ) );

  return parse_frame( frame );
}


static bool
set_nw_dscp( buffer *frame, uint8_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_ipv4( frame ) ) {
    warn( "A non-ipv4 packet (%#x) found while setting the dscp field.", info->format );
    return true;
  }

  ipv4_header_t *header = info->l3_header;
  header->tos = ( uint8_t ) ( ( header->tos & 0x03 ) | ( ( value << 2 ) & 0xFC ) );
  set_ipv4_checksum( header );

  return parse_frame( frame );
}


static bool
set_nw_ecn( buffer *frame, uint8_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_ipv4( frame ) ) {
    warn( "A non-ipv4 packet (%#x) found while setting the ecn field.", info->format );
    return true;
  }

  ipv4_header_t *header = info->l3_header;
  header->tos = ( uint8_t ) ( ( header->tos & 0xFC ) | ( value & 0x03 ) );
  set_ipv4_checksum( header );

  return parse_frame( frame );
}


static bool
set_ip_proto( buffer *frame, uint8_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_ipv4( frame ) ) {
    warn( "A non-ipv4 packet (%#x) found while setting the ip_proto field.", info->format );
    return true;
  }

  ipv4_header_t *header = info->l3_header;
  header->protocol = value;
  set_ipv4_checksum( header );

  return parse_frame( frame );
}


static bool
set_ipv4_src( buffer *frame, uint32_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_ipv4( frame ) ) {
    warn( "A non-ipv4 packet (%#x) found while setting the source address.", info->format );
    return true;
  }

  ipv4_header_t *header = info->l3_header;
  header->saddr = htonl( value );
  if ( packet_type_ipv4_tcp( frame ) ) {
    set_ipv4_tcp_checksum( info->l3_header, ( tcp_header_t * ) info->l4_header, info->l4_payload, info->l4_payload_length );
  }
  else if ( packet_type_ipv4_udp( frame ) ) {
    set_ipv4_udp_checksum( info->l3_header, ( udp_header_t * ) info->l4_header, info->l4_payload );
  }
  else if ( packet_type_icmpv4( frame ) ) {
    set_icmpv4_checksum( ( icmp_header_t * ) info->l4_header, info->l3_payload_length );
  }
  set_ipv4_checksum( header );

  return parse_frame( frame );
}


static bool
set_ipv4_dst( buffer *frame, uint32_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_ipv4( frame ) ) {
    warn( "A non-ipv4 packet (%#x) found when setting the destination address.", info->format );
    return true;
  }

  ipv4_header_t *header = info->l3_header;
  header->daddr = htonl( value );
  if ( packet_type_ipv4_tcp( frame ) ) {
    set_ipv4_tcp_checksum( info->l3_header, ( tcp_header_t * ) info->l4_header, info->l4_payload, info->l4_payload_length );
  }
  else if ( packet_type_ipv4_udp( frame ) ) {
    set_ipv4_udp_checksum( info->l3_header, ( udp_header_t * ) info->l4_header, info->l4_payload );
  }
  else if ( packet_type_icmpv4( frame ) ) {
    set_icmpv4_checksum( ( icmp_header_t * ) info->l4_header, info->l3_payload_length );
  }
  set_ipv4_checksum( header );

  return parse_frame( frame );
}


static bool
set_tcp_src( buffer *frame, uint16_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  tcp_header_t *tcp_header = info->l4_header;

  if ( packet_type_ipv4_tcp( frame ) ) {
    tcp_header->src_port = htons( value );
    set_ipv4_tcp_checksum( info->l3_header, tcp_header, info->l4_payload, info->l4_payload_length );
  }
  else if ( packet_type_ipv6_tcp( frame ) ) {
    tcp_header->src_port = htons( value );
    set_ipv6_tcp_checksum( info->l3_header, tcp_header, info->l4_payload, info->l4_payload_length );
  }
  else {
    warn( "A non-tcp packet (%#x) found while setting the tcp source port.", info->format );
    return true;
  }

  return parse_frame( frame );
}


static bool
set_tcp_dst( buffer *frame, uint16_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  tcp_header_t *tcp_header = info->l4_header;

  if ( packet_type_ipv4_tcp( frame ) ) {
    tcp_header->dst_port = htons( value );
    set_ipv4_tcp_checksum( info->l3_header, tcp_header, info->l4_payload, info->l4_payload_length );
  }
  else if ( packet_type_ipv6_tcp( frame ) ) {
    tcp_header->dst_port = htons( value );
    set_ipv6_tcp_checksum( info->l3_header, tcp_header, info->l4_payload, info->l4_payload_length );
  }
  else {
    warn( "A non-tcp packet (%#x) found while setting the tcp destination port.", info->format );
    return true;
  }

  return parse_frame( frame );
}


static bool
set_udp_src( buffer *frame, uint16_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  udp_header_t *udp_header = info->l4_header;

  if ( packet_type_ipv4_udp( frame ) ) {
    udp_header->src_port = htons( value );
    set_ipv4_udp_checksum( info->l3_header, udp_header, info->l4_payload );
  }
  else if ( packet_type_ipv6_udp( frame ) ) {
    udp_header->src_port = htons( value );
    set_ipv6_udp_checksum( info->l3_header, udp_header, info->l4_payload );
  }
  else {
    warn( "A non-udp packet (%#x) found while setting the udp source port.", info->format );
    return true;
  }

  return parse_frame( frame );
}


static bool
set_udp_dst( buffer *frame, uint16_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  udp_header_t *udp_header = info->l4_header;

  if ( packet_type_ipv4_udp( frame ) ) {
    udp_header->dst_port = htons( value );
    set_ipv4_udp_checksum( info->l3_header, udp_header, info->l4_payload );
  }
  else if ( packet_type_ipv6_udp( frame ) ) {
    udp_header->dst_port = htons( value );
    set_ipv6_udp_checksum( info->l3_header, udp_header, info->l4_payload );
  }
  else {
    warn( "A non-udp packet (%#x) found while setting the udp destination port.", info->format );
    return true;
  }

  return parse_frame( frame );
}


static bool
set_icmpv4_type( buffer *frame, uint8_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_icmpv4( frame ) ) {
    warn( "A non-icmpv4 packet (%#x) found while setting the type field.", info->format );
    return true;
  }

  icmp_header_t *icmp_header = info->l4_header;
  icmp_header->type = value;

  set_icmpv4_checksum( icmp_header, info->l3_payload_length );

  return parse_frame( frame );
}


static bool
set_icmpv4_code( buffer *frame, uint8_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_icmpv4( frame ) ) {
    warn( "A non-icmpv4 packet (%#x) found while setting the code field.", info->format );
    return true;
  }

  icmp_header_t *icmp_header = info->l4_header;
  icmp_header->code = value;

  set_icmpv4_checksum( icmp_header, info->l3_payload_length );

  return parse_frame( frame );
}


static bool
set_arp_op( buffer *frame, uint16_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_arp( frame ) ) {
    warn( "A non-arp packet (%#x) found while setting the opcode field.", info->format );
    return true;
  }

  arp_header_t *header = info->l3_header;
  header->ar_op = htons( value );

  return parse_frame( frame );
}


static bool
set_arp_spa( buffer *frame, uint32_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_arp( frame ) ) {
    warn( "A non-arp packet (%#x) found while setting the source ip address.", info->format );
    return true;
  }

  arp_header_t *header = info->l3_header;
  header->sip = htonl( value );

  return parse_frame( frame );
}


static bool
set_arp_tpa( buffer *frame, uint32_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_arp( frame ) ) {
    warn( "A non-arp packet (%#x) found while setting the destination (target) ip address.", info->format );
    return true;
  }

  arp_header_t *header = info->l3_header;
  header->tip = htonl( value );

  return parse_frame( frame );
}


static bool
set_arp_sha( buffer *frame, match8 *value ) {
  assert( frame != NULL );
  assert( value != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_arp( frame ) ) {
    warn( "A non-arp packet (%#x) found while setting the source mac address.", info->format );
    return true;
  }

  arp_header_t *header = info->l3_header;
  set_dl_address( header->sha, value );

  return parse_frame( frame );
}


static bool
set_arp_tha( buffer *frame, match8 *value ) {
  assert( frame != NULL );
  assert( value != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_arp( frame ) ) {
    warn( "A non-arp packet (%#x) found while setting the destination (target) mac address.", info->format );
    return true;
  }

  arp_header_t *header = info->l3_header;
  set_dl_address( header->tha, value );

  return parse_frame( frame );
}


static bool
set_ipv6_src( buffer *frame, match8 *value ) {
  assert( frame != NULL );
  assert( value != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_ipv6( frame ) ) {
    warn( "A non-ipv6 packet (%#x) found while setting the source ip address.", info->format );
    return true;
  }

  ipv6_header_t *header = info->l3_header;
  set_ipv6_address( header->saddr, value );

  if ( packet_type_ipv6_tcp( frame ) ) {
    set_ipv6_tcp_checksum( info->l3_header, ( tcp_header_t * ) info->l4_header, info->l4_payload, info->l4_payload_length );
  }
  else if ( packet_type_ipv6_udp( frame ) ) {
    set_ipv6_udp_checksum( info->l3_header, ( udp_header_t * ) info->l4_header, info->l4_payload );
  }
  else if ( packet_type_icmpv6( frame ) ) {
    set_icmpv6_checksum( info->l3_header, ( icmpv6_header_t * ) info->l4_header, info->l4_payload_length );
  }

  return parse_frame( frame );
}


static bool
set_ipv6_dst( buffer *frame, match8 value[] ) {
  assert( frame != NULL );
  assert( value != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_ipv6( frame ) ) {
    warn( "A non-ipv6 packet (%#x) found while setting the destination ip address.", info->format );
    return true;
  }

  ipv6_header_t *header = info->l3_header;
  set_ipv6_address( header->daddr, value );

  if ( packet_type_ipv6_tcp( frame ) ) {
    set_ipv6_tcp_checksum( info->l3_header, ( tcp_header_t * ) info->l4_header, info->l4_payload, info->l4_payload_length );
  }
  else if ( packet_type_ipv6_udp( frame ) ) {
    set_ipv6_udp_checksum( info->l3_header, ( udp_header_t * ) info->l4_header, info->l4_payload );
  }
  else if ( packet_type_icmpv6( frame ) ) {
    set_icmpv6_checksum( info->l3_header, ( icmpv6_header_t * ) info->l4_header, info->l4_payload_length );
  }

  return parse_frame( frame );
}


static bool
set_ipv6_flabel( buffer *frame, uint32_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_ipv6( frame ) ) {
    warn( "A non-ipv6 packet (%#x) found while setting the flow label.", info->format );
    return true;
  }

  ipv6_header_t *header = info->l3_header;
  header->hdrctl = ( header->hdrctl & htonl( 0xfff00000 ) ) | ( htonl( value ) & htonl( 0x000fffff ) );

  return parse_frame( frame );
}


static bool
set_icmpv6_type( buffer *frame, uint8_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_icmpv6( frame ) ) {
    warn( "A non-icmpv6 packet (%#x) found while setting the type field.", info->format );
    return true;
  }

  icmpv6_header_t *icmp_header = info->l4_header;
  icmp_header->type = value;
  set_icmpv6_checksum( info->l3_header, icmp_header, info->l4_payload_length );

  return parse_frame( frame );
}


static bool
set_icmpv6_code( buffer *frame, uint8_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_icmpv6( frame ) ) {
    warn( "A non-icmpv6 packet (%#x) found while setting the code field.", info->format );
    return true;
  }

  icmpv6_header_t *icmp_header = info->l4_header;
  icmp_header->code = value;
  set_icmpv6_checksum( info->l3_header, icmp_header, info->l4_payload_length );

  return parse_frame( frame );
}


static bool
set_ipv6_nd_target( buffer *frame, match8 *value ) {
  assert( frame != NULL );
  assert( value != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_icmpv6( frame ) ) {
    warn( "A non-icmpv6 packet (%#x) found while setting the neighbor target address.", info->format );
    return true;
  }

  if ( ( info->icmpv6_type != ICMPV6_TYPE_NEIGHBOR_SOL )
       && ( info->icmpv6_type != ICMPV6_TYPE_NEIGHBOR_ADV ) ) {
    warn( "Unsupported icmpv6 type (%#x) found while setting the neighbor target address.", info->icmpv6_type );
    return true;
  }

  icmpv6_header_t *header = info->l3_payload;
  icmpv6data_ndp_t *icmpv6data_ndp = ( icmpv6data_ndp_t * ) header->data;
  set_ipv6_address( icmpv6data_ndp->nd_target, value );
  set_icmpv6_checksum( info->l3_header, header, info->l4_payload_length );

  return parse_frame( frame );
}


static bool
set_ipv6_nd_sll( buffer *frame, match8 *value ) {
  assert( frame != NULL );
  assert( value != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_icmpv6( frame ) ) {
    warn( "A non-icmpv6 packet (%#x) found while setting the source link-layer address.", info->format );
    return true;
  }

  if ( info->icmpv6_type != ICMPV6_TYPE_NEIGHBOR_SOL ) {
    warn( "Unsupported icmpv6 type (%#x) found while setting the source link-layer address.", info->icmpv6_type );
    return true;
  }

  icmpv6_header_t *header = info->l3_payload;
  icmpv6data_ndp_t *icmpv6data_ndp = ( icmpv6data_ndp_t * ) header->data;

  if ( icmpv6data_ndp->ll_type != ICMPV6_ND_SOURCE_LINK_LAYER_ADDRESS ) {
    warn( "Incorrect link-layer address type (%#x) found while setting the source link-layer address.",
          icmpv6data_ndp->ll_type );
    return true;
  }
  set_dl_address( icmpv6data_ndp->ll_addr, value );
  set_icmpv6_checksum( info->l3_header, header, info->l4_payload_length );

  return parse_frame( frame );
}


static bool
set_ipv6_nd_tll( buffer *frame, match8 *value ) {
  assert( frame != NULL );
  assert( value != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_icmpv6( frame ) ) {
    warn( "A non-icmpv6 packet (%#x) found while setting the target link-layer address.", info->format );
    return true;
  }

  if ( info->icmpv6_type != ICMPV6_TYPE_NEIGHBOR_ADV ) {
    warn( "Unsupported icmpv6 type (%#x) found while setting the target link-layer address.", info->icmpv6_type );
    return true;
  }

  icmpv6_header_t *header = info->l3_payload;
  icmpv6data_ndp_t *icmpv6data_ndp = ( icmpv6data_ndp_t * ) header->data;

  if ( icmpv6data_ndp->ll_type != ICMPV6_ND_TARGET_LINK_LAYER_ADDRESS ) {
    warn( "Incorrect link-layer address type (%#x) found while setting the target link-layer address.",
          icmpv6data_ndp->ll_type );
    return true;
  }
  set_dl_address( icmpv6data_ndp->ll_addr, value );
  set_icmpv6_checksum( info->l3_header, header, info->l4_payload_length );

  return parse_frame( frame );
}


static bool
set_mpls_label( buffer *frame, uint32_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_eth_mpls( frame ) ) {
    warn( "A non-mpls packet (%#x) found while setting the mpls label.", info->format );
    return true;
  }

  mpls_header_t *mpls_header = info->l2_mpls_header;
  mpls_header->label = ( mpls_header->label & htonl( 0x00000fff ) ) | htonl( ( value << 12 ) & 0xfffff000 );

  return parse_frame( frame );
}


static bool
set_mpls_tc( buffer *frame, uint8_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_eth_mpls( frame ) ) {
    warn( "A non-mpls packet (%#x) found while setting the traffic class.", info->format );
    return true;
  }

  mpls_header_t *mpls_header = info->l2_mpls_header;
  mpls_header->label = ( mpls_header->label & htonl( 0xfffff1ff ) ) | htonl( ( ( uint32_t ) value << 9 ) & 0x00000e00 );

  return parse_frame( frame );
}


static bool
set_mpls_bos( buffer *frame, uint8_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_eth_mpls( frame ) ) {
    warn( "A non-mpls packet (%#x) found while setting the bottom of stack bit.", info->format );
    return true;
  }

  mpls_header_t *mpls_header = info->l2_mpls_header;
  mpls_header->label = ( mpls_header->label & htonl( 0xfffffeff ) ) | htonl( ( ( uint32_t ) value << 8 ) & 0x00000100 );

  return parse_frame( frame );
}


static bool
set_pbb_isid( buffer *frame, uint32_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( info->l2_pbb_header == NULL ) {
    warn( "A non-pbb packet (%#x) found while setting pbb sid.", info->format );
    return true;
  }

  pbb_header_t *pbb_header = info->l2_pbb_header;
  pbb_header->isid = ( pbb_header->isid & htonl( 0xFF000000 ) ) | htonl( value & 0x00FFFFFF );

  return parse_frame( frame );
}


static bool
set_tunnel_id( buffer *frame, uint64_t value ) {
  assert( frame != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );

  info->tunnel_id = value;

  return true;
}


static void*
push_linklayer_tag( buffer *frame, void *head, size_t tag_size ) {
  assert( frame != NULL );
  assert( head != NULL );

  size_t insert_offset = ( size_t ) ( ( char * ) head - ( char * ) frame->data );
  append_back_buffer( frame, tag_size );
  // head would be moved because append_back_buffer() may reallocate memory
  head = ( char * ) frame->data + insert_offset;
  memmove( ( char * ) head + tag_size, head, frame->length - insert_offset - tag_size );
  memset( head, 0, tag_size );

  return head;
}


static void
pop_linklayer_tag( buffer *frame, void *head, size_t tag_size ) {
  assert( frame != NULL );
  assert( head != NULL );

  char *tail = ( char * ) head + tag_size;
  size_t length = frame->length - ( ( size_t )( ( char * ) head - ( char * ) frame->data ) + tag_size );
  memmove( head, tail, length );
  frame->length -= tag_size;
}


static void*
push_vlan_tag( buffer *frame, void *head ) {
  assert( frame != NULL );
  assert( head != NULL );

  return push_linklayer_tag( frame, head, sizeof( vlantag_header_t ) );
}


static void
pop_vlan_tag( buffer *frame, void *head ) {
  assert( frame != NULL );
  assert( head != NULL );

  pop_linklayer_tag( frame, head, sizeof( vlantag_header_t ) );
}


static void*
push_mpls_tag( buffer *frame, void *head ) {
  assert( frame != NULL );
  assert( head != NULL );

  return push_linklayer_tag( frame, head, sizeof( uint32_t ) );
}


static void
pop_mpls_tag( buffer *frame, void *head ) {
  assert( frame != NULL );
  assert( head != NULL );

  pop_linklayer_tag( frame, head, sizeof( uint32_t ) );
}


static void*
push_pbb_tag( buffer *frame, void *head ) {
  assert( frame != NULL );
  assert( head != NULL );

  return push_linklayer_tag( frame, head, sizeof( pbb_header_t ) );
}


static void
pop_pbb_tag( buffer *frame, void *head ) {
  assert( frame != NULL );
  assert( head != NULL );

  pop_linklayer_tag( frame, head, sizeof( pbb_header_t ) );
}


static bool
decrement_ttl( uint8_t *ttl ) {
  assert( ttl != NULL );

  if ( *ttl == 0 ) {
    return false;
  }

  ( *ttl )--;

  return true;
}


static bool
execute_action_copy_ttl_in( buffer *frame, action *copy_ttl_in ) {
  assert( frame != NULL );
  assert( copy_ttl_in != NULL );

  packet_info *info = get_packet_info_data( frame );
  if ( packet_type_eth_mpls( frame ) ) {
    void *ptr = ( char * ) info->l2_mpls_header + sizeof( mpls_header_t );
    size_t length = REMAINED_BUFFER_LENGTH( frame, ptr );

    assert( info->l2_mpls_header != NULL );
    mpls_header_t *mpls_header = info->l2_mpls_header;
    uint32_t mpls = ntohl( mpls_header->label );
    uint8_t mpls_bos = ( uint8_t ) ( ( mpls & 0x00000100 ) >>  8 );

    uint8_t ttl = mpls & 0x000000FF;
    if ( mpls_bos == 1 ) { // MPLS-to-IP copy
      // Check the length of remained buffer for an ipv4 header without options.
      if ( length < sizeof( ipv4_header_t ) ) {
        return false;
      }

      // Check the length of remained buffer for an ipv4 header with options.
      ipv4_header_t *ipv4_header = ptr;
      if ( ipv4_header->ihl < 5 ) {
        return false;
      }
      if ( length < ( size_t ) ipv4_header->ihl * 4 ) {
        return false;
      }

      ipv4_header->ttl = ttl;
      // no tcp/udp/icmp checksum caculation here because tos field is not included in pseudo header
      set_ipv4_checksum( ipv4_header );
    }
    else { // MPLS-to-MPLS copy
      if ( length < sizeof( mpls_header_t ) ) {
        debug("incomplete mpls");
        return false;
      }
      mpls_header_t *inner_header = ( mpls_header_t * ) ( mpls_header + 1 );
      //uint32_t inner_mpls = ntohl( inner_header->label ); // unused variable
      uint8_t *inner_mpls_ttl = ( uint8_t * ) inner_header + 3;
      *inner_mpls_ttl = ttl;
    }
  }
  else if ( packet_type_ipv4( frame ) || packet_type_ipv6( frame ) ) {
    warn( "IP-to-IP TTL copy not supported yet." );
  }
  else {
    warn( "A non-ip,mpls packet (%#x) found while setting the ttl field.", info->format );
    return true;
  }



  return parse_frame( frame );
}


static bool
execute_action_pop_mpls( buffer *frame, action *pop_mpls ) {
  assert( frame != NULL );
  assert( pop_mpls != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_eth_mpls( frame ) ) {
    warn( "A non-mpls packet (%#x) found while retrieving the mpls label.", info->format );
    return true;
  }

  pop_mpls_tag( frame, info->l2_mpls_header );

  * ( uint16_t * ) ( ( char * ) info->l2_mpls_header - 2 ) = htons( pop_mpls->ethertype );

  return parse_frame( frame );
}


static bool
execute_action_pop_vlan( buffer *frame, action *pop_vlan ) {
  assert( frame != NULL );
  assert( pop_vlan != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_eth_vtag( frame ) ) {
    warn( "A non-vlan frame (%#x) found while popping a vlan tag.", info->format );
    return true;
  }

  pop_vlan_tag( frame, ( char * ) info->l2_vlan_header - 2 ); // remove TPID ethertype and tci

  return parse_frame( frame );
}


static bool
execute_action_push_mpls( buffer *frame, action *push_mpls ) {
  assert( frame != NULL );
  assert( push_mpls != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );

  void *start = info->l2_payload;
  uint32_t default_mpls = htonl( 0x00000100 );
  if ( info->l2_mpls_header != NULL ) {
    start = info->l2_mpls_header;
    default_mpls = htonl( 0xFFFFFEFF ) & *( uint32_t * ) info->l2_mpls_header;
  }
  else if ( packet_type_ipv4( frame ) ) {
    ipv4_header_t *ipv4_header = info->l3_header;
    default_mpls = htonl( 0x00000100 | ( uint32_t ) ipv4_header->ttl );
  }
  else if ( packet_type_ipv6( frame ) ) {
    ipv6_header_t *ipv6_header = info->l3_header;
    default_mpls = htonl( 0x00000100 | ( uint32_t ) ipv6_header->hoplimit );
  }

  void *mpls = push_mpls_tag( frame, start );

  * ( uint16_t * )( ( char * ) mpls - 2 ) = htons( push_mpls->ethertype );
  mpls_header_t *mpls_header = mpls;
  mpls_header->label = default_mpls;

  return parse_frame( frame );
}


static bool
execute_action_push_vlan( buffer *frame, action *push_vlan ) {
  assert( frame != NULL );
  assert( push_vlan != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  
  char *start = info->l2_payload;
  uint16_t default_tci = 0;
  if ( info->l2_vlan_header != NULL ) {
    start = info->l2_vlan_header;
    default_tci = ( ( vlantag_header_t * ) ( info->l2_vlan_header ) )-> tci;
  }

  void *vlan = push_vlan_tag( frame, start - 2 ); // push vlan tag between source mac and ethertype

  ether_header_t *ether_header = ( ether_header_t * ) frame->data;
  ether_header->type = htons( push_vlan->ethertype );
  ( ( vlantag_header_t * )( ( char * ) vlan + 2 ) )->tci = default_tci;

  return parse_frame( frame );
}


static bool
execute_action_copy_ttl_out( buffer *frame, action *copy_ttl_out ) {
  assert( frame != NULL );
  assert( copy_ttl_out != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );

  if ( packet_type_eth_mpls( frame ) ) {
    void *ptr = ( char * ) info->l2_mpls_header + sizeof( mpls_header_t );
    size_t length = REMAINED_BUFFER_LENGTH( frame, ptr );

    assert( info->l2_mpls_header != NULL );
    mpls_header_t *mpls_header = info->l2_mpls_header;
    uint32_t mpls = ntohl( mpls_header->label );
    uint8_t mpls_bos = ( uint8_t ) ( ( mpls & 0x00000100 ) >>  8 );

    uint8_t ttl = 0;
    if ( mpls_bos == 1 ) { // IP-to-MPLS copy
      // Check the length of remained buffer for an ipv4 header without options.
      if ( length < sizeof( ipv4_header_t ) ) {
        return false;
      }

      // Check the length of remained buffer for an ipv4 header with options.
      ipv4_header_t *ipv4_header = ptr;
      if ( ipv4_header->ihl < 5 ) {
        return false;
      }
      if ( length < ( size_t ) ipv4_header->ihl * 4 ) {
        return false;
      }

      ttl = ipv4_header->ttl;
    }
    else { // MPLS-to-MPLS copy
      if ( length < sizeof( mpls_header_t ) ) {
        debug("incomplete mpls");
        return false;
      }
      mpls_header_t *inner_header = ( mpls_header_t * ) ( mpls_header + 1 );
      uint32_t inner_mpls = ntohl( inner_header->label );
      ttl = inner_mpls & 0x000000FF;
    }

    uint8_t *mpls_ttl = ( ( uint8_t * ) info->l2_mpls_header ) + 3;
    *mpls_ttl = ttl;
  }
  else if ( packet_type_ipv4( frame ) || packet_type_ipv6( frame ) ) {
    warn( "IP-IP TTL copy not supported yet." );
  }
  else {
    warn( "A non-ip,mpls packet (%#x) found while setting the ttl field.", info->format );
    return true;
  }

  return parse_frame( frame );
}


static bool
execute_action_dec_mpls_ttl( buffer *frame, action *dec_mpls_ttl ) {
  assert( frame != NULL );
  assert( dec_mpls_ttl != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_eth_mpls( frame ) ) {
    warn( "A non-mpls packet (%#x) found while decrementing the mpls ttl.", info->format );
    return true;
  }

  assert( info->l2_mpls_header != NULL );
  uint8_t *ttl = ( uint8_t * ) info->l2_mpls_header + 3;

  if ( !decrement_ttl( ttl ) ) {
    match *match = duplicate_match( dec_mpls_ttl->entry->match );
    packet_info *info = ( packet_info * ) frame->user_data;
    match->in_port.value = info->eth_in_port;
    match->in_port.valid = true;
    if ( info->eth_in_phy_port != match->in_port.value ) {
      match->in_phy_port.value = info->eth_in_phy_port;
      match->in_phy_port.valid = true;
    }
    if ( info->metadata != 0 ) {
      match->metadata.value = info->metadata;
      match->metadata.valid = true;
    }
    if ( info->tunnel_id != 0 ) {
      match->tunnel_id.value = info->tunnel_id;
      match->tunnel_id.valid = true;
    }

    notify_packet_in( OFPR_INVALID_TTL, dec_mpls_ttl->entry->table_id, dec_mpls_ttl->entry->cookie, match, frame, MISS_SEND_LEN );
    delete_match( match );
  }

  return parse_frame( frame );
}


static bool
execute_action_dec_nw_ttl( buffer *frame, action *dec_nw_ttl ) {
  assert( frame != NULL );
  assert( dec_nw_ttl != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );

  bool ttl_exceeded = false;
  uint8_t *ttl = NULL;
  if ( packet_type_ipv4( frame ) ) {
    ipv4_header_t *header = info->l3_header;
    ttl = &header->ttl;
    ttl_exceeded = !decrement_ttl( ttl );
    // no tcp/udp/icmp checksum caculation here because ttl field is not included in pseudo header
    set_ipv4_checksum( header );
  }
  else if ( packet_type_ipv6( frame ) ) {
    ipv6_header_t *header = info->l3_header;
    ttl = &header->hoplimit;
    ttl_exceeded = !decrement_ttl( ttl );
  }
  else {
    warn( "A non-ip packet (%#x) found while decrementing the ttl field.", info->format );
    return true;
  }

  if ( ttl_exceeded ) {
    match *match = duplicate_match( dec_nw_ttl->entry->match );
    packet_info *info = ( packet_info * ) frame->user_data;
    match->in_port.value = info->eth_in_port;
    match->in_port.valid = true;
    if ( info->eth_in_phy_port != match->in_port.value ) {
      match->in_phy_port.value = info->eth_in_phy_port;
      match->in_phy_port.valid = true;
    }
    if ( info->metadata != 0 ) {
      match->metadata.value = info->metadata;
      match->metadata.valid = true;
    }
    if ( info->tunnel_id != 0 ) {
      match->tunnel_id.value = info->tunnel_id;
      match->tunnel_id.valid = true;
    }
    notify_packet_in( OFPR_INVALID_TTL, dec_nw_ttl->entry->table_id, dec_nw_ttl->entry->cookie, match, frame, MISS_SEND_LEN );
    delete_match( match );
  }

  return parse_frame( frame );
}


bool
execute_action_set_mpls_ttl( buffer *frame, action *set_mpls_ttl ) {
  assert( frame != NULL );
  assert( set_mpls_ttl != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( !packet_type_eth_mpls( frame ) ) {
    warn( "A non-mpls packet (%#x) found while setting the mpls ttl.", info->format );
    return true;
  }

  assert( info->l2_mpls_header != NULL );
  uint8_t *ttl = ( uint8_t * ) info->l2_mpls_header + 3;
  *ttl = set_mpls_ttl->mpls_ttl;

  return parse_frame( frame );
}


static bool
execute_action_set_nw_ttl( buffer *frame, action *set_nw_ttl ) {
  assert( frame != NULL );
  assert( set_nw_ttl != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );

  if ( packet_type_ipv4( frame ) ) {
    ipv4_header_t *header = info->l3_header;
    header->ttl = set_nw_ttl->nw_ttl;
    set_ipv4_checksum( header );
  }
  else if ( packet_type_ipv6( frame ) ) {
    ipv6_header_t *header = info->l3_header;
    header->hoplimit = set_nw_ttl->nw_ttl;
  }
  else {
    warn( "A non-ip packet (%#x) found while setting the ttl field.", info->format );
    return true;
  }

  return parse_frame( frame );
}


static bool
execute_action_set_field( buffer *frame, action *set_field ) {
  assert( frame != NULL );
  assert( set_field != NULL );
  assert( set_field->match != NULL );

  match *match = set_field->match;

  if ( match->eth_dst[ 0 ].valid ) {
    if ( !set_dl_dst( frame, match->eth_dst ) ) {
      return false;
    }
  }

  if ( match->eth_src[ 0 ].valid ) {
    if ( !set_dl_src( frame, match->eth_src ) ) {
      return false;
    }
  }

  if ( match->eth_type.valid ) {
    if ( !set_dl_type( frame, match->eth_type.value ) ) {
      return false;
    }
  }

  if ( match->vlan_vid.valid ) {
    if ( !set_vlan_vid( frame, match->vlan_vid.value ) ) {
      return false;
    }
  }

  if ( match->vlan_pcp.valid ) {
    if ( !set_vlan_pcp( frame, match->vlan_pcp.value ) ) {
      return false;
    }
  }

  if ( match->ip_dscp.valid ) {
    if ( !set_nw_dscp( frame, match->ip_dscp.value ) ) {
      return false;
    }
  }

  if ( match->ip_ecn.valid ) {
    if ( !set_nw_ecn( frame, match->ip_ecn.value ) ) {
      return false;
    }
  }

  if ( match->ip_proto.valid ) {
    if ( !set_ip_proto( frame, match->ip_proto.value ) ) {
      return false;
    }
  }

  if ( match->ipv4_src.valid ) {
    if ( !set_ipv4_src( frame, match->ipv4_src.value ) ) {
      return false;
    }
  }

  if ( match->ipv4_dst.valid ) {
    if ( !set_ipv4_dst( frame, match->ipv4_dst.value ) ) {
      return false;
    }
  }

  if ( match->tcp_src.valid ) {
    if ( !set_tcp_src( frame, match->tcp_src.value ) ) {
      return false;
    }
  }

  if ( match->tcp_dst.valid ) {
    if ( !set_tcp_dst( frame, match->tcp_dst.value ) ) {
      return false;
    }
  }

  if ( match->udp_src.valid ) {
    if ( !set_udp_src( frame, match->udp_src.value ) ) {
      return false;
    }
  }

  if ( match->udp_dst.valid ) {
    if ( !set_udp_dst( frame, match->udp_dst.value ) ) {
      return false;
    }
  }

  if ( match->icmpv4_type.valid ) {
    if ( !set_icmpv4_type( frame, match->icmpv4_type.value ) ) {
      return false;
    }
  }

  if ( match->icmpv4_code.valid ) {
    if ( !set_icmpv4_code( frame, match->icmpv4_code.value ) ) {
      return false;
    }
  }

  if ( match->arp_op.valid ) {
    if ( !set_arp_op( frame, match->arp_op.value ) ) {
      return false;
    }
  }

  if ( match->arp_spa.valid ) {
    if ( !set_arp_spa( frame, match->arp_spa.value ) ) {
      return false;
    }
  }

  if ( match->arp_tpa.valid ) {
    if ( !set_arp_tpa( frame, match->arp_tpa.value ) ) {
      return false;
    }
  }

  if ( match->arp_sha[ 0 ].valid ) {
    if ( !set_arp_sha( frame, &match->arp_sha[ 0 ] ) ) {
      return false;
    }
  }

  if ( match->arp_tha[ 0 ].valid ) {
    if ( !set_arp_tha( frame, &match->arp_tha[ 0 ] ) ) {
      return false;
    }
  }

  if ( match->ipv6_src[ 0 ].valid ) {
    if ( !set_ipv6_src( frame, &match->ipv6_src[ 0 ] ) ) {
      return false;
    }
  }

  if ( match->ipv6_dst[ 0 ].valid ) {
    if ( !set_ipv6_dst( frame, &match->ipv6_dst[ 0 ] ) ) {
      return false;
    }
  }

  if ( match->ipv6_flabel.valid ) {
    if ( !set_ipv6_flabel( frame, match->ipv6_flabel.value ) ) {
      return false;
    }
  }

  if ( match->icmpv6_type.valid ) {
    if ( !set_icmpv6_type( frame, match->icmpv6_type.value ) ) {
      return false;
    }
  }

  if ( match->icmpv6_code.valid ) {
    if ( !set_icmpv6_code( frame, match->icmpv6_code.value ) ) {
      return false;
    }
  }

  if ( match->ipv6_nd_target[ 0 ].valid ) {
    if ( !set_ipv6_nd_target( frame, match->ipv6_nd_target ) ) {
      return false;
    }
  }

  if ( match->ipv6_nd_sll[ 0 ].valid ) {
    if ( !set_ipv6_nd_sll( frame, match->ipv6_nd_sll ) ) {
      return false;
    }
  }

  if ( match->ipv6_nd_tll[ 0 ].valid ) {
    if ( !set_ipv6_nd_tll( frame, match->ipv6_nd_tll ) ) {
      return false;
    }
  }

  if ( match->mpls_label.valid ) {
    if ( !set_mpls_label( frame, match->mpls_label.value ) ) {
      return false;
    }
  }

  if ( match->mpls_tc.valid ) {
    if ( !set_mpls_tc( frame, match->mpls_tc.value ) ) {
      return false;
    }
  }

  if ( match->mpls_bos.valid ) {
    if ( !set_mpls_bos( frame, match->mpls_bos.value ) ) {
      return false;
    }
  }

  if ( match->pbb_isid.valid ) {
    if ( !set_pbb_isid( frame, match->pbb_isid.value ) ) {
      return false;
    }
  }

  if ( match->tunnel_id.valid ) {
    if ( !set_tunnel_id( frame, match->tunnel_id.value ) ) {
      return false;
    }
  }

  // TODO: sctp_dst implementation is missing.
  // TODO: sctp_src implementation is missing.

  return true;
}


static bool
execute_group_all( buffer *frame, bucket_list *buckets ) {
  assert( frame != NULL );
  assert( buckets != NULL );

  bucket_list *bucket_element = get_first_element( buckets );
  while ( bucket_element != NULL ) {
    bucket *b = bucket_element->data;
    if ( b != NULL ) {
      b->packet_count++;
      b->byte_count += frame->length;
      if ( execute_action_list( b->actions, frame ) != OFDPE_SUCCESS ) {
        return false;
      }
    }
    bucket_element = bucket_element->next;
  }

  return true;
}


static bool
execute_action_push_pbb( buffer *frame, action *push_pbb ) {
  assert( frame != NULL );
  assert( push_pbb != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );

  char *start = info->l2_payload;
  uint32_t default_isid = 0;
  if ( info->l2_pbb_header != NULL ) {
    // PBB I-SID <- PBB I-SID
    start = info->l2_pbb_header;
    pbb_header_t *pbb = info->l2_pbb_header;
    default_isid |= ntohl( pbb->isid ) & 0x00FFFFFF;
  }
  if ( info->l2_vlan_header != NULL ) {
    // PBB I-PCP <- VLAN PCP
    vlantag_header_t *vlan = info->l2_vlan_header;
    default_isid |= ( ( ( uint32_t ) ntohs( vlan->tci ) >> 13 ) << 29 ) & 0xE0000000;
  }

  void *new = push_pbb_tag( frame, start - 2 ); // push pbb before ethertype

  *( ( uint16_t * ) new ) = htons( push_pbb->ethertype );

  ether_header_t *ether = ( ether_header_t * ) frame->data;
  pbb_header_t *pbb = ( pbb_header_t * ) ( ( char * ) new + 2 );
  pbb->isid = htonl( default_isid );
  memcpy( pbb->cda, ether->macda, ETH_ADDRLEN );
  memcpy( pbb->csa, ether->macsa, ETH_ADDRLEN );

  return parse_frame( frame );
}


static bool
execute_action_pop_pbb( buffer *frame, action *pop_pbb ) {
  assert( frame != NULL );
  assert( pop_pbb != NULL );

  packet_info *info = get_packet_info_data( frame );
  assert( info != NULL );
  if ( info->l2_pbb_header == NULL ) {
    warn( "A non-pbb frame (%#x) found while popping a pbb tag.", info->format );
    return true;
  }

  pbb_header_t *pbb_header = info->l2_pbb_header;
  ether_header_t *ether_header = frame->data;
  memcpy( ether_header->macda, pbb_header->cda, ETH_ADDRLEN );
  memcpy( ether_header->macsa, pbb_header->csa, ETH_ADDRLEN );

  pop_pbb_tag( frame, ( char * ) info->l2_pbb_header - 2 ); // remove PBB ethertype and I-TAG

  return parse_frame( frame );
}


static bool
check_bucket( action_list *actions ) {
  assert( actions != NULL );

  action_list *element = get_first_element( actions );
  bool ret = true;

  while ( element != NULL ) {
    action *action = element->data;
    if ( action != NULL ) {
      if ( action->type == OFPAT_OUTPUT ) {
        if ( !switch_port_is_up( action->port ) ) {
          ret = false;
          break;
        }
      }
    }
    element = element->next;
  }

  return ret;
}


#ifdef GROUP_SELECT_BY_HASH
static inline uint32_t
group_select_by_hash_core( uint32_t value, const void *key, int size ) {
  // 32 bit FNV_prime
  const uint32_t prime = 0x01000193UL;
  const unsigned char *c = key;

  for ( int i = 0; i < size; i++ ) {
    value ^= ( const uint32_t ) c[ i ];
    value *= prime;
  }

  return value;
}


static uint32_t
group_select_by_hash( const buffer *frame ) {
  assert( frame != NULL );
  assert( frame->user_data != NULL );
  const packet_info *info = ( packet_info * ) frame->user_data;

  if ( ( info->format & ( ETH_DIX | ETH_8023_SNAP ) ) == 0 ) {
    return ( uint32_t ) rand();
  }

  // 32 bit offset_basis
  uint32_t value = 0x811c9dc5UL;

  value = group_select_by_hash_core( value, info->eth_macda, sizeof( info->eth_macda ) );
  value = group_select_by_hash_core( value, info->eth_macsa, sizeof( info->eth_macsa ) );
  value = group_select_by_hash_core( value, &info->eth_type, sizeof( info->eth_type ) );
  if ( ( info->format & ETH_8021Q ) == ETH_8021Q ) {
    value = group_select_by_hash_core( value, &info->vlan_vid, sizeof( info->vlan_vid ) );
  }
  if ( ( info->format & MPLS ) == MPLS ) {
    value = group_select_by_hash_core( value, &info->mpls_label, sizeof( info->mpls_label ) );
  }

  if ( ( info->format & NW_IPV4 ) == NW_IPV4 ) {
    value = group_select_by_hash_core( value, &info->ipv4_protocol, sizeof( info->ipv4_protocol ) );
    value = group_select_by_hash_core( value, &info->ipv4_saddr, sizeof( info->ipv4_saddr ) );
    value = group_select_by_hash_core( value, &info->ipv4_daddr, sizeof( info->ipv4_daddr ) );
  }
  else if ( ( info->format & NW_IPV6 ) == NW_IPV6 ) {
    value = group_select_by_hash_core( value, &info->ipv6_protocol, sizeof( info->ipv6_protocol ) );
    value = group_select_by_hash_core( value, &info->ipv6_saddr, sizeof( info->ipv6_saddr ) );
    value = group_select_by_hash_core( value, &info->ipv6_daddr, sizeof( info->ipv6_daddr ) );
  }
  else {
    return value;
  }

  if ( ( info->format & TP_TCP ) == TP_TCP ) {
    value = group_select_by_hash_core( value, &info->tcp_src_port, sizeof( info->tcp_src_port ) );
    value = group_select_by_hash_core( value, &info->tcp_dst_port, sizeof( info->tcp_dst_port ) );
  }
  else if ( ( info->format & TP_UDP ) == TP_UDP ) {
    value = group_select_by_hash_core( value, &info->udp_src_port, sizeof( info->udp_src_port ) );
    value = group_select_by_hash_core( value, &info->udp_dst_port, sizeof( info->udp_dst_port ) );
  }

  return value;
}
#endif


static bool
execute_group_select( buffer *frame, bucket_list *buckets ) {
  assert( frame != NULL );
  assert( buckets != NULL );

  list_element *candidates = NULL;
  create_list( &candidates );

  dlist_element *bucket_element = get_first_element( buckets );

  while ( bucket_element != NULL ) {
    bucket *b = bucket_element->data;
    if ( b != NULL ) {
      if ( !check_bucket( b->actions ) ) {
        continue;
      }
      append_to_tail( &candidates, bucket_element );
    }
    bucket_element = bucket_element->next;
  }

  uint32_t length_of_candidates = list_length_of( candidates );
  if ( length_of_candidates == 0 ) {
    delete_list( candidates );
    return true;
  }

#ifdef GROUP_SELECT_BY_HASH
  uint32_t candidate_index = group_select_by_hash( frame ) % length_of_candidates;
#else
  uint32_t candidate_index = ( ( uint32_t ) rand() ) % length_of_candidates;
#endif
  debug( "execute group select. bucket=%u(/%u)", candidate_index, length_of_candidates );
  list_element *target = candidates;
  for ( uint32_t i = 0; target != NULL && i < length_of_candidates; i++ ) {
    if ( i == candidate_index ) {
      break;
    }
    target = target->next;
  }

  if ( target != NULL ) {
    bucket_element = target->data;
    bucket *b = bucket_element->data;
    if ( b != NULL ) {
      b->packet_count++;
      b->byte_count += frame->length;
      if ( execute_action_list( b->actions, frame ) != OFDPE_SUCCESS ) {
        delete_list( candidates );
        return false;
      }
    }
  }

  delete_list( candidates );

  return true;
}


static bool
execute_group_indirect( buffer *frame, bucket_list *buckets ) {
  assert( frame != NULL );
  assert( buckets != NULL );

  dlist_element *element = get_first_element( buckets );
  if ( element->next != NULL || element->prev != NULL ) {
    error( "Only a single bucket can exist in a group." );
    return false;
  }

  bucket *b = element->data;
  b->packet_count++;
  b->byte_count += frame->length;
  dlist_element *actions = get_first_element( b->actions );

  if ( execute_action_list( actions, frame ) != OFDPE_SUCCESS ) {
    return false;
  }

  return true;
}


static bool
execute_action_group( buffer *frame, action *group ) {
  assert( frame != NULL );
  assert( group != NULL );

  group_entry *entry = lookup_group_entry( group->group_id );
  if ( entry == NULL ) {
    return true;
  }

  entry->packet_count++;
  entry->byte_count += frame->length;

  bool ret = false;

  switch ( entry->type ) {
    case OFPGT_ALL:
    {
      debug( "Executing action group (OFPGT_ALL)." );
      ret = execute_group_all( frame, entry->buckets );
    }
    break;

    case OFPGT_SELECT:
    {
      debug( "Execute action group (OFPGT_SELECT)." );
      ret = execute_group_select( frame, entry->buckets );
    }
    break;

    case OFPGT_INDIRECT:
    {
      debug( "Executing action group (OFPGT_INDIRECT)." );
      ret = execute_group_indirect( frame, entry->buckets );
    }
    break;

    case OFPGT_FF:
    {
      debug( "Executing action group (OFPGT_FF)." );
      warn( "OFPGT_FF is not implemented." );
      ret = false;
    }
    break;

    default:
    {
      error( "Undefined group type (%#x).", entry->type );
      ret = false;
    }
    break;
  }

  return ret;
}


static bool
execute_action_output( buffer *frame, action *output ) {
  assert( frame != NULL );
  assert( output != NULL );

  bool ret = true;

  if ( output->port == OFPP_CONTROLLER ) {
    packet_info *info = ( packet_info * ) frame->user_data;
    uint32_t in_port = info->eth_in_port;
    switch_port *port = lookup_switch_port( in_port );

    match *match = NULL;
    uint8_t table_id = 0;
    uint64_t cookie = 0;
    if ( output->entry != NULL ) {
      match = duplicate_match( output->entry->match );
      cookie = output->entry->cookie;
      table_id = output->entry->table_id;
    } else {
      match = create_match();
    }
    match->in_port.value = info->eth_in_port;
    match->in_port.valid = true;
    if ( info->eth_in_phy_port != match->in_port.value ) {
      match->in_phy_port.value = info->eth_in_phy_port;
      match->in_phy_port.valid = true;
    }
    if ( info->metadata != 0 ) {
      match->metadata.value = info->metadata;
      match->metadata.valid = true;
    }
    if ( info->tunnel_id != 0 ) {
      match->tunnel_id.value = info->tunnel_id;
      match->tunnel_id.valid = true;
    }
    if ( output->entry != NULL && output->entry->table_miss ) {
      if ( port == NULL || ( port->config & OFPPC_NO_PACKET_IN ) == 0 ){
        notify_packet_in( OFPR_NO_MATCH, table_id, cookie, match, frame, MISS_SEND_LEN );
      }
    }
    else {
      notify_packet_in( OFPR_ACTION, table_id, cookie, match, frame, output->max_len );
    }
    delete_match( match );
  }
  else if ( output->port == OFPP_TABLE ) {
    packet_info *info = ( packet_info * ) frame->user_data;
    uint32_t in_port = info->eth_in_port;

    // port is valid standard switch port or OFPP_CONTROLLER
    switch_port *port = lookup_switch_port( in_port );
    bool free_port = false;
    if ( port == NULL ){
      port = ( switch_port * ) xmalloc( sizeof( switch_port ) );
      memset( port, 0, sizeof( switch_port ) );
      port->port_no = OFPP_CONTROLLER;
      free_port = true;
    }

    handle_received_frame( port, frame );

    if ( free_port ) {
      xfree( port );
    }
  }
  else {
    if ( send_frame_from_switch_port( output->port, frame ) != OFDPE_SUCCESS ) {
      ret = false;
    }
  }

  return ret;
}


OFDPE
execute_action_list( action_list *list, buffer *frame ) {
  assert( list != NULL );
  assert( frame != NULL );

  debug( "Executing action list ( list = %p, frame = %p ).", list, frame );

  for ( action_list *element = get_first_element( list ); element != NULL; element = element->next ) {
    action *action = element->data;
    if ( action == NULL ) {
      continue;
    }

    bool ret = false;
    switch ( action->type ) {
      case OFPAT_OUTPUT:
      {
        debug( "Executing action (OFPAT_OUTPUT): port = %u, maxlen = %u.", action->port, action->max_len );
        ret = execute_action_output( frame, action );
      }
      break;
      
      case OFPAT_COPY_TTL_OUT:
      {
        debug( "Executing action (OFPAT_COPY_TTL_OUT)." );
        ret = execute_action_copy_ttl_out( frame, action );
      }
      break;

      case OFPAT_COPY_TTL_IN:
      {
        debug( "Executing action (OFPAT_COPY_TTL_IN)." );
        ret = execute_action_copy_ttl_in( frame, action );
      }
      break;

      case OFPAT_SET_MPLS_TTL:
      {
        debug( "Executing action (OFPAT_SET_MPLS_TTL): ttl = %u.", action->mpls_ttl );
        ret = execute_action_set_mpls_ttl( frame, action );
      }
      break;

      case OFPAT_DEC_MPLS_TTL:
      {
        debug( "Executing action (OFPAT_DEC_MPLS_TTL)." );
        ret = execute_action_dec_mpls_ttl( frame, action );
      }
      break;

      case OFPAT_PUSH_VLAN:
      {
        debug( "Executing action (OFPAT_PUSH_VLAN)." );
        ret = execute_action_push_vlan( frame, action );
      }
      break;

      case OFPAT_POP_VLAN:
      {
        debug( "Executing action (OFPAT_POP_VLAN)." );
        ret = execute_action_pop_vlan( frame, action );
      }
      break;

      case OFPAT_PUSH_MPLS:
      {
        debug( "Executing action (OFPAT_PUSH_MPLS)." );
        ret = execute_action_push_mpls( frame, action );
      }
      break;

      case OFPAT_POP_MPLS:
      {
        debug( "Executing action (OFPAT_POP_MPLS)." );
        ret = execute_action_pop_mpls( frame, action );
      }
      break;

      case OFPAT_SET_QUEUE:
      {
        debug( "Executing action (OFPAT_SET_QUEUE)." );
        warn( "OFPAT_SET_QUEUE is not supported." );
        ret = false;
      }
      break;

      case OFPAT_GROUP:
      {
        debug( "Executing action (OFPAT_GROUP)." );
        ret = execute_action_group( frame, action );
      }
      break;

      case OFPAT_SET_NW_TTL:
      {
        debug( "Executing action (OFPAT_SET_NW_TTL): ttl = %u.", action->nw_ttl );
        ret = execute_action_set_nw_ttl( frame, action );
      }
      break;

      case OFPAT_DEC_NW_TTL:
      {
        debug( "Executing action (OFPAT_DEC_NW_TTL)." );
        ret = execute_action_dec_nw_ttl( frame, action );
      }
      break;

      case OFPAT_SET_FIELD:
      {
        debug( "Executing action (OFPAT_SET_FIELD)." );
        ret = execute_action_set_field( frame, action );
      }
      break;

      case OFPAT_PUSH_PBB:
      {
        debug( "Executing action (OFPAT_PUSH_PBB)." );
        ret = execute_action_push_pbb( frame, action );
      }
      break;

      case OFPAT_POP_PBB:
      {
        debug( "Executing action (OFPAT_POP_PBB)." );
        ret = execute_action_pop_pbb( frame, action );
      }
      break;

      case OFPAT_EXPERIMENTER:
      {
        debug( "Executing action (OFPAT_EXPERIMENTER)." );
        warn( "OFPAT_EXPERIMENTER is not supported." );
        ret = false;
      }
      break;

      default:
      {
        error( "Undefined actions type (%#x).", action->type );
        ret = false;
      }
      break;
    }

    if ( !ret ) {
      return OFDPE_FAILED;
    }
  }

  return OFDPE_SUCCESS;
}


OFDPE
execute_action_set( action_set *set, buffer *frame ) {
  assert( set != NULL );
  assert( frame != NULL );

  debug( "Executing action set ( set = %p, frame = %p ).", set, frame );

  if ( set->copy_ttl_in != NULL ) {
    debug( "Executing action (OFPAT_COPY_TTL_IN)." );
    if ( !execute_action_copy_ttl_in( frame, set->copy_ttl_in ) ) {
      return OFDPE_FAILED;
    }
  }

  if ( set->pop_vlan != NULL ) {
    debug( "Executing action (OFPAT_POP_VLAN)." );
    if ( !execute_action_pop_vlan( frame, set->pop_vlan ) ) {
      return OFDPE_FAILED;
    }
  }

  if ( set->pop_pbb != NULL ) {
    debug( "Executing action (OFPAT_POP_PBB)." );
    if ( !execute_action_pop_pbb( frame, set->pop_pbb ) ) {
      return OFDPE_FAILED;
    }
  }

  if ( set->pop_mpls != NULL ) {
    debug( "Executing action (OFPAT_POP_MPLS)." );
    if ( !execute_action_pop_mpls( frame, set->pop_mpls ) ) {
      return OFDPE_FAILED;
    }
  }

  if ( set->push_mpls != NULL ) {
    debug( "Executing action (OFPAT_PUSH_MPLS)." );
    if ( !execute_action_push_mpls( frame, set->push_mpls ) ) {
      return OFDPE_FAILED;
    }
  }

  if ( set->push_pbb != NULL ) {
    debug( "Executing action (OFPAT_PUSH_PBB)." );
    if ( !execute_action_push_pbb( frame, set->push_pbb ) ) {
      return OFDPE_FAILED;
    }
  }

  if ( set->push_vlan != NULL ) {
    debug( "Executing action (OFPAT_PUSH_VLAN)." );
    if ( !execute_action_push_vlan( frame, set->push_vlan ) ) {
      return OFDPE_FAILED;
    }
  }

  if ( set->copy_ttl_out != NULL ) {
    debug( "Executing action (OFPAT_COPY_TTL_OUT)." );
    if ( !execute_action_copy_ttl_out( frame, set->copy_ttl_out ) ) {
      return OFDPE_FAILED;
    }
  }

  if ( set->dec_mpls_ttl != NULL ) {
    debug( "Executing action (OFPAT_DEC_MPLS_TTL)." );
    if ( !execute_action_dec_mpls_ttl( frame, set->dec_mpls_ttl ) ) {
      return OFDPE_FAILED;
    }
  }

  if ( set->dec_nw_ttl != NULL ) {
    debug( "Executing action (OFPAT_DEC_NW_TTL)." );
    if ( !execute_action_dec_nw_ttl( frame, set->dec_nw_ttl ) ) {
      return OFDPE_FAILED;
    }
  }

  if ( set->set_mpls_ttl != NULL ) {
    debug( "Executing action (OFPAT_SET_MPLS_TTL)." );
    if ( !execute_action_set_mpls_ttl( frame, set->set_mpls_ttl ) ) {
      return OFDPE_FAILED;
    }
  }

  if ( set->set_nw_ttl != NULL ) {
    debug( "Executing action (OFPAT_SET_NW_TTL)." );
    if ( !execute_action_set_nw_ttl( frame, set->set_nw_ttl ) ) {
      return OFDPE_FAILED;
    }
  }

  if ( set->set_field != NULL ) {
    debug( "Executing action (OFPAT_SET_FIELD)." );
    if ( !execute_action_set_field( frame, set->set_field ) ) {
      return OFDPE_FAILED;
    }
  }

  if ( set->set_queue != NULL ) {
    debug( "Executing action (OFPAT_SET_QUEUE)." );
    warn( "OFPAT_SET_QUEUE is not supported" );
    return OFDPE_FAILED;
  }

  if ( set->group != NULL ) {
    debug( "Executing action (OFPAT_GROUP)." );
    if ( !execute_action_group( frame, set->group ) ) {
      return OFDPE_FAILED;
    }
  }

  if ( set->group == NULL && set->output != NULL ) {
    debug( "Executing action (OFPAT_OUTPUT)." );
    if ( !execute_action_output( frame, set->output ) ) {
      return OFDPE_FAILED;
    }
  }

  return OFDPE_SUCCESS;
}


OFDPE
execute_packet_out( uint32_t buffer_id, uint32_t in_port, action_list *action_list, buffer *frame ) {
  assert( action_list != NULL );

  buffer *target = NULL;

  if ( get_logging_level() >= LOG_DEBUG ) {
    debug( "Handling Packet-Out ( buffer_id = %#x, in_port = %u, actions_list = %p, frame = %p ).",
           buffer_id, in_port, action_list, frame );
    dump_action_list( action_list, debug );
    if ( frame != NULL ) {
      dump_buffer( frame, debug );
    }
  }

  if ( buffer_id != OFP_NO_BUFFER ) {
    target = get_packet_from_packet_in_buffer( buffer_id );
    if ( target == NULL ) {
      error( "Failed to retrieve packet from packet buffer ( buffer_id = %#x ).", buffer_id );
      return ERROR_OFDPE_BAD_REQUEST_BUFFER_UNKNOWN;
    }
  }
  else {
    if ( frame == NULL ) {
      return ERROR_OFDPE_BAD_REQUEST_BAD_PACKET;
    }
    target = duplicate_buffer( frame );
  }

  if ( target->user_data == NULL ) {
    if ( !parse_packet( target ) ) {
      free_buffer( target );
      return ERROR_OFDPE_BAD_REQUEST_BAD_PACKET;
    }
  }

  assert( target->user_data != NULL );
  if ( in_port > 0 && ( in_port <= OFPP_MAX || in_port == OFPP_CONTROLLER ) ) {
    ( ( packet_info * ) target->user_data )->eth_in_port = in_port;
    ( ( packet_info * ) target->user_data )->eth_in_phy_port = in_port;
  }

  if ( !lock_pipeline() ) {
    free_buffer( target );
    return OFDPE_FAILED;
  }

  OFDPE ret = execute_action_list( action_list, target );
  if ( ret != OFDPE_SUCCESS ) {
    error( "Failed to execute action list on Packet-Out ( action_list = %p, target = %p ).",
           action_list, target );
    dump_action_list( action_list, error );
    dump_buffer( target, error );
  }

  unlock_pipeline();

  free_buffer( target );

  return ret;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/
