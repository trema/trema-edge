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
#include "trema.h"
#include "ruby.h"
#include "action-common.h"
#include "hash-util.h"
#include "unpack-util.h"


buffer *
r_array_to_buffer( VALUE r_array ) {
  buffer *data = NULL;

  if ( !NIL_P( r_array ) ) {
    Check_Type( r_array, T_ARRAY );
    uint32_t length = ( uint32_t ) RARRAY_LEN( r_array );

    data = alloc_buffer_with_length( length );
    append_back_buffer( data, length );
    uint8_t *data_ptr = data->data;
    for ( uint32_t i = 0; i < length; i++ ) {
      data_ptr[ i ] = ( uint8_t ) FIX2INT( rb_ary_entry( r_array , i ) );
    }
  }
  return data;
}


VALUE
buffer_to_r_array( const buffer *buffer ) {
  if ( buffer != NULL ) {
    if ( buffer->length ) {
      uint16_t length = ( uint16_t ) buffer->length;
      VALUE data_array = rb_ary_new2( ( long int ) length );
      uint8_t *data = ( uint8_t * ) ( ( char * ) buffer->data );
      long i;

      for ( i = 0; i < length; i++ ) {
        rb_ary_push( data_array, INT2FIX( data[ i ] ) );
      }
      return data_array;
    }
  }
  return Qnil;
}


VALUE
ofp_match_to_r_match( const struct ofp_match *match ) {
  assert( match != NULL );
  assert( match->length >= offsetof( struct ofp_match, oxm_fields ) );

  uint16_t oxms_len = 0;
  uint16_t oxm_len = 0;
  const oxm_match_header *src;

  uint16_t offset = offsetof( struct ofp_match, oxm_fields );
  oxms_len = ( uint16_t ) ( match->length - offset );
  src = ( const oxm_match_header * ) ( ( const char * ) match + offset );
  VALUE r_attributes = rb_hash_new();

  while ( oxms_len > sizeof( oxm_match_header ) ) {
    oxm_len = OXM_LENGTH( *src );
    unpack_r_match( src, r_attributes );

    offset = ( uint16_t ) ( sizeof( oxm_match_header ) + oxm_len );
    if ( oxms_len < offset ) {
      break;
    }
    oxms_len = ( uint16_t ) ( oxms_len - offset );
    src = ( const oxm_match_header * ) ( ( const char * ) src + offset );
  }
  return rb_funcall( rb_eval_string( "Trema::Match" ), rb_intern( "new" ), 1, r_attributes );
}


#define APPEND_OXM_MATCH_UINT8( r_match, at_value, append_oxm_match_f, match ) \
{ \
  VALUE r_value = rb_iv_get( r_match, at_value ); \
  if ( !NIL_P( r_value ) ) { \
    append_oxm_match_f( match, ( uint8_t ) NUM2UINT( r_value ) ); \
  } \
}

#define APPEND_OXM_MATCH_UINT16( r_match, at_value, append_oxm_match_f, match ) \
{ \
  VALUE r_value = rb_iv_get( r_match, at_value ); \
  if ( !NIL_P( r_value ) ) { \
    append_oxm_match_f( match, ( uint16_t ) NUM2UINT( r_value ) ); \
  } \
}

#define APPEND_OXM_MATCH_UINT16_MASK( r_match, at_value, append_oxm_match_f, match ) \
{ \
  VALUE r_value = rb_iv_get( r_match, at_value ); \
  if ( !NIL_P( r_value ) ) { \
    uint16_t mask = 0; \
    VALUE r_mask = rb_iv_get( r_match, at_value "_mask" ); \
    if ( !NIL_P( r_mask ) ) { \
      mask = ( uint16_t ) NUM2UINT( r_mask ); \
    } \
    append_oxm_match_f( match, ( uint16_t ) NUM2UINT( r_value ), mask ); \
  } \
}

#define APPEND_OXM_MATCH_UINT32( r_match, at_value, append_oxm_match_f, match ) \
{ \
  VALUE r_value = rb_iv_get( r_match, at_value ); \
  if ( !NIL_P( r_value ) ) { \
    append_oxm_match_f( match, NUM2UINT( r_value ) ); \
  } \
}

#define APPEND_OXM_MATCH_UINT32_MASK( r_match, at_value, append_oxm_match_f, match ) \
{ \
  VALUE r_value = rb_iv_get( r_match, at_value ); \
  if ( !NIL_P( r_value ) ) { \
    uint32_t mask = UINT32_MAX; \
    VALUE r_mask = rb_iv_get( r_match, at_value "_mask" ); \
    if ( !NIL_P( r_mask ) ) { \
      mask = NUM2UINT( r_mask ); \
    } \
    append_oxm_match_f( match, NUM2UINT( r_value ), mask ); \
  } \
}

#define APPEND_OXM_MATCH_UINT64_MASK( r_match, at_value, append_oxm_match_f, match ) \
{ \
  VALUE r_value = rb_iv_get( r_match, at_value ); \
  if ( !NIL_P( r_value ) ) { \
    uint64_t mask = UINT64_MAX; \
    VALUE r_mask = rb_iv_get( r_match, at_value "_mask" ); \
    if ( !NIL_P( r_mask ) ) { \
      mask = ( uint64_t ) NUM2ULL( r_mask ); \
    } \
    append_oxm_match_f( match, ( uint64_t ) NUM2ULL( r_value ), mask ); \
  } \
}

#define APPEND_OXM_MATCH_DL_ADDR( r_match, at_value, append_oxm_match_f, match ) \
{ \
  VALUE r_value = rb_iv_get( r_match, at_value ); \
  if ( !NIL_P( r_value ) ) { \
    uint8_t dl_addr[ OFP_ETH_ALEN ]; \
    append_oxm_match_f( match, dl_addr_to_a( r_value, dl_addr ) ); \
  } \
}

#define APPEND_OXM_MATCH_DL_ADDR_MASK( r_match, at_value, append_oxm_match_f, match ) \
{ \
  VALUE r_value = rb_iv_get( r_match, at_value ); \
  if ( !NIL_P( r_value ) ) { \
    uint8_t dl_mask[ OFP_ETH_ALEN ] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }; \
    VALUE r_mask = rb_iv_get( r_match, at_value "_mask" ); \
    if ( !NIL_P( r_mask ) ) { \
      dl_addr_to_a( r_mask, dl_mask ); \
    } \
    uint8_t dl_addr[ OFP_ETH_ALEN ]; \
    append_oxm_match_f( match, dl_addr_to_a( r_value, dl_addr ), dl_mask ); \
  } \
}

#define APPEND_OXM_MATCH_IPV4_ADDR( r_match, at_value, append_oxm_match_f, match ) \
{ \
  VALUE r_value = rb_iv_get( r_match, at_value ); \
  if ( !NIL_P( r_value ) ) { \
    append_oxm_match_f( match, nw_addr_to_i( r_value ) ); \
  } \
}

#define APPEND_OXM_MATCH_IPV4_ADDR_MASK( r_match, at_value, append_oxm_match_f, match ) \
{ \
  VALUE r_value = rb_iv_get( r_match, at_value ); \
  if ( !NIL_P( r_value ) ) { \
    uint32_t ipv4_mask = UINT32_MAX; \
    VALUE r_mask = rb_iv_get( r_match, at_value "_mask" ); \
    if ( !NIL_P( r_mask ) ) { \
      ipv4_mask = nw_addr_to_i( r_mask ); \
    } \
    append_oxm_match_f( match, nw_addr_to_i( r_value ), ipv4_mask ); \
  } \
}

#define APPEND_OXM_MATCH_IPV6_ADDR( r_match, at_value, append_oxm_match_f, match ) \
{ \
  VALUE r_value = rb_iv_get( r_match, at_value ); \
  if ( !NIL_P( r_value ) ) { \
    struct in6_addr ipv6_addr; \
    append_oxm_match_f( match, ipv6_addr_to_in6_addr( r_value, &ipv6_addr ) ); \
  } \
}

#define APPEND_OXM_MATCH_IPV6_ADDR_MASK( r_match, at_value, append_oxm_match_f, match ) \
{ \
  VALUE r_value = rb_iv_get( r_match, at_value ); \
  if ( !NIL_P( r_value ) ) { \
    struct in6_addr ipv6_mask; \
    memset( ipv6_mask.s6_addr, 0xff, sizeof( ipv6_mask.s6_addr ) ); \
    VALUE r_mask = rb_iv_get( r_match, at_value "_mask" ); \
    if ( !NIL_P( r_mask ) ) { \
      ipv6_addr_to_in6_addr( r_mask, &ipv6_mask ); \
    } \
    struct in6_addr ipv6_addr; \
    append_oxm_match_f( match, ipv6_addr_to_in6_addr( r_value, &ipv6_addr ), ipv6_mask ); \
  } \
}

void
r_match_to_oxm_match( VALUE r_match, oxm_matches *match ) {
  APPEND_OXM_MATCH_UINT32( r_match, "@in_port", append_oxm_match_in_port, match );
  APPEND_OXM_MATCH_UINT32( r_match, "@in_phy_port", append_oxm_match_in_phy_port, match );

  APPEND_OXM_MATCH_UINT64_MASK( r_match, "@metadata", append_oxm_match_metadata, match );

  APPEND_OXM_MATCH_DL_ADDR_MASK( r_match, "@eth_src", append_oxm_match_eth_src, match );
  APPEND_OXM_MATCH_DL_ADDR_MASK( r_match, "@eth_dst", append_oxm_match_eth_dst, match );

  APPEND_OXM_MATCH_UINT16( r_match, "@eth_type", append_oxm_match_eth_type, match );
  APPEND_OXM_MATCH_UINT16_MASK( r_match, "@vlan_vid", append_oxm_match_vlan_vid, match );

  APPEND_OXM_MATCH_UINT8( r_match, "@vlan_pcp", append_oxm_match_vlan_pcp, match );
  APPEND_OXM_MATCH_UINT8( r_match, "@ip_dscp", append_oxm_match_ip_dscp, match );
  APPEND_OXM_MATCH_UINT8( r_match, "@ip_ecn", append_oxm_match_ip_ecn, match );
  APPEND_OXM_MATCH_UINT8( r_match, "@ip_proto", append_oxm_match_ip_proto, match );

  APPEND_OXM_MATCH_IPV4_ADDR_MASK( r_match, "@ipv4_src", append_oxm_match_ipv4_src, match );
  APPEND_OXM_MATCH_IPV4_ADDR_MASK( r_match, "@ipv4_dst", append_oxm_match_ipv4_dst, match );

  APPEND_OXM_MATCH_UINT16( r_match, "@tcp_src", append_oxm_match_tcp_src, match );
  APPEND_OXM_MATCH_UINT16( r_match, "@tcp_dst", append_oxm_match_tcp_dst, match );
  APPEND_OXM_MATCH_UINT16( r_match, "@udp_src", append_oxm_match_udp_src, match );
  APPEND_OXM_MATCH_UINT16( r_match, "@udp_dst", append_oxm_match_udp_dst, match );
  APPEND_OXM_MATCH_UINT16( r_match, "@sctp_src", append_oxm_match_sctp_src, match );
  APPEND_OXM_MATCH_UINT16( r_match, "@sctp_dst", append_oxm_match_sctp_dst, match );

  APPEND_OXM_MATCH_UINT8( r_match, "@icmpv4_type", append_oxm_match_icmpv4_type, match );
  APPEND_OXM_MATCH_UINT8( r_match, "@icmpv4_code", append_oxm_match_icmpv4_code, match );

  APPEND_OXM_MATCH_UINT16( r_match, "@arp_op", append_oxm_match_arp_op, match );

  APPEND_OXM_MATCH_IPV4_ADDR_MASK( r_match, "@arp_spa", append_oxm_match_arp_spa, match );
  APPEND_OXM_MATCH_IPV4_ADDR_MASK( r_match, "@arp_tpa", append_oxm_match_arp_tpa, match );

  APPEND_OXM_MATCH_DL_ADDR_MASK( r_match, "@arp_sha", append_oxm_match_arp_sha, match );
  APPEND_OXM_MATCH_DL_ADDR_MASK( r_match, "@arp_tha", append_oxm_match_arp_tha, match );

  APPEND_OXM_MATCH_IPV6_ADDR_MASK( r_match, "@ipv6_src", append_oxm_match_ipv6_src, match );
  APPEND_OXM_MATCH_IPV6_ADDR_MASK( r_match, "@ipv6_dst", append_oxm_match_ipv6_dst, match );

  APPEND_OXM_MATCH_UINT32_MASK( r_match, "@ipv6_flable", append_oxm_match_ipv6_flabel, match );

  APPEND_OXM_MATCH_UINT8( r_match, "@icmpv6_type", append_oxm_match_icmpv6_type, match );
  APPEND_OXM_MATCH_UINT8( r_match, "@icmpv6_code", append_oxm_match_icmpv6_code, match );

  APPEND_OXM_MATCH_IPV6_ADDR( r_match, "@ipv6_nd_target", append_oxm_match_ipv6_nd_target, match );

  APPEND_OXM_MATCH_DL_ADDR( r_match, "@ipv6_nd_sll", append_oxm_match_ipv6_nd_sll, match );
  APPEND_OXM_MATCH_DL_ADDR( r_match, "@ipv6_nd_tll", append_oxm_match_ipv6_nd_tll, match );

  APPEND_OXM_MATCH_UINT32( r_match, "@mpls_label", append_oxm_match_mpls_label, match );

  APPEND_OXM_MATCH_UINT8( r_match, "@mpls_tc", append_oxm_match_mpls_tc, match );
  APPEND_OXM_MATCH_UINT8( r_match, "@mpls_bos", append_oxm_match_mpls_bos, match );

  APPEND_OXM_MATCH_UINT32_MASK( r_match, "@pbb_isid", append_oxm_match_pbb_isid, match );

  APPEND_OXM_MATCH_UINT64_MASK( r_match, "@tunnel_id", append_oxm_match_tunnel_id, match );

  APPEND_OXM_MATCH_UINT16_MASK( r_match, "@ipv6_exthdr", append_oxm_match_ipv6_exthdr, match );
}


VALUE
oxm_match_to_r_match( const oxm_matches *match ) {
  assert( match != NULL );

  VALUE r_options = rb_hash_new();

  for ( list_element *list = match->list; list != NULL; list = list->next ) {
    const oxm_match_header *oxm = list->data;
    unpack_r_match( oxm, r_options );
  }
  return rb_funcall( rb_eval_string( "Trema::Match" ), rb_intern( "new" ), 1, r_options );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
