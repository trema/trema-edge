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
#include "hash-util.h"
#include "conversion-util.h"


#define PACKET_INFO_MAC_ADDR( packet_member )                                          \
  {                                                                                    \
    VALUE ret = ULL2NUM( mac_to_uint64( ( ( packet_info * ) ( frame->user_data ) )->packet_member ) ); \
    return rb_funcall( rb_eval_string( "Mac" ), rb_intern( "new" ), 1, ret );  \
  }


#define PACKET_INFO_IPv4_ADDR( packet_member )                                          \
  {                                                                                   \
    VALUE ret = UINT2NUM( ( ( packet_info * ) ( frame->user_data ) )->packet_member ); \
    return rb_funcall( rb_eval_string( "IPAddr" ), rb_intern( "new" ), 2, ret, rb_eval_string( "Socket::AF_INET" )  );   \
  }


#define PACKET_INFO_IPv6_ADDR( packet_member ) \
  { \
      char ipv6_str[ INET6_ADDRSTRLEN ]; \
      memset( ipv6_str, '\0', sizeof( ipv6_str ) ); \
      if ( inet_ntop( AF_INET6, &( ( packet_info * ) ( frame->user_data ) )->packet_member, ipv6_str, sizeof( ipv6_str ) ) != NULL ) { \
        return rb_funcall( rb_eval_string( "IPAddr" ), rb_intern( "new" ), 1, rb_str_new2( ipv6_str ) ); \
      } \
      return Qnil; \
  }


static packet_info *
get_packet_in_info( const buffer *frame ) {
  return ( packet_info * ) ( frame->user_data );
}




static VALUE
packet_in_match( packet_in *message ) {
  return oxm_match_to_r_match( message->match );
}


static VALUE
packet_in_data( packet_in *message ) {
  const buffer *data_frame = message->data;
  return buffer_to_r_array( data_frame );
}


static VALUE
packet_in_eth_type( const buffer *frame ) {
  return UINT2NUM( get_packet_in_info( frame )->eth_type );
}


static VALUE
packet_in_eth_src( const buffer *frame ) {
  PACKET_INFO_MAC_ADDR( eth_macsa )
}


static VALUE
packet_in_eth_dst( const buffer *frame ) {
  PACKET_INFO_MAC_ADDR( eth_macda )
}


static VALUE
packet_in_vlan_vid( const buffer *frame ) {
  return UINT2NUM( get_packet_in_info( frame )->vlan_vid );
}


static VALUE
packet_in_vlan_pcp( const buffer *frame ) {
  return UINT2NUM( get_packet_in_info( frame )->vlan_prio );
}


static VALUE
packet_in_vlan_cfi( const buffer *frame ) {
  return UINT2NUM( get_packet_in_info( frame )->vlan_cfi );
}


static VALUE
packet_in_vlan_tci( const buffer *frame ) {
  return UINT2NUM( get_packet_in_info( frame )->vlan_tci );
}


static VALUE
packet_in_vlan_tpid( const buffer *frame ) {
  return UINT2NUM( get_packet_in_info( frame )->vlan_tpid );
}


static VALUE
packet_in_arp_op( const buffer *frame ) {
  return UINT2NUM( get_packet_in_info( frame )->arp_ar_op );
}


static VALUE
packet_in_arp_sha( const buffer *frame ) {
  PACKET_INFO_MAC_ADDR( arp_sha )
}


static VALUE
packet_in_arp_spa( const buffer *frame ) {
  PACKET_INFO_IPv4_ADDR( arp_spa )
}


static VALUE
packet_in_arp_tha( const buffer *frame ) {
  PACKET_INFO_MAC_ADDR( arp_tha )
}


static VALUE
packet_in_arp_tpa( const buffer *frame ) {
  PACKET_INFO_IPv4_ADDR( arp_tpa )
}


static VALUE
packet_in_ipv6_src( const buffer *frame ) {
  PACKET_INFO_IPv6_ADDR( ipv6_saddr )
}


static VALUE
packet_in_ipv6_dst( const buffer *frame ) {
  PACKET_INFO_IPv6_ADDR( ipv6_daddr )
}


static VALUE
packet_in_ipv6_flabel( const buffer *frame ) {
  return UINT2NUM( get_packet_in_info( frame )->ipv6_flowlabel );
}


static VALUE
packet_in_icmpv4( const uint8_t ip_proto ) {
  return ( ip_proto == IPPROTO_ICMP ) ? Qtrue : Qfalse;
}


static VALUE
packet_in_icmpv6( const uint8_t ip_proto ) {
  return ( ip_proto == IPPROTO_ICMPV6 ) ? Qtrue : Qfalse;
}


static VALUE
packet_in_ip_dscp( const buffer *frame ) {
  if ( packet_type_ipv4( frame ) ) {
    return UINT2NUM( get_packet_in_info( frame )->ipv4_tos >> 2 & 0x3f );
  }
  if ( packet_type_ipv6( frame ) ) {
    return UINT2NUM( get_packet_in_info( frame )->ipv6_tc >> 2 & 0x3f );
  }
  return Qnil;
}


static VALUE
packet_in_ip_ecn( const buffer *frame ) {
  if ( packet_type_ipv4( frame ) ) {
    return UINT2NUM( get_packet_in_info( frame )->ipv4_tos & 0x3 );
  }
  if ( packet_type_ipv6( frame ) ) {
    return UINT2NUM( get_packet_in_info( frame )->ipv6_tc & 0x3 );
  }
  return Qnil;
}


static VALUE
packet_in_ipv4_src( const buffer *frame ) {
  PACKET_INFO_IPv4_ADDR( ipv4_saddr )
}


static VALUE
packet_in_ipv4_dst( const buffer *frame ) {
  PACKET_INFO_IPv4_ADDR( ipv4_daddr )
}


static VALUE
packet_in_arp( const buffer *frame ) {
  return ( packet_type_arp( frame ) ) ? Qtrue : Qfalse;
}


static VALUE
packet_in_vtag( const buffer *frame ) {
  return ( packet_type_eth_vtag( frame ) ) ? Qtrue : Qfalse;
}


static bool
packet_in_ipv4( const buffer *frame ) {
  return packet_type_ipv4( frame );
}


static bool
packet_in_ipv6( const buffer *frame ) {
  return packet_type_ipv6( frame );
}


static VALUE
packet_in_ipv4_tos( const buffer *frame ) {
  return UINT2NUM( get_packet_in_info( frame )->ipv4_tos );
}


static VALUE
packet_in_ipv4_tot_len( const buffer *frame ) {
  return UINT2NUM( get_packet_in_info( frame )->ipv4_tot_len );
}


static VALUE
packet_in_ipv4_id( const buffer *frame ) {
  return UINT2NUM( get_packet_in_info( frame )->ipv4_id );
}


static VALUE
packet_in_ip_proto( const buffer *frame ) {
  if ( packet_in_ipv4( frame ) ) {
    return UINT2NUM( get_packet_in_info( frame )->ipv4_protocol );
  }
  if ( packet_in_ipv6( frame ) ) {
    return UINT2NUM( get_packet_in_info( frame )->ipv6_protocol );
  }
  return Qnil;
}


static VALUE
packet_in_igmp( const buffer *frame ) {
  return ( packet_type_igmp( frame ) ) ? Qtrue : Qfalse;
}


static VALUE
packet_in_ipv4_tcp( const buffer *frame ) {
  return ( packet_type_ipv4_tcp( frame ) ) ? Qtrue : Qfalse;
}


static VALUE
packet_in_ipv4_udp( const buffer *frame ) {
  return ( packet_type_ipv4_udp( frame ) ) ? Qtrue : Qfalse;
}


static VALUE
packet_in_ipv6_tcp( const buffer *frame ) {
  return ( packet_type_ipv6_tcp( frame ) ) ? Qtrue : Qfalse;
}


static VALUE
packet_in_tcp( const uint8_t ip_proto ) {
  return ( ip_proto == IPPROTO_TCP ) ? Qtrue : Qfalse;
}


static VALUE
packet_in_tcp_src( const buffer *frame ) {
  return UINT2NUM( get_packet_in_info( frame )->tcp_src_port );
}


static VALUE
packet_in_tcp_dst( const buffer *frame ) {
  return UINT2NUM( get_packet_in_info( frame )->tcp_dst_port );
}


static VALUE
packet_in_udp( const uint8_t ip_proto ) {
  return ( ip_proto == IPPROTO_UDP ) ? Qtrue : Qfalse;
}


static VALUE
packet_in_udp_src( const buffer *frame ) {
  return UINT2NUM( get_packet_in_info( frame )->udp_src_port );
}


static VALUE
packet_in_udp_dst( const buffer *frame ) {
  return UINT2NUM( get_packet_in_info( frame )->udp_dst_port );
}


static VALUE
packet_in_sctp( const uint8_t ip_proto ) {
  return ( ip_proto == IPPROTO_SCTP ) ? Qtrue : Qfalse;
}


static VALUE
packet_in_sctp_src( const buffer *frame ) {
  return UINT2NUM( get_packet_in_info( frame )->sctp_src_port );
}


static VALUE
packet_in_sctp_dst( const buffer *frame ) {
  return UINT2NUM( get_packet_in_info( frame )->sctp_dst_port );
}


static VALUE
packet_in_ipv6_udp( const buffer *frame ) {
  return ( packet_type_ipv6_udp( frame ) ) ? Qtrue : Qfalse;
}


static VALUE
packet_in_arp_request( const buffer *frame ) {
  return ( packet_type_arp_request( frame ) ) ? Qtrue : Qfalse;
}


static VALUE
packet_in_arp_reply( const buffer *frame ) {
  return ( packet_type_arp_reply( frame ) ) ? Qtrue : Qfalse;
}


static VALUE
packet_in_icmpv4_type( const buffer *frame ) {
  return UINT2NUM( get_packet_in_info( frame )->icmpv4_type );
}


static VALUE
packet_in_icmpv4_code( const buffer *frame ) {
  return UINT2NUM( get_packet_in_info( frame )->icmpv4_code );
}


static VALUE
packet_in_icmpv6_code( const buffer *frame ) {
  return UINT2NUM( get_packet_in_info( frame )->icmpv6_code );
}


static VALUE
packet_in_icmpv6_type( const buffer *frame ) {
  return UINT2NUM( get_packet_in_info( frame )->icmpv6_type );
}


static VALUE
packet_in_ipv6_nd_target( const buffer *frame, const uint16_t icmpv6_type ) {
  if ( ( icmpv6_type == 135 ) ||  ( icmpv6_type == 136 ) ) {
    PACKET_INFO_IPv6_ADDR( icmpv6_nd_target )
  }
  return Qnil;
}


static VALUE
packet_in_ipv6_nd_sll( const buffer *frame, const uint16_t icmpv6_type ) {
  if ( ( icmpv6_type == 135 ) ||  ( icmpv6_type == 136 ) ) {
    PACKET_INFO_MAC_ADDR( icmpv6_nd_sll )
  }
  return Qnil;
}


static VALUE
packet_in_ipv6_nd_tll( const buffer *frame, const uint16_t icmpv6_type ) {
  if ( ( icmpv6_type == 135 ) ||  ( icmpv6_type == 136 ) ) {
    PACKET_INFO_MAC_ADDR( icmpv6_nd_tll )
  }
  return Qnil;
}

  
static VALUE
packet_in_mpls_label( const buffer *frame ) {
  uint32_t mpls_label = get_packet_in_info( frame )->mpls_label;    
  return UINT2NUM( mpls_label >> 12 & 0xfffff );
}


static VALUE
packet_in_mpls_tc( const buffer *frame ) {
  uint32_t mpls_label = get_packet_in_info( frame )->mpls_label;    
  return UINT2NUM( mpls_label >> 9 & 0x7 ); 
}


static VALUE
packet_in_mpls_bos( const buffer *frame ) {
  uint32_t mpls_label = get_packet_in_info( frame )->mpls_label;    
  return UINT2NUM( mpls_label >> 8 & 0x1 ); 
}


static VALUE
packet_in_mpls( const uint16_t eth_type ) {
  return ( ( eth_type == ETH_ETHTYPE_MPLS_UNI ) || ( eth_type == ETH_ETHTYPE_MPLS_MLT ) ) ? Qtrue : Qfalse; 
}


static VALUE
packet_in_ipv6_exthdr( const buffer *frame ) {
  return UINT2NUM( get_packet_in_info( frame )->ipv6_exthdr );
} 


static VALUE
packet_in_pbb( const uint16_t eth_type ) {
 return ( eth_type == ETH_ETHTYPE_PBB ) ? Qtrue : Qfalse;
}


static VALUE
packet_in_pbb_isid( const buffer *frame ) {
  return UINT2NUM( get_packet_in_info( frame )->pbb_isid );
}


static VALUE
unpack_packet_in( packet_in *message ) {
  VALUE attributes = rb_hash_new();

  HASH_SET( attributes, "datapath_id", ULL2NUM( message->datapath_id ) );  
  HASH_SET( attributes, "transaction_id", UINT2NUM( message->transaction_id ) );
  HASH_SET( attributes, "buffer_id", UINT2NUM( message->buffer_id ) );
  HASH_SET( attributes, "total_len", UINT2NUM( message->total_len ) );
  HASH_SET( attributes, "reason", UINT2NUM( message->reason ) );
  HASH_SET( attributes, "table_id", UINT2NUM( message->table_id ) );
  HASH_SET( attributes, "cookie", ULL2NUM( message->cookie ) );
  HASH_SET( attributes, "match", packet_in_match( message ) );
  HASH_SET( attributes, "data", packet_in_data( message ) );

  // packet_info information
  VALUE pi_attributes = rb_hash_new();
  assert( message->data );
  HASH_SET( pi_attributes, "eth_src", packet_in_eth_src( message->data ) );
  HASH_SET( pi_attributes, "eth_dst", packet_in_eth_dst( message->data ) );

  VALUE r_eth_type = packet_in_eth_type( message->data );
  const uint16_t eth_type = ( const uint16_t ) NUM2UINT( r_eth_type );
  HASH_SET( pi_attributes, "eth_type", r_eth_type );

  bool ipv4 = packet_in_ipv4( message->data );
  VALUE r_ipv4 = ( ipv4 == true ) ? Qtrue : Qfalse;
  HASH_SET( pi_attributes, "ipv4", r_ipv4 );
  if ( r_ipv4 == Qtrue ) {
    HASH_SET( pi_attributes, "ipv4_src", packet_in_ipv4_src( message->data ) );
    HASH_SET( pi_attributes, "ipv4_dst", packet_in_ipv4_dst( message->data ) );
    HASH_SET( pi_attributes, "ipv4_tos", packet_in_ipv4_tos( message->data ) );
    HASH_SET( pi_attributes, "ipv4_tot_len", packet_in_ipv4_tot_len( message->data ) );
    HASH_SET( pi_attributes, "ipv4_id", packet_in_ipv4_id( message->data ) );
  }
  
  bool ipv6 = packet_in_ipv6( message->data );
  VALUE r_ipv6 = ( ipv6 == true ) ? Qtrue: Qfalse;
  HASH_SET( pi_attributes, "ipv6", r_ipv6 );

  HASH_SET( pi_attributes, "ip_dscp", packet_in_ip_dscp( message->data ) );
  HASH_SET( pi_attributes, "ip_ecn", packet_in_ip_ecn( message->data ) );
  VALUE r_ip_proto =  packet_in_ip_proto( message->data );

  VALUE r_vtag = packet_in_vtag( message->data );
  HASH_SET( pi_attributes, "vtag", r_vtag );
  if ( r_vtag == Qtrue ) {
    HASH_SET( pi_attributes, "vlan_vid", packet_in_vlan_vid( message->data ) );
    HASH_SET( pi_attributes, "vlan_prio", packet_in_vlan_pcp( message->data ) );
    HASH_SET( pi_attributes, "vlan_tci", packet_in_vlan_tci( message->data ) );
    HASH_SET( pi_attributes, "vlan_tpid", packet_in_vlan_tpid( message->data ) );
    HASH_SET( pi_attributes, "vlan_cfi", packet_in_vlan_cfi( message->data ) );
  }

  if ( r_ip_proto != Qnil ) {
    HASH_SET( pi_attributes, "ip_proto", r_ip_proto );
    const uint8_t ip_proto = ( const uint8_t ) NUM2UINT( r_ip_proto );

    VALUE r_tcp = packet_in_tcp( ip_proto );
    HASH_SET( pi_attributes, "tcp", r_tcp );
    if ( r_tcp == Qtrue ) {
      HASH_SET( pi_attributes, "tcp_src", packet_in_tcp_src( message->data ) );
      HASH_SET( pi_attributes, "tcp_dst", packet_in_tcp_dst( message->data ) );
    }

    VALUE r_udp = packet_in_udp( ip_proto );
    HASH_SET( pi_attributes, "udp", r_udp );
    if( r_udp == Qtrue ) {
      HASH_SET( pi_attributes, "udp_src", packet_in_udp_src( message->data ) );
      HASH_SET( pi_attributes, "udp_dst", packet_in_udp_dst( message->data ) );
    }

    VALUE r_sctp = packet_in_sctp( ip_proto );
    HASH_SET( pi_attributes, "sctp", r_sctp );
    if ( r_sctp == Qtrue ) {
      HASH_SET( pi_attributes, "sctp_src", packet_in_sctp_src( message->data ) );
     HASH_SET( pi_attributes, "sctp_dst", packet_in_sctp_dst( message->data ) );
    }

    VALUE r_icmpv4 = packet_in_icmpv4( ip_proto );
    HASH_SET( pi_attributes, "icmpv4", r_icmpv4 );
    if ( r_icmpv4 == Qtrue ) {
      HASH_SET( pi_attributes, "icmpv4_type", packet_in_icmpv4_type( message->data ) );
      HASH_SET( pi_attributes, "icmpv4_code", packet_in_icmpv4_code( message->data ) );
    }

    VALUE r_icmpv6 = packet_in_icmpv6( ip_proto );
    HASH_SET( pi_attributes, "icmpv6", r_icmpv6 );
    if ( r_icmpv6 == Qtrue ) {
      VALUE r_icmpv6_type = packet_in_icmpv6_type( message->data );
      const uint8_t icmpv6_type = ( const uint8_t ) NUM2UINT( r_icmpv6_type );
      HASH_SET( pi_attributes, "icmpv6_type", r_icmpv6_type );
      HASH_SET( pi_attributes, "icmpv6_code", packet_in_icmpv6_code( message->data ) );
      HASH_SET( pi_attributes, "ipv6_nd_target", packet_in_ipv6_nd_target( message->data, icmpv6_type ) );
      HASH_SET( pi_attributes, "ipv6_nd_sll", packet_in_ipv6_nd_sll( message->data, icmpv6_type ) );
      HASH_SET( pi_attributes, "ipv6_nd_tll", packet_in_ipv6_nd_tll( message->data, icmpv6_type ) );
    }
  }


  HASH_SET( pi_attributes, "ipv4_tcp", packet_in_ipv4_tcp( message->data ) );
  HASH_SET( pi_attributes, "ipv4_udp", packet_in_ipv4_udp( message->data ) );
  HASH_SET( pi_attributes, "ipv6_tcp", packet_in_ipv6_tcp( message->data ) );
  HASH_SET( pi_attributes, "ipv6_udp", packet_in_ipv6_udp( message->data ) );

  VALUE r_arp = packet_in_arp( message->data );
  HASH_SET( pi_attributes, "arp", r_arp );
  if ( r_arp == Qtrue ) {
    HASH_SET( pi_attributes, "arp_request", packet_in_arp_request( message->data ) );
    HASH_SET( pi_attributes, "arp_reply", packet_in_arp_reply( message->data ) );
    HASH_SET( pi_attributes, "arp_op", packet_in_arp_op( message->data ) );
    HASH_SET( pi_attributes, "arp_sha", packet_in_arp_sha( message->data ) );
    HASH_SET( pi_attributes, "arp_spa", packet_in_arp_spa( message->data ) );
    HASH_SET( pi_attributes, "arp_tha", packet_in_arp_tha( message->data ) );
    HASH_SET( pi_attributes, "arp_tpa", packet_in_arp_tpa( message->data ) );
  }




  if ( r_ipv6 == Qtrue ) {
    HASH_SET( pi_attributes, "ipv6_src", packet_in_ipv6_src( message->data ) );
    HASH_SET( pi_attributes, "ipv6_dst", packet_in_ipv6_dst( message->data ) );
    HASH_SET( pi_attributes, "ipv6_flabel", packet_in_ipv6_flabel( message->data ) );
    HASH_SET( pi_attributes, "ipv6_exthdr", packet_in_ipv6_exthdr( message->data ) );
  }

  HASH_SET( pi_attributes, "igmp", packet_in_igmp( message->data ) );
  
  VALUE r_mpls = packet_in_mpls( eth_type );
  HASH_SET( pi_attributes, "mpls", r_mpls );
  if ( r_mpls == Qtrue ) {
    HASH_SET( pi_attributes, "mpls_label", packet_in_mpls_label( message->data ) );
    HASH_SET( pi_attributes, "mpls_tc", packet_in_mpls_tc( message->data ) );
    HASH_SET( pi_attributes, "mpls_bos", packet_in_mpls_bos( message->data ) );
  }
  VALUE r_pbb = packet_in_pbb( eth_type );
  HASH_SET( pi_attributes, "pbb", r_pbb );
  if ( r_pbb == Qtrue ) { 
    HASH_SET( pi_attributes, "pbb_isid", packet_in_pbb_isid( message->data ) );
  }

  VALUE cPacketInfo = rb_funcall( rb_eval_string( "Messages::PacketInfo" ), rb_intern( "new" ), 1, pi_attributes );
  HASH_SET( attributes, "packet_info", cPacketInfo );
  VALUE str = rb_inspect( attributes );
  debug( "attributes  %s", StringValuePtr( str ) );

  return rb_funcall( rb_eval_string( "Messages::PacketIn" ), rb_intern( "new" ), 1, attributes );
}


/*
 * Handler called when +OFPT_PACKET_IN+ message is received.
 */
void
handle_packet_in( uint64_t datapath_id, packet_in message ) {
  VALUE controller = ( VALUE ) message.user_data;
  if ( !rb_respond_to( controller, rb_intern( "packet_in" ) ) ) {
    return;
  }

  VALUE cPacketIn = unpack_packet_in( &message );
  rb_funcall( controller, rb_intern( "packet_in" ), 2, ULL2NUM( datapath_id ), cPacketIn );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
