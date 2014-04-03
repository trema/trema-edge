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


#include <arpa/inet.h>
#include "trema.h"
#include "ruby.h"
#include "action-common.h"
#include "hash-util.h"


extern VALUE mActions;
static VALUE basic_action_eval;
static VALUE flexible_action_eval;


static openflow_actions *
openflow_actions_ptr( VALUE self ) {
  openflow_actions *actions;
  Data_Get_Struct( self, openflow_actions, actions );
  return actions;
}


static oxm_matches *
oxm_match_ptr( VALUE self ) {
  oxm_matches *match;
  Data_Get_Struct( self, oxm_matches, match );
  return match;
}


static uint32_t
ip_addr_to_i( VALUE ip_addr ) {
  return nw_addr_to_i( ip_addr );
}


static VALUE
pack_in_port( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_in_port = HASH_REF( options, in_port );
  if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_in_port( oxm_match_ptr( actions ), NUM2UINT( r_in_port ) );
  }

  return self;
}


static VALUE
pack_in_phy_port( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_in_phy_port = HASH_REF( options, in_phy_port );
  if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_in_phy_port( oxm_match_ptr( actions ), NUM2UINT( r_in_phy_port ) );
  }

  return self;
}


static VALUE
pack_metadata( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_metadata = HASH_REF( options, metadata );
  if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_metadata( oxm_match_ptr( actions ), rb_num2ull( r_metadata ), UINT64_MAX );
  }

  return self;
}


static VALUE
pack_eth_dst( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_mac_address = HASH_REF( options, mac_address );
  uint8_t *dl_addr = ( uint8_t * ) xmalloc( sizeof( uint8_t ) * OFP_ETH_ALEN );

  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_eth_dst( openflow_actions_ptr( actions ), dl_addr_to_a( r_mac_address, dl_addr ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    uint8_t eth_dst_mask[ OFP_ETH_ALEN ] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    append_oxm_match_eth_dst( oxm_match_ptr( actions ), dl_addr_to_a( r_mac_address, dl_addr ), eth_dst_mask );
  }
  xfree( dl_addr );

  return self;
}


static VALUE
pack_eth_src( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_mac_address = HASH_REF( options, mac_address );
  uint8_t *dl_addr = ( uint8_t * ) xmalloc( sizeof( uint8_t ) * OFP_ETH_ALEN );

  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_eth_src( openflow_actions_ptr( actions ), dl_addr_to_a( r_mac_address, dl_addr ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    uint8_t eth_src_mask[ OFP_ETH_ALEN ] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    append_oxm_match_eth_src( oxm_match_ptr( actions ), dl_addr_to_a( r_mac_address, dl_addr ), eth_src_mask );
  }
  xfree( dl_addr );

  return self;
}


static VALUE
pack_ether_type( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_ether_type = HASH_REF( options, ether_type );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_eth_type( openflow_actions_ptr( actions ), ( const uint16_t ) NUM2UINT( r_ether_type ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_eth_type( oxm_match_ptr( actions ), ( uint16_t ) NUM2UINT( r_ether_type ) );
  }

  return self;
}


static VALUE
pack_vlan_vid( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_vlan_vid = HASH_REF( options, vlan_vid );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_vlan_vid( openflow_actions_ptr( actions ), ( const uint16_t ) NUM2UINT( r_vlan_vid ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_vlan_vid( oxm_match_ptr( actions ), ( const uint16_t ) NUM2UINT( r_vlan_vid ), UINT16_MAX );
  }

  return self;
}


static VALUE
pack_vlan_priority( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_vlan_priority = HASH_REF( options, vlan_priority );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_vlan_pcp( openflow_actions_ptr( actions ), ( const uint8_t ) NUM2UINT( r_vlan_priority ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_vlan_pcp( oxm_match_ptr( actions ), ( uint8_t ) NUM2UINT( r_vlan_priority ) );
  }

  return self;
}


static VALUE
pack_ip_dscp( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_ip_dscp = HASH_REF( options, ip_dscp );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_ip_dscp( openflow_actions_ptr( actions ), ( const uint8_t ) NUM2UINT( r_ip_dscp ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_ip_dscp( oxm_match_ptr( actions ), ( uint8_t ) r_ip_dscp );
  }

  return self;
}


static VALUE
pack_ip_ecn( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_ip_ecn = HASH_REF( options, ip_ecn );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_ip_ecn( openflow_actions_ptr( actions ), ( const uint8_t ) NUM2UINT( r_ip_ecn ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_ip_ecn( oxm_match_ptr( actions ), ( uint8_t ) NUM2UINT( r_ip_ecn ) );
  }

  return self;
}


static VALUE
pack_ip_proto( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_ip_proto = HASH_REF( options, ip_proto );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_ip_proto( openflow_actions_ptr( actions ), ( const uint8_t ) NUM2UINT( r_ip_proto ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_ip_proto( oxm_match_ptr( actions ), ( uint8_t ) NUM2UINT( r_ip_proto ) );
  }

  return self;
}


static VALUE
pack_ipv4_src_addr( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_ip_addr = HASH_REF( options, ip_addr );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_ipv4_src( openflow_actions_ptr( actions ), ip_addr_to_i( r_ip_addr ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_ipv4_src( oxm_match_ptr( actions ), ip_addr_to_i( r_ip_addr ), UINT32_MAX ); 
  }

  return self;
}


static VALUE
pack_ipv4_dst_addr( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_ip_addr = HASH_REF( options, ip_addr ); 
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_ipv4_dst( openflow_actions_ptr( actions ), ip_addr_to_i( r_ip_addr ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_ipv4_dst( oxm_match_ptr( actions ), ip_addr_to_i( r_ip_addr ), UINT32_MAX );
  }

  return self;
}


static VALUE
pack_tcp_src_port( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_transport_port = HASH_REF( options, transport_port );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_tcp_src( openflow_actions_ptr( actions ), ( const uint16_t ) NUM2UINT( r_transport_port ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_tcp_src( oxm_match_ptr( actions ), ( uint16_t ) NUM2UINT( r_transport_port ) );
  }

  return self;
}


static VALUE
pack_tcp_dst_port( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_transport_port = HASH_REF( options, transport_port );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_tcp_dst( openflow_actions_ptr( actions ), ( const uint16_t ) NUM2UINT( r_transport_port ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_tcp_dst( oxm_match_ptr( actions ), ( uint16_t ) NUM2UINT( r_transport_port ) );
  }

  return self;
}


static VALUE
pack_udp_src_port( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_transport_port = HASH_REF( options, transport_port );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_udp_src( openflow_actions_ptr( actions ), ( const uint16_t ) NUM2UINT( r_transport_port ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_udp_src( oxm_match_ptr( actions ), ( uint16_t ) NUM2UINT( r_transport_port ) );
  }

  return self;
}


static VALUE
pack_udp_dst_port( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_transport_port = HASH_REF( options, transport_port );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_udp_dst( openflow_actions_ptr( actions ), ( const uint16_t ) NUM2UINT( r_transport_port ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_udp_dst( oxm_match_ptr( actions ), ( uint16_t ) NUM2UINT( r_transport_port ) );
  }

  return self;
}


static VALUE
pack_sctp_src_port( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_transport_port = HASH_REF( options, transport_port );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_sctp_src( openflow_actions_ptr( actions ), ( const uint16_t ) NUM2UINT( r_transport_port ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_sctp_src( oxm_match_ptr( actions ), ( uint16_t ) NUM2UINT( r_transport_port ) ); 
  }

  return self;
}


static VALUE
pack_sctp_dst_port( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_transport_port = HASH_REF( options, transport_port );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_sctp_dst( openflow_actions_ptr( actions ), ( const uint16_t ) NUM2UINT( r_transport_port ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_sctp_dst( oxm_match_ptr( actions ), ( uint16_t ) NUM2UINT( r_transport_port ) ); 
  }

  return self;
}


static VALUE
pack_icmpv4_type( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_icmpv4_type = HASH_REF( options, icmpv4_type );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_icmpv4_type( openflow_actions_ptr( actions ), ( const uint8_t ) NUM2UINT( r_icmpv4_type ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_icmpv4_type( oxm_match_ptr( actions ), ( uint8_t ) NUM2UINT( r_icmpv4_type ) );
  }

  return self;
}


static VALUE
pack_icmpv4_code( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_icmpv4_code = HASH_REF( options, icmpv4_code );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_icmpv4_code( openflow_actions_ptr( actions ), ( const uint8_t ) NUM2UINT( r_icmpv4_code ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_icmpv4_code( oxm_match_ptr( actions ), ( uint8_t ) NUM2UINT( r_icmpv4_code ) );
  }

  return self;
}


static VALUE
pack_arp_op( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_arp_op = HASH_REF( options, arp_opcode );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_arp_op( openflow_actions_ptr( actions ), ( const uint16_t ) NUM2UINT( r_arp_op ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_arp_op( oxm_match_ptr( actions ), ( uint16_t ) NUM2UINT( r_arp_op ) );
  }

  return self;
}


static VALUE
pack_arp_spa( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_ip_addr = HASH_REF( options, ip_addr );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_arp_spa( openflow_actions_ptr( actions ), ip_addr_to_i( r_ip_addr ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_arp_spa( oxm_match_ptr( actions ), ip_addr_to_i( r_ip_addr ), UINT32_MAX );
  }

  return self;
}


static VALUE
pack_arp_tpa( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_ip_addr = HASH_REF( options, ip_addr );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_arp_tpa( openflow_actions_ptr( actions ), ip_addr_to_i( r_ip_addr ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_arp_tpa( oxm_match_ptr( actions ), ip_addr_to_i( r_ip_addr ), UINT32_MAX );
  }

  return self;
}


static VALUE
pack_arp_sha( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_mac_address = HASH_REF( options, mac_address );
  uint8_t *dl_addr = ( uint8_t * ) xmalloc( sizeof( uint8_t ) * OFP_ETH_ALEN );

  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_arp_sha( openflow_actions_ptr( actions ), dl_addr_to_a( r_mac_address, dl_addr ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    uint8_t mask[ OFP_ETH_ALEN ] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    append_oxm_match_arp_sha( oxm_match_ptr( actions ), dl_addr_to_a( r_mac_address, dl_addr ), mask );
  }
  xfree( dl_addr );

  return self;
}


static VALUE
pack_arp_tha( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_mac_address = HASH_REF( options, mac_address );
  uint8_t *dl_addr = ( uint8_t * ) xmalloc( sizeof( uint8_t ) * OFP_ETH_ALEN );

  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_arp_tha( openflow_actions_ptr( actions ), dl_addr_to_a( r_mac_address, dl_addr ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    uint8_t mask[ OFP_ETH_ALEN ] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    append_oxm_match_arp_tha( oxm_match_ptr( actions ), dl_addr_to_a( r_mac_address, dl_addr ), mask );
  }
  xfree( dl_addr );

  return self;
}


static VALUE
pack_ipv6_src_addr( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_ip_addr = HASH_REF( options, ip_addr ); 
  struct in6_addr *in6_addr = ( struct in6_addr * ) xmalloc( sizeof( struct in6_addr ) );

  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_ipv6_src( openflow_actions_ptr( actions ), ipv6_addr_to_in6_addr( r_ip_addr, in6_addr ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    struct in6_addr in6_mask;
    memset( &in6_mask, 0xff, sizeof( struct in6_addr ) );
    append_oxm_match_ipv6_src( oxm_match_ptr( actions ), ipv6_addr_to_in6_addr( r_ip_addr, in6_addr ), in6_mask );
  }
  xfree( in6_addr );

  return self;
}


static VALUE
pack_ipv6_dst_addr( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_ip_addr = HASH_REF( options, ip_addr ); 
  struct in6_addr *in6_addr = ( struct in6_addr * ) xmalloc( sizeof( struct in6_addr ) );

  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_ipv6_dst( openflow_actions_ptr( actions ), ipv6_addr_to_in6_addr( r_ip_addr, in6_addr ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    struct in6_addr in6_mask;
    memset( &in6_mask, 0xff, sizeof( struct in6_addr ) );
    append_oxm_match_ipv6_dst( oxm_match_ptr( actions ), ipv6_addr_to_in6_addr( r_ip_addr, in6_addr ), in6_mask );
  }
  xfree( in6_addr );

  return self;
}


static VALUE
pack_ipv6_flow_label( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_ipv6_flow_label = HASH_REF( options, ipv6_flow_label );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_ipv6_flabel( openflow_actions_ptr( actions ), NUM2UINT( r_ipv6_flow_label ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_ipv6_flabel( oxm_match_ptr( actions ), NUM2UINT( r_ipv6_flow_label ), UINT32_MAX );
  }

  return self;
}


static VALUE
pack_icmpv6_type( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_icmpv6_type = HASH_REF( options, icmpv6_type );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_icmpv6_type( openflow_actions_ptr( actions ), ( const uint8_t ) NUM2UINT( r_icmpv6_type ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_icmpv6_type( oxm_match_ptr( actions ), ( uint8_t ) NUM2UINT( r_icmpv6_type ) );
  }

  return self;
}


static VALUE
pack_icmpv6_code( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_icmpv6_code = HASH_REF( options, icmpv6_code );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_icmpv6_code( openflow_actions_ptr( actions ), ( const uint8_t ) NUM2UINT( r_icmpv6_code ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_icmpv6_code( oxm_match_ptr( actions ), ( uint8_t ) NUM2UINT( r_icmpv6_code ) );
  }

  return self;
}


static VALUE
pack_ipv6_nd_target( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_ip_addr = HASH_REF( options, ip_addr );
  struct in6_addr *in6_addr = ( struct in6_addr * ) xmalloc( sizeof( struct in6_addr ) );

  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_ipv6_nd_target( openflow_actions_ptr( actions ), ipv6_addr_to_in6_addr( r_ip_addr, in6_addr ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_ipv6_nd_target( oxm_match_ptr( actions ), ipv6_addr_to_in6_addr( r_ip_addr, in6_addr ) );
  }
  xfree( in6_addr );

  return self;
}


static VALUE
pack_ipv6_nd_sll( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_mac_address = HASH_REF( options, mac_address );
  uint8_t *dl_addr = ( uint8_t * ) xmalloc( sizeof( uint8_t ) * OFP_ETH_ALEN );

  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_ipv6_nd_sll( openflow_actions_ptr( actions ), dl_addr_to_a( r_mac_address, dl_addr ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_ipv6_nd_sll( oxm_match_ptr( actions ), dl_addr_to_a( r_mac_address, dl_addr ) );
  }
  xfree( dl_addr );

  return self;
}


static VALUE
pack_ipv6_nd_tll( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_mac_address = HASH_REF( options, mac_address );
  uint8_t *dl_addr = ( uint8_t * ) xmalloc( sizeof( uint8_t ) * OFP_ETH_ALEN );

  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_ipv6_nd_tll( openflow_actions_ptr( actions ), dl_addr_to_a( r_mac_address, dl_addr ) );

  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_ipv6_nd_tll( oxm_match_ptr( actions ), dl_addr_to_a( r_mac_address, dl_addr ) );
  }
  xfree( dl_addr );

  return self;
}


static VALUE
pack_mpls_label( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_mpls_label = HASH_REF( options, mpls_label );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_mpls_label( openflow_actions_ptr( actions ), ( const uint32_t ) NUM2UINT( r_mpls_label ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_mpls_label( oxm_match_ptr( actions ), NUM2UINT( r_mpls_label ) );
  }

  return self;
}


static VALUE
pack_mpls_tc( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_mpls_tc = HASH_REF( options, mpls_tc );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_mpls_tc( openflow_actions_ptr( actions ), ( const uint8_t ) NUM2UINT( r_mpls_tc ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_mpls_tc( oxm_match_ptr( actions ), ( uint8_t ) NUM2UINT( r_mpls_tc ) );
  }

  return self;
}


static VALUE
pack_mpls_bos( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_mpls_bos = HASH_REF( options, mpls_bos );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_mpls_bos( openflow_actions_ptr( actions ), ( const uint8_t ) NUM2UINT( r_mpls_bos ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_mpls_bos( oxm_match_ptr( actions ), ( uint8_t ) NUM2UINT( r_mpls_bos ) );
  }

  return self;
}


static VALUE
pack_pbb_isid( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_pbb_isid = HASH_REF( options, pbb_isid );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_pbb_isid( openflow_actions_ptr( actions ), ( const uint32_t ) NUM2UINT( r_pbb_isid ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_pbb_isid( oxm_match_ptr( actions ), NUM2UINT( r_pbb_isid ), UINT32_MAX );
  }

  return self;
}


static VALUE
pack_tunnel_id( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_tunnel_id = HASH_REF( options, tunnel_id );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_tunnel_id( openflow_actions_ptr( actions ), ( const uint64_t ) rb_num2ull( r_tunnel_id ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_tunnel_id( oxm_match_ptr( actions ), ( uint64_t ) rb_num2ull( r_tunnel_id ), UINT64_MAX );
  }

  return self;
}


static VALUE
pack_ipv6_exthdr( VALUE self, VALUE actions, VALUE options ) {
  VALUE r_ipv6_exthdr = HASH_REF( options, ipv6_exthdr );
  if ( rb_obj_is_kind_of( actions, basic_action_eval ) ) {
    append_action_set_field_ipv6_exthdr( openflow_actions_ptr( actions ), ( const uint16_t ) NUM2UINT( r_ipv6_exthdr ) );
  }
  else if ( rb_obj_is_kind_of( actions, flexible_action_eval ) ) {
    append_oxm_match_ipv6_exthdr( oxm_match_ptr( actions ), ( uint16_t ) NUM2UINT( r_ipv6_exthdr ), UINT16_MAX );
  }

  return self;
}


void
Init_flexible_action( void ) {
  basic_action_eval = rb_eval_string( "Trema::BasicAction" );
  rb_define_module_function( mActions, "pack_in_port", pack_in_port, 2 );
  rb_define_module_function( mActions, "pack_in_phy_port", pack_in_phy_port, 2 );
  rb_define_module_function( mActions, "pack_metadata", pack_metadata, 2 );
  rb_define_module_function( mActions, "pack_eth_dst", pack_eth_dst, 2 );
  rb_define_module_function( mActions, "pack_eth_src", pack_eth_src, 2 );
  rb_define_module_function( mActions, "pack_ether_type", pack_ether_type, 2 );
  rb_define_module_function( mActions, "pack_vlan_vid", pack_vlan_vid, 2 );
  rb_define_module_function( mActions, "pack_vlan_priority", pack_vlan_priority, 2 );
  rb_define_module_function( mActions, "pack_ip_dscp", pack_ip_dscp, 2 );
  rb_define_module_function( mActions, "pack_ip_ecn", pack_ip_ecn, 2 );
  rb_define_module_function( mActions, "pack_ip_proto", pack_ip_proto, 2 );
  rb_define_module_function( mActions, "pack_ipv4_src_addr", pack_ipv4_src_addr, 2 );
  rb_define_module_function( mActions, "pack_ipv4_dst_addr", pack_ipv4_dst_addr, 2 );
  rb_define_module_function( mActions, "pack_tcp_src_port", pack_tcp_src_port, 2 );
  rb_define_module_function( mActions, "pack_tcp_dst_port", pack_tcp_dst_port, 2 );
  rb_define_module_function( mActions, "pack_udp_src_port", pack_udp_src_port, 2 );
  rb_define_module_function( mActions, "pack_udp_dst_port", pack_udp_dst_port, 2 );
  rb_define_module_function( mActions, "pack_sctp_src_port", pack_sctp_src_port, 2 );
  rb_define_module_function( mActions, "pack_sctp_dst_port", pack_sctp_dst_port, 2 );
  rb_define_module_function( mActions, "pack_icmpv4_type", pack_icmpv4_type, 2 );
  rb_define_module_function( mActions, "pack_icmpv4_code", pack_icmpv4_code, 2 );
  rb_define_module_function( mActions, "pack_arp_op", pack_arp_op, 2 );
  rb_define_module_function( mActions, "pack_arp_spa", pack_arp_spa, 2 );
  rb_define_module_function( mActions, "pack_arp_tpa", pack_arp_tpa, 2 );
  rb_define_module_function( mActions, "pack_arp_sha", pack_arp_sha, 2 );
  rb_define_module_function( mActions, "pack_arp_tha", pack_arp_tha, 2 );
  rb_define_module_function( mActions, "pack_ipv6_src_addr", pack_ipv6_src_addr, 2 );
  rb_define_module_function( mActions, "pack_ipv6_dst_addr", pack_ipv6_dst_addr, 2 );
  rb_define_module_function( mActions, "pack_ipv6_flow_label", pack_ipv6_flow_label, 2 );
  rb_define_module_function( mActions, "pack_icmpv6_type", pack_icmpv6_type, 2 );
  rb_define_module_function( mActions, "pack_icmpv6_code", pack_icmpv6_code, 2 );
  rb_define_module_function( mActions, "pack_ipv6_nd_target", pack_ipv6_nd_target, 2 );
  rb_define_module_function( mActions, "pack_ipv6_nd_sll", pack_ipv6_nd_sll, 2 );
  rb_define_module_function( mActions, "pack_ipv6_nd_tll", pack_ipv6_nd_tll, 2 );
  rb_define_module_function( mActions, "pack_mpls_label", pack_mpls_label, 2 );
  rb_define_module_function( mActions, "pack_mpls_tc", pack_mpls_tc, 2 );
  rb_define_module_function( mActions, "pack_mpls_bos", pack_mpls_bos, 2 );
  rb_define_module_function( mActions, "pack_pbb_isid", pack_pbb_isid, 2 );
  rb_define_module_function( mActions, "pack_tunnel_id", pack_tunnel_id, 2 );
  rb_define_module_function( mActions, "pack_ipv6_exthdr", pack_ipv6_exthdr, 2 );
  rb_require( "trema/flexible-action" );
  flexible_action_eval = rb_eval_string( "Trema::FlexibleAction" );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
