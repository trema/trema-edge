/*
 * Unit tests for utility functions.
 * 
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


#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "cmockery_trema.h"
#include "log.h"
#include "ipv4.h"
#include "trema_wrapper.h"
#include "utility.h"
#include "oxm_match.h"
#include "openflow_message.h"
#include "wrapper.h"


/********************************************************************************
 * Setup and teardown
 ********************************************************************************/

static void ( *original_critical )( const char *format, ... );

static void
mock_critical( const char *format, ... ) {
  char output[ 256 ];
  va_list args;
  va_start( args, format );
  vsprintf( output, format, args );
  va_end( args );
  check_expected( output );
}


static void ( *original_abort )( void );

static void
stub_abort() {
  // Do nothing.
}


static void
setup() {
  original_critical = critical;
  critical = mock_critical;

  original_abort = abort;
  trema_abort = stub_abort;
}


static void
teardown() {
  critical = original_critical;
  trema_abort = original_abort;
}


/********************************************************************************
 * Tests.
 ********************************************************************************/

static void
test_die() {
  expect_string( mock_critical, output, "Bye!" );
  die( "Bye!" );
}


static void
test_hash_core() {
  unsigned char bin1[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
  unsigned char bin2[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

  assert_true( hash_core( bin1, sizeof( bin1 ) ) == hash_core( bin2, sizeof( bin2 ) ) );
}


static void
test_compare_string() {
  char hello1[] = "Hello World";
  char hello2[] = "Hello World";
  char bye[] = "Bye World";

  assert_true( compare_string( hello1, hello2 ) );
  assert_false( compare_string( hello1, bye ) );
}


static void
test_hash_string() {
  char hello1[] = "Hello World";
  char hello2[] = "Hello World";

  assert_true( hash_string( hello1 ) == hash_string( hello2 ) );
}


static void
test_compare_uint32() {
  uint32_t x = 123;
  uint32_t y = 123;
  uint32_t z = 321;

  assert_true( compare_uint32( ( void * ) &x, ( void * ) &y ) );
  assert_false( compare_uint32( ( void * ) &x, ( void * ) &z ) );
}


static void
test_hash_uint32() {
  uint32_t key = 123;

  assert_int_equal( 123, hash_uint32( ( void * ) &key ) );
}


static void
test_compare_datapath_id() {
  uint64_t x = 123;
  uint64_t y = 123;
  uint64_t z = 321;

  assert_true( compare_datapath_id( ( void * ) &x, ( void * ) &y ) );
  assert_false( compare_datapath_id( ( void * ) &x, ( void * ) &z ) );
}


static void
test_hash_datapath_id() {
  uint64_t x = 123;
  uint64_t y = 123;
  uint64_t z = 321;

  assert_true( hash_datapath_id( ( void * ) &x ) == hash_datapath_id( ( void * ) &y ) );
  assert_true( hash_datapath_id( ( void * ) &x ) != hash_datapath_id( ( void * ) &z ) );
}


static void
test_compare_mac() {
  uint8_t mac1[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  uint8_t mac2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  assert_true( compare_mac( mac1, mac1 ) );
  assert_false( compare_mac( mac1, mac2 ) );
}


static void
test_hash_mac() {
  uint8_t mac1[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  uint8_t mac2[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

  assert_true( hash_mac( mac1 ) == hash_mac( mac2 ) );
}


static void
test_mac_to_uint64() {
  uint8_t mac1[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  uint8_t mac2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  assert_true( mac_to_uint64( mac1 ) == 281474976710655ULL );
  assert_true( mac_to_uint64( mac2 ) == 0 );
}


static void
test_string_to_datapath_id() {
  uint64_t datapath_id;
  uint64_t expected_datapath_id = 18446744073709551615ULL;

  assert_true( string_to_datapath_id( "18446744073709551615", &datapath_id ) );
  assert_memory_equal( &datapath_id, &expected_datapath_id, sizeof( uint64_t ) );

  assert_false( string_to_datapath_id( "INVALID DATAPATH ID", &datapath_id ) );
}


static void
test_match_to_string() {
  char match_str[ MATCH_STRING_LENGTH ];

  {
    char expected_match_str[] = "all";
    oxm_matches *match = NULL;
    assert_true( match_to_string( match, match_str, sizeof( match_str ) ) );
    assert_string_equal( match_str, expected_match_str );
    match = create_oxm_matches();
    assert_true( match_to_string( match, match_str, sizeof( match_str ) ) );
    assert_string_equal( match_str, expected_match_str );
    delete_oxm_matches( match );
  }

  {
    char expected_match_str[] = 
      "in_port = 1, in_phy_port = 2, metadata = 0x0102030405060708, "
      "metadata = 0x0102030405060708/0xffffffff00000000, "
      "eth_dst = 01:02:03:04:05:06, eth_dst = 01:02:03:04:05:06/ff:ff:ff:00:00:00, "
      "eth_src = 01:02:03:04:05:06, eth_src = 01:02:03:04:05:06/ff:ff:ff:00:00:00, "
      "eth_type = 0x0800, vlan_vid = 0x0fa0, vlan_vid = 0x0fa0/0xff00, vlan_pcp = 0x03, "
      "ip_dscp = 0x04, ip_ecn = 0x05, ip_proto = 0x06, "
      "ipv4_src = 1.2.3.4, ipv4_src = 1.2.3.4/255.255.0.0, "
      "ipv4_dst = 1.2.3.4, ipv4_dst = 1.2.3.4/255.255.0.0, "
      "tcp_src = 1000, tcp_dst = 2000, udp_src = 3000, udp_dst = 4000, sctp_src = 5000, sctp_dst = 6000, "
      "icmpv4_type = 0x07, icmpv4_code = 0x08, arp_opcode = 0x0102, "
      "arp_spa = 1.2.3.4, arp_spa = 1.2.3.4/255.255.0.0, "
      "arp_tpa = 1.2.3.4, arp_tpa = 1.2.3.4/255.255.0.0, "
      "arp_sha = 01:02:03:04:05:06, arp_sha = 01:02:03:04:05:06/ff:ff:ff:00:00:00, "
      "arp_tha = 01:02:03:04:05:06, arp_tha = 01:02:03:04:05:06/ff:ff:ff:00:00:00, "
      "ipv6_src = 102:304:506:708:90a:b0c:d0e:f00, ipv6_src = 102:304:506:708:90a:b0c:d0e:f00/ffff:ffff:ffff:ffff::, "
      "ipv6_dst = 102:304:506:708:90a:b0c:d0e:f00, ipv6_dst = 102:304:506:708:90a:b0c:d0e:f00/ffff:ffff:ffff:ffff::, "
      "ipv6_flabel = 0x01020304, ipv6_flabel = 0x01020304/0xffff0000, icmpv6_type = 0x09, icmpv6_code = 0x0a, "
      "ipv6_nd_target = 102:304:506:708:90a:b0c:d0e:f00, ipv6_nd_sll = 01:02:03:04:05:06, ipv6_nd_tll = 01:02:03:04:05:06, "
      "mpls_label = 0x01020304, mpls_tc = 0x01, mpls_bos = 0x02, pbb_isid = 0x01020304, pbb_isid = 0x01020304/0xffff0000, "
      "tunnel_id = 0x0102030405060708, tunnel_id = 0x0102030405060708/0xffffffff00000000, "
      "ipv6_exthdr = 0x0102, ipv6_exthdr = 0x0102/0xff00";

    const uint16_t data_16bit = 0x0102;
    const uint32_t data_32bit = 0x01020304;
    const uint8_t data_48bit[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    const uint64_t data_64bit = 0x0102030405060708;
    const struct in6_addr data_128bit = { { { 0x01, 0x02, 0x03, 0x04,
                                              0x05, 0x06, 0x07, 0x08,
                                              0x09, 0x0a, 0x0b, 0x0c,
                                              0x0d, 0x0e, 0x0f, 0x00 } } };

    const uint16_t mask_16bit = 0xff00;
    const uint32_t mask_32bit = 0xffff0000;
    const uint8_t mask_48bit[6] = { 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 };
    const uint64_t mask_64bit = 0xffffffff00000000;
    const struct in6_addr mask_128bit = { { { 0xff, 0xff, 0xff, 0xff,
                                              0xff, 0xff, 0xff, 0xff,
                                              0x00, 0x00, 0x00, 0x00,
                                              0x00, 0x00, 0x00, 0x00 } } };

    const uint16_t nomask_16bit = 0x0000;
    const uint32_t nomask_32bit = 0x00000000;
    const uint8_t nomask_48bit[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const uint64_t nomask_64bit = 0x0000000000000000;
    const struct in6_addr nomask_128bit = { { { 0x00, 0x00, 0x00, 0x00,
                                              0x00, 0x00, 0x00, 0x00,
                                              0x00, 0x00, 0x00, 0x00,
                                              0x00, 0x00, 0x00, 0x00 } } };

    uint8_t d_48bit[ OFP_ETH_ALEN ];
    uint8_t m_48bit[ OFP_ETH_ALEN ];
    uint8_t nm_48bit[ OFP_ETH_ALEN ];

    memcpy( d_48bit, data_48bit, sizeof( d_48bit ) );
    memcpy( m_48bit, mask_48bit, sizeof( m_48bit ) );
    memcpy( nm_48bit, nomask_48bit, sizeof( m_48bit ) );

    oxm_matches *match = create_oxm_matches();
    append_oxm_match_in_port( match, 1 );
    append_oxm_match_in_phy_port( match, 2 );
    append_oxm_match_metadata( match, data_64bit, nomask_64bit );
    append_oxm_match_metadata( match, data_64bit, mask_64bit );
    append_oxm_match_eth_dst( match, d_48bit, nm_48bit );
    append_oxm_match_eth_dst( match, d_48bit, m_48bit );
    append_oxm_match_eth_src( match, d_48bit, nm_48bit );
    append_oxm_match_eth_src( match, d_48bit, m_48bit );
    append_oxm_match_eth_type( match, 0x0800 );
    append_oxm_match_vlan_vid( match, 4000, nomask_16bit );
    append_oxm_match_vlan_vid( match, 4000, mask_16bit );
    append_oxm_match_vlan_pcp( match, 3 );
    append_oxm_match_ip_dscp( match, 4 );
    append_oxm_match_ip_ecn( match, 5 );
    append_oxm_match_ip_proto( match, 6 );
    append_oxm_match_ipv4_src( match, data_32bit, nomask_32bit );
    append_oxm_match_ipv4_src( match, data_32bit, mask_32bit );
    append_oxm_match_ipv4_dst( match, data_32bit, nomask_32bit );
    append_oxm_match_ipv4_dst( match, data_32bit, mask_32bit );
    append_oxm_match_tcp_src( match, 1000 );
    append_oxm_match_tcp_dst( match, 2000 );
    append_oxm_match_udp_src( match, 3000 );
    append_oxm_match_udp_dst( match, 4000 );
    append_oxm_match_sctp_src( match, 5000 );
    append_oxm_match_sctp_dst( match, 6000 );
    append_oxm_match_icmpv4_type( match, 7 );
    append_oxm_match_icmpv4_code( match, 8 );
    append_oxm_match_arp_op( match, data_16bit );
    append_oxm_match_arp_spa( match, data_32bit, nomask_32bit );
    append_oxm_match_arp_spa( match, data_32bit, mask_32bit );
    append_oxm_match_arp_tpa( match, data_32bit, nomask_32bit );
    append_oxm_match_arp_tpa( match, data_32bit, mask_32bit );
    append_oxm_match_arp_sha( match, d_48bit, nm_48bit );
    append_oxm_match_arp_sha( match, d_48bit, m_48bit );
    append_oxm_match_arp_tha( match, d_48bit, nm_48bit );
    append_oxm_match_arp_tha( match, d_48bit, m_48bit );
    append_oxm_match_ipv6_src( match, data_128bit, nomask_128bit );
    append_oxm_match_ipv6_src( match, data_128bit, mask_128bit );
    append_oxm_match_ipv6_dst( match, data_128bit, nomask_128bit );
    append_oxm_match_ipv6_dst( match, data_128bit, mask_128bit );
    append_oxm_match_ipv6_flabel( match, data_32bit, nomask_32bit );
    append_oxm_match_ipv6_flabel( match, data_32bit, mask_32bit );
    append_oxm_match_icmpv6_type( match, 9 );
    append_oxm_match_icmpv6_code( match, 0xa );
    append_oxm_match_ipv6_nd_target( match, data_128bit );
    append_oxm_match_ipv6_nd_sll( match, d_48bit );
    append_oxm_match_ipv6_nd_tll( match, d_48bit );
    append_oxm_match_mpls_label( match, data_32bit );
    append_oxm_match_mpls_tc( match, 1 );
    append_oxm_match_mpls_bos( match, 2 );
    append_oxm_match_pbb_isid( match, data_32bit, nomask_32bit );
    append_oxm_match_pbb_isid( match, data_32bit, mask_32bit );
    append_oxm_match_tunnel_id( match, data_64bit, nomask_64bit );
    append_oxm_match_tunnel_id( match, data_64bit, mask_64bit );
    append_oxm_match_ipv6_exthdr( match, data_16bit, nomask_16bit );
    append_oxm_match_ipv6_exthdr( match, data_16bit, mask_16bit );

    assert_true( match_to_string( match, match_str, sizeof( match_str ) ) );
    assert_string_equal( match_str, expected_match_str );

    delete_oxm_matches( match );
  }
}


static void
test_match_to_string_fails_with_insufficient_buffer() {
  char match_str[ 1 ];

  oxm_matches *match = create_oxm_matches();
  assert_false( match_to_string( match, match_str, sizeof( match_str ) ) );
  delete_oxm_matches( match );
}


static void
test_phy_port_to_string() {
  char phy_port_str[ 256 ];
  char expected_phy_port_str[] = "port_no = 1, hw_addr = 01:02:03:04:05:06, name = GbE 0/1, config = 0x1, state = 0x1, curr = 0x4820, advertised = 0xffff, supported = 0xffff, peer = 0xffff, curr_speed = 0x3e8, max_speed = 0x7d0";
  uint8_t hw_addr[ OFP_ETH_ALEN ] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
  uint32_t port_features = ( OFPPF_10MB_HD | OFPPF_10MB_FD | OFPPF_100MB_HD |
                            OFPPF_100MB_FD | OFPPF_1GB_HD | OFPPF_1GB_FD |
                            OFPPF_10GB_FD | OFPPF_40GB_FD | OFPPF_100GB_FD |
                            OFPPF_1TB_FD | OFPPF_OTHER | OFPPF_COPPER |
                            OFPPF_FIBER | OFPPF_AUTONEG | OFPPF_PAUSE |
                            OFPPF_PAUSE_ASYM );
  struct ofp_port phy_port;

  phy_port.port_no = 1;
  memcpy( phy_port.hw_addr, hw_addr, sizeof( phy_port.hw_addr ) );
  memset( phy_port.name, '\0', OFP_MAX_PORT_NAME_LEN );
  strncpy( phy_port.name, "GbE 0/1", OFP_MAX_PORT_NAME_LEN );
  phy_port.config = OFPPC_PORT_DOWN;
  phy_port.state = OFPPS_LINK_DOWN;
  phy_port.curr = ( OFPPF_1GB_FD | OFPPF_COPPER | OFPPF_PAUSE );
  phy_port.advertised = port_features;
  phy_port.supported = port_features;
  phy_port.peer = port_features;
  phy_port.curr_speed = 1000;
  phy_port.max_speed = 2000;

  assert_true( port_to_string( &phy_port, phy_port_str, sizeof( phy_port_str ) ) );
  assert_string_equal( phy_port_str, expected_phy_port_str );
}


static void
test_phy_port_to_string_fails_with_insufficient_buffer() {
  char phy_port_str[ 1 ];
  struct ofp_port phy_port;

  assert_false( port_to_string( &phy_port, phy_port_str, sizeof( phy_port_str ) ) );
}


static void
test_actions_to_string_with_action_output() {
  char str[ 128 ];
  char expected_str[] = "output: port=1 max_len=65535";
  struct ofp_action_output action;

  action.type = OFPAT_OUTPUT;
  action.len = sizeof( struct ofp_action_output );
  action.port = 1;
  action.max_len = 65535;

  assert_true( actions_to_string( ( const struct ofp_action_header * ) &action, action.len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
}


static void
test_actions_to_string_with_action_set_field() {
  char str[ 128 ];
  char expected_str[] = "set_field: field=[tcp_src = 1000]";
  uint16_t len = ( uint16_t ) ( offsetof( struct ofp_action_set_field, field ) + sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_TCP_SRC ) );
  uint16_t total_len = ( uint16_t ) ( len + PADLEN_TO_64( len ) );
  struct ofp_action_set_field *action = xcalloc( 1, total_len );
  oxm_match_header *oxm;
  uint16_t *oxm_val;

  action->type = OFPAT_SET_FIELD;
  action->len = total_len;
  oxm = ( oxm_match_header * ) action->field;
  *oxm = OXM_OF_TCP_SRC;
  oxm_val = ( uint16_t * ) ( oxm + 1 );
  *oxm_val = 1000;

  assert_true( actions_to_string( ( const struct ofp_action_header * ) action, action->len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );

  xfree( action );
}


static void
test_actions_to_string_with_action_set_queue() {
  char str[ 128 ];
  char expected_str[] = "set_queue: queue_id=3";
  struct ofp_action_set_queue action;

  action.type = OFPAT_SET_QUEUE;
  action.len = sizeof( struct ofp_action_set_queue );
  action.queue_id = 3;

  assert_true( actions_to_string( ( const struct ofp_action_header * ) &action, action.len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
}


static void
test_actions_to_string_with_action_copy_ttl_out() {
  char str[ 128 ];
  char expected_str[] = "copy_ttl_out";
  struct ofp_action_header action;

  action.type = OFPAT_COPY_TTL_OUT;
  action.len = sizeof( struct ofp_action_header );

  assert_true( actions_to_string( ( const struct ofp_action_header * ) &action, action.len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
}


static void
test_actions_to_string_with_action_copy_ttl_in() {
  char str[ 128 ];
  char expected_str[] = "copy_ttl_in";
  struct ofp_action_header action;

  action.type = OFPAT_COPY_TTL_IN;
  action.len = sizeof( struct ofp_action_header );

  assert_true( actions_to_string( ( const struct ofp_action_header * ) &action, action.len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
}


static void
test_actions_to_string_with_action_set_mpls_ttl() {
  char str[ 128 ];
  char expected_str[] = "set_mpls_ttl: mpls_ttl=3";
  struct ofp_action_mpls_ttl action;

  action.type = OFPAT_SET_MPLS_TTL;
  action.len = sizeof( struct ofp_action_mpls_ttl );
  action.mpls_ttl = 3;

  assert_true( actions_to_string( ( const struct ofp_action_header * ) &action, action.len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
}


static void
test_actions_to_string_with_action_dec_mpls_ttl() {
  char str[ 128 ];
  char expected_str[] = "dec_mpls_ttl";
  struct ofp_action_header action;

  action.type = OFPAT_DEC_MPLS_TTL;
  action.len = sizeof( struct ofp_action_header );

  assert_true( actions_to_string( ( const struct ofp_action_header * ) &action, action.len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
}


static void
test_actions_to_string_with_action_push_vlan() {
  char str[ 128 ];
  char expected_str[] = "push_vlan: ethertype=0x3";
  struct ofp_action_push action;

  action.type = OFPAT_PUSH_VLAN;
  action.len = sizeof( struct ofp_action_push );
  action.ethertype = 3;

  assert_true( actions_to_string( ( const struct ofp_action_header * ) &action, action.len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
}


static void
test_actions_to_string_with_action_pop_vlan() {
  char str[ 128 ];
  char expected_str[] = "pop_vlan";
  struct ofp_action_header action;

  action.type = OFPAT_POP_VLAN;
  action.len = sizeof( struct ofp_action_header );

  assert_true( actions_to_string( ( const struct ofp_action_header * ) &action, action.len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
}


static void
test_actions_to_string_with_action_push_mpls() {
  char str[ 128 ];
  char expected_str[] = "push_mpls: ethertype=0x3";
  struct ofp_action_push action;

  action.type = OFPAT_PUSH_MPLS;
  action.len = sizeof( struct ofp_action_push );
  action.ethertype = 3;

  assert_true( actions_to_string( ( const struct ofp_action_header * ) &action, action.len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
}


static void
test_actions_to_string_with_action_pop_mpls() {
  char str[ 128 ];
  char expected_str[] = "pop_mpls: ethertype=0x3";
  struct ofp_action_pop_mpls action;

  action.type = OFPAT_POP_MPLS;
  action.len = sizeof( struct ofp_action_pop_mpls );
  action.ethertype = 3;

  assert_true( actions_to_string( ( const struct ofp_action_header * ) &action, action.len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
}


static void
test_actions_to_string_with_action_group() {
  char str[ 128 ];
  char expected_str[] = "group: group_id=0x3";
  struct ofp_action_group action;

  action.type = OFPAT_GROUP;
  action.len = sizeof( struct ofp_action_group );
  action.group_id = 3;

  assert_true( actions_to_string( ( const struct ofp_action_header * ) &action, action.len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
}


static void
test_actions_to_string_with_action_set_nw_ttl() {
  char str[ 128 ];
  char expected_str[] = "set_nw_ttl: nw_ttl=3";
  struct ofp_action_nw_ttl action;

  action.type = OFPAT_SET_NW_TTL;
  action.len = sizeof( struct ofp_action_nw_ttl );
  action.nw_ttl = 3;

  assert_true( actions_to_string( ( const struct ofp_action_header * ) &action, action.len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
}


static void
test_actions_to_string_with_action_dec_nw_ttl() {
  char str[ 128 ];
  char expected_str[] = "dec_nw_ttl";
  struct ofp_action_header action;

  action.type = OFPAT_DEC_NW_TTL;
  action.len = sizeof( struct ofp_action_header );

  assert_true( actions_to_string( ( const struct ofp_action_header * ) &action, action.len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
}


static void
test_actions_to_string_with_action_push_pbb() {
  char str[ 128 ];
  char expected_str[] = "push_pbb: ethertype=0x3";
  struct ofp_action_push action;

  action.type = OFPAT_PUSH_PBB;
  action.len = sizeof( struct ofp_action_push );
  action.ethertype = 3;

  assert_true( actions_to_string( ( const struct ofp_action_header * ) &action, action.len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
}


static void
test_actions_to_string_with_action_pop_pbb() {
  char str[ 128 ];
  char expected_str[] = "pop_pbb";
  struct ofp_action_header action;

  action.type = OFPAT_POP_PBB;
  action.len = sizeof( struct ofp_action_header );

  assert_true( actions_to_string( ( const struct ofp_action_header * ) &action, action.len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
}


static void
test_actions_to_string_with_action_experimenter() {
  char str[ 128 ];
  char expected_str[] = "experimenter: experimenter=0xdeadbeef";
  struct ofp_action_experimenter_header action;

  action.type = OFPAT_EXPERIMENTER;
  action.len = sizeof( struct ofp_action_experimenter_header );
  action.experimenter = 0xdeadbeef;

  assert_true( actions_to_string( ( const struct ofp_action_header * ) &action, action.len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
}


static void
test_actions_to_string_with_undefined_action() {
  char str[ 128 ];
  char expected_str[] = "undefined: type=0xcafe";
  struct ofp_action_header action;

  action.type = 0xcafe;
  action.len = sizeof( struct ofp_action_header );

  assert_true( actions_to_string( ( const struct ofp_action_header * ) &action, action.len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
}


static void
test_actions_to_string_with_multiple_actions() {
  char str[ 128 ];
  char expected_str[] = "output: port=1 max_len=65535, set_queue: queue_id=3";
  uint16_t actions_length = sizeof( struct ofp_action_output ) + sizeof( struct ofp_action_set_queue );
  void *actions = malloc( actions_length );
  memset( actions, 0, actions_length );
  struct ofp_action_output *output = actions;
  struct ofp_action_set_queue *set_queue = ( struct ofp_action_set_queue * ) ( ( char * ) actions + sizeof( struct ofp_action_output ) );

  output->type = OFPAT_OUTPUT;
  output->len = sizeof( struct ofp_action_output );
  output->port = 1;
  output->max_len = 65535;
  set_queue->type = OFPAT_SET_QUEUE;
  set_queue->len = sizeof( struct ofp_action_set_queue );
  set_queue->queue_id = 3;

  assert_true( actions_to_string( ( const struct ofp_action_header * ) actions, actions_length, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
  free( actions );
}


static void
test_actions_to_string_fails_with_insufficient_buffer() {
  char str[ 1 ];
  struct ofp_action_output action;

  action.type = OFPAT_OUTPUT;
  action.len = sizeof( struct ofp_action_output );
  action.port = 1;
  action.max_len = 65535;

  assert_false( actions_to_string( ( const struct ofp_action_header * ) &action, action.len, str, sizeof( str ) ) );
}


static void
test_instructions_to_string_goto_table() {
  char str[ 128 ];
  char expected_str[] = "goto_table: table_id=0x3";
  struct ofp_instruction_goto_table inst;

  inst.type = OFPIT_GOTO_TABLE;
  inst.len = sizeof( struct ofp_instruction_goto_table );
  inst.table_id = 3;

  assert_true( instructions_to_string( ( const struct ofp_instruction * ) &inst, inst.len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
}


static void
test_instructions_to_string_write_metadata() {
  char str[ 128 ];
  char expected_str[] = "write_metadata: metadata=0x3 metadata_mask=0x4";
  struct ofp_instruction_write_metadata inst;

  inst.type = OFPIT_WRITE_METADATA;
  inst.len = sizeof( struct ofp_instruction_write_metadata );
  inst.metadata = 3;
  inst.metadata_mask = 4;

  assert_true( instructions_to_string( ( const struct ofp_instruction * ) &inst, inst.len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
}


static void
test_instructions_to_string_write_actions() {
  char str[ 128 ];
  {
    char expected_str[] = "write_actions: actions=[set_queue: queue_id=3, output: port=1 max_len=65535]";
    uint16_t len = ( uint16_t ) ( offsetof( struct ofp_instruction_actions, actions ) + sizeof( struct ofp_action_set_queue ) + sizeof( struct ofp_action_output ) );
    struct ofp_instruction_actions *inst = xcalloc( 1, len );
    struct ofp_action_set_queue *set_queue = ( struct ofp_action_set_queue * ) inst->actions;
    struct ofp_action_output *output = ( struct ofp_action_output * ) ( set_queue + 1 );

    inst->type = OFPIT_WRITE_ACTIONS;
    inst->len = len;
    set_queue->type = OFPAT_SET_QUEUE;
    set_queue->len = sizeof( struct ofp_action_set_queue );
    set_queue->queue_id = 3;
    output->type = OFPAT_OUTPUT;
    output->len = sizeof( struct ofp_action_output );
    output->port = 1;
    output->max_len = 65535;

    assert_true( instructions_to_string( ( const struct ofp_instruction * ) inst, inst->len, str, sizeof( str ) ) );
    assert_string_equal( str, expected_str );

    xfree( inst );
  }

  {
    char expected_str[] = "write_actions: actions=[no action]";
    uint16_t len = ( uint16_t ) offsetof( struct ofp_instruction_actions, actions );
    struct ofp_instruction_actions *inst = xcalloc( 1, len );

    inst->type = OFPIT_WRITE_ACTIONS;
    inst->len = len;

    assert_true( instructions_to_string( ( const struct ofp_instruction * ) inst, inst->len, str, sizeof( str ) ) );
    assert_string_equal( str, expected_str );

    xfree( inst );
  }
}


static void
test_instructions_to_string_apply_actions() {
  char str[ 128 ];
  {
    char expected_str[] = "apply_actions: actions=[set_queue: queue_id=3, output: port=1 max_len=65535]";
    uint16_t len = ( uint16_t ) ( offsetof( struct ofp_instruction_actions, actions ) + sizeof( struct ofp_action_set_queue ) + sizeof( struct ofp_action_output ) );
    struct ofp_instruction_actions *inst = xcalloc( 1, len );
    struct ofp_action_set_queue *set_queue = ( struct ofp_action_set_queue * ) inst->actions;
    struct ofp_action_output *output = ( struct ofp_action_output * ) ( set_queue + 1 );

    inst->type = OFPIT_APPLY_ACTIONS;
    inst->len = len;
    set_queue->type = OFPAT_SET_QUEUE;
    set_queue->len = sizeof( struct ofp_action_set_queue );
    set_queue->queue_id = 3;
    output->type = OFPAT_OUTPUT;
    output->len = sizeof( struct ofp_action_output );
    output->port = 1;
    output->max_len = 65535;

    assert_true( instructions_to_string( ( const struct ofp_instruction * ) inst, inst->len, str, sizeof( str ) ) );
    assert_string_equal( str, expected_str );

    xfree( inst );
  }

  {
    char expected_str[] = "apply_actions: actions=[no action]";
    uint16_t len = ( uint16_t ) offsetof( struct ofp_instruction_actions, actions );
    struct ofp_instruction_actions *inst = xcalloc( 1, len );

    inst->type = OFPIT_APPLY_ACTIONS;
    inst->len = len;

    assert_true( instructions_to_string( ( const struct ofp_instruction * ) inst, inst->len, str, sizeof( str ) ) );
    assert_string_equal( str, expected_str );

    xfree( inst );
  }
}


static void
test_instructions_to_string_clear_actions() {
  char str[ 128 ];
  char expected_str[] = "clear_actions";
  struct ofp_instruction_actions inst;

  inst.type = OFPIT_CLEAR_ACTIONS;
  inst.len = sizeof( struct ofp_instruction_actions );

  assert_true( instructions_to_string( ( const struct ofp_instruction * ) &inst, inst.len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
}


static void
test_instructions_to_string_meter() {
  char str[ 128 ];
  char expected_str[] = "meter: meter_id=0x3";
  struct ofp_instruction_meter inst;

  inst.type = OFPIT_METER;
  inst.len = sizeof( struct ofp_instruction_meter );
  inst.meter_id = 3;

  assert_true( instructions_to_string( ( const struct ofp_instruction * ) &inst, inst.len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
}


static void
test_instructions_to_string_experimenter() {
  char str[ 128 ];
  char expected_str[] = "experimenter: experimenter=0x3";
  struct ofp_instruction_experimenter inst;

  inst.type = OFPIT_EXPERIMENTER;
  inst.len = sizeof( struct ofp_instruction_experimenter );
  inst.experimenter = 3;

  assert_true( instructions_to_string( ( const struct ofp_instruction * ) &inst, inst.len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
}


static void
test_instructions_to_string_with_undefined_instruction() {
  char str[ 128 ];
  char expected_str[] = "undefined: type=0xcafe";
  struct ofp_instruction inst;

  inst.type = 0xcafe;
  inst.len = sizeof( struct ofp_instruction );

  assert_true( instructions_to_string( ( const struct ofp_instruction * ) &inst, inst.len, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
}


static void
test_instructions_to_string_with_multiple_instructions() {
  char str[ 128 ];
  char expected_str[] = "goto_table: table_id=0x3, write_metadata: metadata=0x3 metadata_mask=0x4";
  uint16_t insts_length = sizeof( struct ofp_instruction_goto_table ) + sizeof( struct ofp_instruction_write_metadata );
  void *insts = malloc( insts_length );
  memset( insts, 0, insts_length );
  struct ofp_instruction_goto_table *goto_table = insts;
  struct ofp_instruction_write_metadata *write_metadata = ( struct ofp_instruction_write_metadata * ) ( ( char * ) insts + sizeof( struct ofp_instruction_goto_table ) );

  goto_table->type = OFPIT_GOTO_TABLE;
  goto_table->len = sizeof( struct ofp_instruction_goto_table );
  goto_table->table_id = 3;
  write_metadata->type = OFPIT_WRITE_METADATA;
  write_metadata->len = sizeof( struct ofp_instruction_write_metadata );
  write_metadata->metadata = 3;
  write_metadata->metadata_mask = 4;

  assert_true( instructions_to_string( ( const struct ofp_instruction * ) insts, insts_length, str, sizeof( str ) ) );
  assert_string_equal( str, expected_str );
  free( insts );
}


static void
test_instructions_to_string_fails_with_insufficient_buffer() {
  char str[ 1 ];
  struct ofp_instruction_goto_table inst;

  inst.type = OFPIT_GOTO_TABLE;
  inst.len = sizeof( struct ofp_instruction_goto_table );
  inst.table_id = 3;

  assert_false( instructions_to_string( ( const struct ofp_instruction * ) &inst, inst.len, str, sizeof( str ) ) );

}


static void
test_get_checksum_udp_packet() {
  ipv4_header_t ipv4_header;

  // Create a test packet.
  memset( &ipv4_header, 0, sizeof( ipv4_header ) );
  ipv4_header.version = 4;
  ipv4_header.ihl = 5;
  ipv4_header.tos = 0;
  ipv4_header.tot_len = htons( 0x004c );
  ipv4_header.id = htons( 0x48d8 );
  ipv4_header.frag_off = htons( 0 );
  ipv4_header.ttl = 0x80;
  ipv4_header.protocol = 0x11;
  ipv4_header.csum = 0;
  ipv4_header.saddr = htonl( 0x0a3835af );
  ipv4_header.daddr = htonl( 0x0a3837ff );

  uint16_t checksum = get_checksum( ( uint16_t * ) &ipv4_header,
                                    sizeof( ipv4_header ) );
  assert_int_equal( checksum, 0xab6f );
}


static void
test_get_checksum_icmp_packet() {
  ipv4_header_t ipv4_header;

  // Create a test packet.
  memset( &ipv4_header, 0, sizeof( ipv4_header ) );
  ipv4_header.version = 4;
  ipv4_header.ihl = 5;
  ipv4_header.tos = 0;
  ipv4_header.tot_len = htons( 0x0054 );
  ipv4_header.id = htons( 0xaec3 );
  ipv4_header.frag_off = htons( 0 );
  ipv4_header.ttl = 0x40;
  ipv4_header.protocol = 0x01;
  ipv4_header.csum = 0;
  ipv4_header.saddr = htonl( 0xc0a8642b );
  ipv4_header.daddr = htonl( 0xc0a8642c );

  uint16_t checksum = get_checksum( ( uint16_t * ) &ipv4_header,
                                    sizeof( ipv4_header ) );
  assert_int_equal( checksum, 0x3d82 );
}


/********************************************************************************
 * Run tests.
 ********************************************************************************/

int
main() {
  const UnitTest tests[] = {
    unit_test_setup_teardown( test_die, setup, teardown ),

    unit_test( test_hash_core ),

    unit_test( test_compare_string ),
    unit_test( test_hash_string ),

    unit_test( test_compare_uint32 ),
    unit_test( test_hash_uint32 ),

    unit_test( test_compare_datapath_id ),
    unit_test( test_hash_datapath_id ),

    unit_test( test_compare_mac ),
    unit_test( test_hash_mac ),
    unit_test( test_mac_to_uint64 ),

    unit_test( test_string_to_datapath_id ),

    unit_test( test_match_to_string ),
    unit_test( test_match_to_string_fails_with_insufficient_buffer ),

    unit_test( test_phy_port_to_string ),
    unit_test( test_phy_port_to_string_fails_with_insufficient_buffer ),

    unit_test( test_actions_to_string_with_action_output ),
    unit_test( test_actions_to_string_with_action_set_field ),
    unit_test( test_actions_to_string_with_action_set_queue ),
    unit_test( test_actions_to_string_with_action_copy_ttl_out ),
    unit_test( test_actions_to_string_with_action_copy_ttl_in ),
    unit_test( test_actions_to_string_with_action_set_mpls_ttl ),
    unit_test( test_actions_to_string_with_action_dec_mpls_ttl ),
    unit_test( test_actions_to_string_with_action_push_vlan ),
    unit_test( test_actions_to_string_with_action_pop_vlan ),
    unit_test( test_actions_to_string_with_action_push_mpls ),
    unit_test( test_actions_to_string_with_action_pop_mpls ),
    unit_test( test_actions_to_string_with_action_group ),
    unit_test( test_actions_to_string_with_action_set_nw_ttl ),
    unit_test( test_actions_to_string_with_action_dec_nw_ttl ),
    unit_test( test_actions_to_string_with_action_push_pbb ),
    unit_test( test_actions_to_string_with_action_pop_pbb ),
    unit_test( test_actions_to_string_with_action_experimenter ),
    unit_test( test_actions_to_string_with_undefined_action ),
    unit_test( test_actions_to_string_with_multiple_actions ),
    unit_test( test_actions_to_string_fails_with_insufficient_buffer ),

    unit_test( test_instructions_to_string_goto_table ),
    unit_test( test_instructions_to_string_write_metadata ),
    unit_test( test_instructions_to_string_write_actions ),
    unit_test( test_instructions_to_string_apply_actions ),
    unit_test( test_instructions_to_string_clear_actions ),
    unit_test( test_instructions_to_string_meter ),
    unit_test( test_instructions_to_string_experimenter ),
    unit_test( test_instructions_to_string_with_undefined_instruction ),
    unit_test( test_instructions_to_string_with_multiple_instructions ),
    unit_test( test_instructions_to_string_fails_with_insufficient_buffer ),

    unit_test( test_get_checksum_udp_packet ),
    unit_test( test_get_checksum_icmp_packet ),
  };
  setup_leak_detector();
  return run_tests( tests );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
