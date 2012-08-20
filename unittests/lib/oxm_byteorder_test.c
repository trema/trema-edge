/*
 * An OpenFlow application interface library.
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


#include <netinet/in.h>
#include "oxm_byteorder.h"
#include "checks.h"
#include "cmockery_trema.h"
#include "wrapper.h"
#include "byteorder.h"


void
mock_die( const char *format, ... ) {
  UNUSED( format );

  mock_assert( false, "mock_die", __FILE__, __LINE__ );
}


void hton_oxm_match_header( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_8( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_16( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_16w( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_32( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_32w( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_64( oxm_match_header *dst, const oxm_match_header *src );
void hton_oxm_match_64w( oxm_match_header *dst, const oxm_match_header *src );


#define TLVLEN( width ) ( uint16_t ) ( sizeof( oxm_match_header ) + ( width ) )
#define TLVLEN_W( width ) ( uint16_t ) ( sizeof( oxm_match_header ) + ( uint16_t ) ( ( width ) * 2 ) )


const uint8_t data_8bit = 0x12;
const uint16_t data_16bit = 0x1234;
const uint32_t data_32bit = 0x12345678;
const uint8_t data_48bit[6] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0x12 };
const uint64_t data_64bit = 0x1234567890123456;
const struct in6_addr data_128bit = { { { 0x12, 0x34, 0x56, 0x78,
                                          0x90, 0x12, 0x34, 0x56,
                                          0x78, 0x90, 0x12, 0x34,
                                          0x56, 0x78, 0x90, 0x12 } } };

const uint16_t mask_16bit = 0x4321;
const uint32_t mask_32bit = 0x87654321;
const uint8_t mask_48bit[6] = { 0x21, 0x09, 0x87, 0x65, 0x43, 0x21 };
const uint64_t mask_64bit = 0x6543210987654321;
const struct in6_addr mask_128bit = { { { 0x21, 0x09, 0x87, 0x65,
                                          0x43, 0x21, 0x09, 0x87,
                                          0x65, 0x43, 0x21, 0x09,
                                          0x87, 0x65, 0x43, 0x21 } } };



static oxm_match_header *
create_oxm_match_8( oxm_match_header header, const uint8_t value, bool nwbyte ) {
  assert( OXM_LENGTH( header ) == sizeof( uint8_t ) );

  oxm_match_header *buf = xmalloc( sizeof( oxm_match_header ) + sizeof( uint8_t ) );
  if ( nwbyte ) {
    *buf = htonl( header );
  } else {
    *buf = header;
  }
  uint8_t *v = ( uint8_t * ) ( ( char * ) buf + sizeof( oxm_match_header ) );
  *v = value;

  return buf;
}


static oxm_match_header *
create_oxm_match_16( oxm_match_header header, const uint16_t value, bool nwbyte ) {
  assert( OXM_LENGTH( header ) == sizeof( uint16_t ) );

  oxm_match_header *buf = xmalloc( sizeof( oxm_match_header ) + sizeof( uint16_t ) );
  if ( nwbyte ) {
    *buf = htonl( header );
  } else {
    *buf = header;
  }
  uint16_t *v = ( uint16_t * ) ( ( char * ) buf + sizeof( oxm_match_header ) );
  *v = value;

  return buf;
}


static oxm_match_header *
create_oxm_match_16w( oxm_match_header header, const uint16_t value, const uint16_t mask, bool nwbyte ) {
  assert( OXM_LENGTH( header ) == ( sizeof( uint16_t ) * 2 ) );

  oxm_match_header *buf = xmalloc( sizeof( oxm_match_header ) + ( sizeof( uint16_t ) * 2 ) );
  if ( nwbyte ) {
    *buf = htonl( header );
  } else {
    *buf = header;
  }
  uint16_t *v = ( uint16_t * ) ( ( char * ) buf + sizeof( oxm_match_header ) );
  *v = value;
  v = ( uint16_t * ) ( ( char * ) v + sizeof( uint16_t ) );
  *v = mask;

  return buf;
}


static oxm_match_header *
create_oxm_match_32( oxm_match_header header, const uint32_t value, bool nwbyte ) {
  assert( OXM_LENGTH( header ) == sizeof( uint32_t ) );

  oxm_match_header *buf = xmalloc( sizeof( oxm_match_header ) + sizeof( uint32_t ) );
  if ( nwbyte ) {
    *buf = htonl( header );
  } else {
    *buf = header;
  }
  uint32_t *v = ( uint32_t * ) ( ( char * ) buf + sizeof( oxm_match_header ) );
  *v = value;

  return buf;
}


static oxm_match_header *
create_oxm_match_32w( oxm_match_header header, const uint32_t value, const uint32_t mask, bool nwbyte ) {
  assert( OXM_LENGTH( header ) == ( sizeof( uint32_t ) * 2 ) );

  oxm_match_header *buf = xmalloc( sizeof( oxm_match_header ) + sizeof( uint32_t ) * 2 );
  if ( nwbyte ) {
    *buf = htonl( header );
  } else {
    *buf = header;
  }
  uint32_t *v = ( uint32_t * ) ( ( char * ) buf + sizeof( oxm_match_header ) );
  *v = value;
  v = ( uint32_t * ) ( ( char * ) v + sizeof( uint32_t ) );
  *v = mask;

  return buf;
}


static oxm_match_header *
create_oxm_match_64( oxm_match_header header, const uint64_t value, bool nwbyte ) {
  assert( OXM_LENGTH( header ) == sizeof( uint64_t ) );

  oxm_match_header *buf = xmalloc( sizeof( oxm_match_header ) + sizeof( uint64_t ) );
  if ( nwbyte ) {
    *buf = htonl( header );
  } else {
    *buf = header;
  }
  uint64_t *v = ( uint64_t * ) ( ( char * ) buf + sizeof( oxm_match_header ) );
  *v = value;

  return buf;
}


static oxm_match_header *
create_oxm_match_64w( oxm_match_header header, const uint64_t value, const uint64_t mask, bool nwbyte ) {
  assert( OXM_LENGTH( header ) == ( sizeof( uint64_t ) * 2 ) );

  oxm_match_header *buf = xmalloc( sizeof( oxm_match_header ) + sizeof( uint64_t ) * 2 );
  if ( nwbyte ) {
    *buf = htonl( header );
  } else {
    *buf = header;
  }
  uint64_t *v = ( uint64_t * ) ( ( char * ) buf + sizeof( oxm_match_header ) );
  *v = value;
  v = ( uint64_t * ) ( ( char * ) v + sizeof( uint64_t ) );
  *v = mask;

  return buf;
}


static oxm_match_header *
create_oxm_match_eth_addr( oxm_match_header header, const uint8_t addr[ OFP_ETH_ALEN ], bool nwbyte ) {
  assert( OXM_LENGTH( header ) == ( OFP_ETH_ALEN * sizeof( uint8_t ) ) );

  oxm_match_header *buf = xmalloc( sizeof( oxm_match_header ) + ( OFP_ETH_ALEN * sizeof( uint8_t ) ) );
  if ( nwbyte ) {
    *buf = htonl( header );
  } else {
    *buf = header;
  }
  uint8_t *value = ( uint8_t * ) ( ( char * ) buf + sizeof( oxm_match_header ) );
  memcpy( value, addr, OFP_ETH_ALEN * sizeof( uint8_t ) );

  return buf;
}


static oxm_match_header *
create_oxm_match_eth_addr_w( oxm_match_header header,
                            const uint8_t addr[ OFP_ETH_ALEN ],
                            const uint8_t mask[ OFP_ETH_ALEN ],
                            bool nwbyte ) {
  assert( OXM_LENGTH( header ) == ( 2 * OFP_ETH_ALEN * sizeof( uint8_t ) ) );

  oxm_match_header *buf = xmalloc( sizeof( oxm_match_header ) + ( 2 * OFP_ETH_ALEN * sizeof( uint8_t ) ) );
  if ( nwbyte ) {
    *buf = htonl( header );
  } else {
    *buf = header;
  }
  uint8_t *value = ( uint8_t * ) ( ( char * ) buf + sizeof( oxm_match_header ) );
  memcpy( value, addr, OFP_ETH_ALEN * sizeof( uint8_t ) );
  value = ( uint8_t * ) ( ( char * ) value + ( sizeof( uint8_t ) * OFP_ETH_ALEN ) );
  memcpy( value, mask, OFP_ETH_ALEN * sizeof( uint8_t ) );

  return buf;
}


static oxm_match_header *
create_oxm_match_ipv6_addr( oxm_match_header header,
                            const struct in6_addr addr,
                            const struct in6_addr mask,
                            bool nwbyte ) {
  uint8_t length = OXM_LENGTH( header );
  oxm_match_header *buf = xmalloc( sizeof( oxm_match_header ) + length );
  if ( nwbyte ) {
    *buf = htonl( header );
  } else {
    *buf = header;
  }
  void *p = ( char * ) buf + sizeof( oxm_match_header );
  memcpy( p, &addr, sizeof( struct in6_addr ) );

  if ( OXM_HASMASK( header ) ) {
    p = ( char * ) p + sizeof( struct in6_addr );
    memcpy( p, &mask, sizeof( struct in6_addr ) );
  }

  return buf;
}


/********************************************************************************
 * Tests.
 ********************************************************************************/


static void
test_hton_oxm_match_header() {
  const uint32_t data = data_32bit;
  uint16_t width = sizeof( uint32_t );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src = create_oxm_match_32( OXM_OF_IN_PORT, data, false );
  oxm_match_header *dst = xcalloc( 1, tlvlen );

  hton_oxm_match_header( dst, src );
  assert_int_equal( *dst, htonl( *src ) );

  expect_assert_failure( hton_oxm_match_header( dst, NULL ) );
  expect_assert_failure( hton_oxm_match_header( NULL, src ) );
  expect_assert_failure( hton_oxm_match_header( NULL, NULL ) );

  xfree( src );
  xfree( dst );
}


static void
test_hton_oxm_match_8() {
  const uint8_t data = data_8bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src = create_oxm_match_8( OXM_OF_VLAN_PCP, data, false );
  oxm_match_header *dst = xcalloc( 1, tlvlen );

  hton_oxm_match_8( dst, src );

  uint8_t *dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
  uint8_t *src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
  assert_int_equal( *dst, htonl( *src ) );
  assert_int_equal( *dst_val, *src_val );

  xfree( src );
  xfree( dst );
}


static void
test_hton_oxm_match_16() {
  const uint16_t data = data_16bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src = create_oxm_match_16( OXM_OF_VLAN_VID, data, false );
  oxm_match_header *dst = xcalloc( 1, tlvlen );

  hton_oxm_match_16( dst, src );

  uint16_t *dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
  uint16_t *src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
  assert_int_equal( *dst, htonl( *src ) );
  assert_int_equal( *dst_val, htons( *src_val ) );

  xfree( src );
  xfree( dst );
}


static void
test_hton_oxm_match_16w() {
  const uint16_t data = data_16bit;
  const uint16_t mask = mask_16bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN_W( width );

  oxm_match_header *src = create_oxm_match_16w( OXM_OF_VLAN_VID_W, data, mask, false );
  oxm_match_header *dst = xcalloc( 1, tlvlen );

  hton_oxm_match_16w( dst, src );

  uint16_t *dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
  uint16_t *src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
  uint16_t *dst_mask = ( uint16_t * ) ( ( char * ) src_val + width );
  uint16_t *src_mask = ( uint16_t * ) ( ( char * ) dst_val + width );
  assert_int_equal( *dst, htonl( *src ) );
  assert_int_equal( *dst_val, htons( *src_val ) );
  assert_int_equal( *dst_mask, htons( *src_mask ) );

  xfree( src );
  xfree( dst );
}


static void
test_hton_oxm_match_32() {
  const uint32_t data = data_32bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src = create_oxm_match_32( OXM_OF_IPV4_SRC, data, false );
  oxm_match_header *dst = xcalloc( 1, tlvlen );

  hton_oxm_match_32( dst, src );

  uint32_t *dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
  uint32_t *src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
  assert_int_equal( *dst, htonl( *src ) );
  assert_int_equal( *dst_val, htonl( *src_val ) );

  xfree( src );
  xfree( dst );
}


static void
test_hton_oxm_match_32w() {
  const uint32_t data = data_32bit;
  const uint32_t mask = mask_32bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN_W( width );

  oxm_match_header *src = create_oxm_match_32w( OXM_OF_IPV4_SRC_W, data, mask, false );
  oxm_match_header *dst = xcalloc( 1, tlvlen );

  hton_oxm_match_32w( dst, src );

  uint32_t *dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
  uint32_t *src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
  uint32_t *dst_mask = ( uint32_t * ) ( ( char * ) src_val + width );
  uint32_t *src_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
  assert_int_equal( *dst, htonl( *src ) );
  assert_int_equal( *dst_val, htonl( *src_val ) );
  assert_int_equal( *dst_mask, htonl( *src_mask ) );

  xfree( src );
  xfree( dst );
}


static void
test_hton_oxm_match_64() {
  const uint64_t data = data_64bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src = create_oxm_match_64( OXM_OF_METADATA, data, false );
  oxm_match_header *dst = xcalloc( 1, tlvlen );

  hton_oxm_match_64( dst, src );

  uint64_t *dst_val = ( uint64_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
  uint64_t *src_val = ( uint64_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
  assert_int_equal( *dst, htonl( *src ) );
  assert_true( *dst_val == htonll( *src_val ) );

  xfree( src );
  xfree( dst );
}


static void
test_hton_oxm_match_64w() {
  const uint64_t data = data_64bit;
  const uint64_t mask = mask_64bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN_W( width );

  oxm_match_header *src = create_oxm_match_64w( OXM_OF_METADATA_W, data, mask, false );
  oxm_match_header *dst = xcalloc( 1, tlvlen );

  hton_oxm_match_64w( dst, src );

  uint64_t *dst_val = ( uint64_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
  uint64_t *src_val = ( uint64_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
  uint64_t *dst_mask = ( uint64_t * ) ( ( char * ) src_val + width );
  uint64_t *src_mask = ( uint64_t * ) ( ( char * ) dst_val + width );
  assert_int_equal( *dst, htonl( *src ) );
  assert_true( *dst_val == htonll( *src_val ) );
  assert_true( *dst_mask == htonll( *src_mask ) );

  xfree( src );
  xfree( dst );
}


static void
test_hton_oxm_match_in_port() {
  const uint32_t data = data_32bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint32_t *src_val, *dst_val;

  {
    src = create_oxm_match_32( OXM_OF_IN_PORT, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_in_port( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htonl( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_32( OXM_OF_IN_PHY_PORT, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_in_port( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htonl( *src_val ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_metadata() {
  const uint64_t data = data_64bit;
  const uint64_t mask = mask_64bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint64_t *src_val, *dst_val, *src_mask, *dst_mask;

  {
    src = create_oxm_match_64( OXM_OF_METADATA, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_metadata( dst, src );

    dst_val = ( uint64_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint64_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_true( *dst_val == htonll( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  tlvlen = TLVLEN_W( width );

  {
    src = create_oxm_match_64w( OXM_OF_METADATA_W, data, mask, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_metadata( dst, src );

    dst_val = ( uint64_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint64_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint64_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint64_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, htonl( *src ) );
    assert_true( *dst_val == htonll( *src_val ) );
    assert_true( *dst_mask == htonll( *src_mask ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_eth_addr() {
  uint8_t data[6];
  uint8_t mask[6];
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  memcpy( data, data_48bit, sizeof( data ) );
  memcpy( mask, mask_48bit, sizeof( mask ) );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val, *src_mask, *dst_mask;

  {
    src = create_oxm_match_eth_addr( OXM_OF_ETH_DST, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_eth_addr( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_eth_addr( OXM_OF_ETH_SRC, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_eth_addr( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    xfree( src );
    xfree( dst );
  }

  tlvlen = TLVLEN_W( width );

  {
    src = create_oxm_match_eth_addr_w( OXM_OF_ETH_DST_W, data, mask, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_eth_addr( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint8_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint8_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, htonl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    assert_memory_equal( dst_mask, src_mask, width );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_eth_addr_w( OXM_OF_ETH_SRC_W, data, mask, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_eth_addr( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint8_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint8_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, htonl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    assert_memory_equal( dst_mask, src_mask, width );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_eth_type() {
  const uint16_t data = data_16bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint16_t *src_val, *dst_val;

  {
    src = create_oxm_match_16( OXM_OF_ETH_TYPE, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_eth_type( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htons( *src_val ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_vlan_vid() {
  const uint16_t data = data_16bit;
  const uint16_t mask = mask_16bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint16_t *src_val, *dst_val, *src_mask, *dst_mask;

  {
    src = create_oxm_match_16( OXM_OF_VLAN_VID, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_vlan_vid( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htons( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  tlvlen = TLVLEN_W( width );

  {
    src = create_oxm_match_16w( OXM_OF_VLAN_VID_W, data, mask, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_vlan_vid( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint16_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint16_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htons( *src_val ) );
    assert_int_equal( *dst_mask, htons( *src_mask ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_vlan_pcp() {
  const uint8_t data = data_8bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val;

  {
    src = create_oxm_match_8( OXM_OF_VLAN_PCP, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_vlan_pcp( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, *src_val );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_ip_dscp() {
  const uint8_t data = data_8bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val;

  {
    src = create_oxm_match_8( OXM_OF_IP_DSCP, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_ip_dscp( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, *src_val );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_ip_ecn() {
  const uint8_t data = data_8bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val;

  {
    src = create_oxm_match_8( OXM_OF_IP_ECN, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_ip_ecn( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, *src_val );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_ip_proto() {
  const uint8_t data = data_8bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val;

  {
    src = create_oxm_match_8( OXM_OF_IP_PROTO, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_ip_proto( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, *src_val );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_ipv4_addr() {
  const uint32_t data = data_32bit;
  const uint32_t mask = mask_32bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint32_t *src_val, *dst_val, *src_mask, *dst_mask;

  {
    src = create_oxm_match_32( OXM_OF_IPV4_SRC, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_ipv4_addr( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htonl( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_32( OXM_OF_IPV4_DST, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_ipv4_addr( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htonl( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  tlvlen = TLVLEN_W( width );

  {
    src = create_oxm_match_32w( OXM_OF_IPV4_SRC_W, data, mask, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_ipv4_addr( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htonl( *src_val ) );
    assert_int_equal( *dst_mask, htonl( *src_mask ) );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_32w( OXM_OF_IPV4_SRC_W, data, mask, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_ipv4_addr( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htonl( *src_val ) );
    assert_int_equal( *dst_mask, htonl( *src_mask ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_tcp_port() {
  const uint16_t data = data_16bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint16_t *src_val, *dst_val;

  {
    src = create_oxm_match_16( OXM_OF_TCP_SRC, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_tcp_port( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htons( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_16( OXM_OF_TCP_DST, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_tcp_port( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htons( *src_val ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_udp_port() {
  const uint16_t data = data_16bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint16_t *src_val, *dst_val;

  {
    src = create_oxm_match_16( OXM_OF_UDP_SRC, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_udp_port( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htons( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_16( OXM_OF_UDP_DST, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_udp_port( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htons( *src_val ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_sctp_port() {
  const uint16_t data = data_16bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint16_t *src_val, *dst_val;

  {
    src = create_oxm_match_16( OXM_OF_SCTP_SRC, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_sctp_port( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htons( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_16( OXM_OF_SCTP_DST, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_sctp_port( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htons( *src_val ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_icmpv4_type() {
  const uint8_t data = data_8bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val;

  {
    src = create_oxm_match_8( OXM_OF_ICMPV4_TYPE, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_icmpv4_type( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, *src_val );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_icmpv4_code() {
  const uint8_t data = data_8bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val;

  {
    src = create_oxm_match_8( OXM_OF_ICMPV4_CODE, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_icmpv4_code( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, *src_val );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_arp_op() {
  const uint16_t data = data_16bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint16_t *src_val, *dst_val;

  {
    src = create_oxm_match_16( OXM_OF_ARP_OP, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_arp_op( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htons( *src_val ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_arp_pa() {
  const uint32_t data = data_32bit;
  const uint32_t mask = mask_32bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint32_t *src_val, *dst_val, *src_mask, *dst_mask;

  {
    src = create_oxm_match_32( OXM_OF_ARP_SPA, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_arp_pa( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htonl( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_32( OXM_OF_ARP_TPA, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_arp_pa( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htonl( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  tlvlen = TLVLEN_W( width );

  {
    src = create_oxm_match_32w( OXM_OF_ARP_SPA_W, data, mask, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_arp_pa( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htonl( *src_val ) );
    assert_int_equal( *dst_mask, htonl( *src_mask ) );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_32w( OXM_OF_ARP_TPA_W, data, mask, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_arp_pa( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htonl( *src_val ) );
    assert_int_equal( *dst_mask, htonl( *src_mask ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_arp_ha() {
  uint8_t data[6];
  uint8_t mask[6];
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  memcpy( data, data_48bit, sizeof( data ) );
  memcpy( mask, mask_48bit, sizeof( mask ) );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val, *src_mask, *dst_mask;

  {
    src = create_oxm_match_eth_addr( OXM_OF_ARP_SHA, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_arp_ha( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_eth_addr( OXM_OF_ARP_THA, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_arp_ha( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    xfree( src );
    xfree( dst );
  }

  tlvlen = TLVLEN_W( width );

  {
    src = create_oxm_match_eth_addr_w( OXM_OF_ARP_SHA_W, data, mask, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_arp_ha( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint8_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint8_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, htonl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    assert_memory_equal( dst_mask, src_mask, width );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_eth_addr_w( OXM_OF_ARP_THA_W, data, mask, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_arp_ha( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint8_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint8_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, htonl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    assert_memory_equal( dst_mask, src_mask, width );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_ipv6_addr() {
  struct in6_addr data;
  struct in6_addr mask;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  memcpy( &data, &data_128bit, sizeof( data ) );
  memcpy( &mask, &mask_128bit, sizeof( mask ) );

  oxm_match_header *src, *dst;
  struct in6_addr *src_val, *dst_val, *src_mask, *dst_mask;

  {
    src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_SRC, data, mask, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_ipv6_addr( dst, src );

    dst_val = ( struct in6_addr * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( struct in6_addr * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_DST, data, mask, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_ipv6_addr( dst, src );

    dst_val = ( struct in6_addr * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( struct in6_addr * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    xfree( src );
    xfree( dst );
  }

  tlvlen = TLVLEN_W( width );

  {
    src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_SRC_W, data, mask, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_ipv6_addr( dst, src );

    dst_val = ( struct in6_addr * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( struct in6_addr * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( struct in6_addr * ) ( ( char * ) dst_val + width );
    src_mask = ( struct in6_addr * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, htonl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    assert_memory_equal( dst_mask, src_mask, width );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_DST_W, data, mask, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_ipv6_addr( dst, src );

    dst_val = ( struct in6_addr * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( struct in6_addr * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( struct in6_addr * ) ( ( char * ) dst_val + width );
    src_mask = ( struct in6_addr * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, htonl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    assert_memory_equal( dst_mask, src_mask, width );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_ipv6_flabel() {
  const uint32_t data = data_32bit;
  const uint32_t mask = mask_32bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint32_t *src_val, *dst_val, *src_mask, *dst_mask;

  {
    src = create_oxm_match_32( OXM_OF_IPV6_FLABEL, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_ipv6_flabel( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htonl( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  tlvlen = TLVLEN_W( width );

  {
    src = create_oxm_match_32w( OXM_OF_IPV6_FLABEL_W, data, mask, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_ipv6_flabel( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htonl( *src_val ) );
    assert_int_equal( *dst_mask, htonl( *src_mask ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_icmpv6_type() {
  const uint8_t data = data_8bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val;

  {
    src = create_oxm_match_8( OXM_OF_ICMPV6_TYPE, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_icmpv6_type( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, *src_val );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_icmpv6_code() {
  const uint8_t data = data_8bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val;

  {
    src = create_oxm_match_8( OXM_OF_ICMPV6_CODE, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_icmpv6_code( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, *src_val );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_ipv6_nd_target() {
  struct in6_addr data;
  struct in6_addr mask;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  memcpy( &data, &data_128bit, sizeof( data ) );
  memcpy( &mask, &mask_128bit, sizeof( mask ) );

  oxm_match_header *src, *dst;
  struct in6_addr *src_val, *dst_val;

  {
    src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_ND_TARGET, data, mask, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_ipv6_nd_target( dst, src );

    dst_val = ( struct in6_addr * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( struct in6_addr * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_ipv6_nd_ll() {
  uint8_t data[6];
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  memcpy( data, data_48bit, sizeof( data ) );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val;

  {
    src = create_oxm_match_eth_addr( OXM_OF_IPV6_ND_SLL, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_ipv6_nd_ll( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_eth_addr( OXM_OF_IPV6_ND_TLL, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_ipv6_nd_ll( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_mpls_label() {
  const uint32_t data = data_32bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint32_t *src_val, *dst_val;

  {
    src = create_oxm_match_32( OXM_OF_MPLS_LABEL, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_mpls_label( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htonl( *src_val ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_mpls_tc() {
  const uint8_t data = data_8bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val;

  {
    src = create_oxm_match_8( OXM_OF_MPLS_TC, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_mpls_tc( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, *src_val );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_mpls_bos() {
  const uint8_t data = data_8bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val;

  {
    src = create_oxm_match_8( OXM_OF_MPLS_BOS, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_mpls_bos( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, *src_val );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_pbb_isid() {
  const uint32_t data = data_32bit;
  const uint32_t mask = mask_32bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint32_t *src_val, *dst_val, *src_mask, *dst_mask;

  {
    src = create_oxm_match_32( OXM_OF_PBB_ISID, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_pbb_isid( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htonl( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  tlvlen = TLVLEN_W( width );

  {
    src = create_oxm_match_32w( OXM_OF_PBB_ISID_W, data, mask, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_pbb_isid( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htonl( *src_val ) );
    assert_int_equal( *dst_mask, htonl( *src_mask ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_tunnel_id() {
  const uint64_t data = data_64bit;
  const uint64_t mask = mask_64bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint64_t *src_val, *dst_val, *src_mask, *dst_mask;

  {
    src = create_oxm_match_64( OXM_OF_TUNNEL_ID, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_tunnel_id( dst, src );

    dst_val = ( uint64_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint64_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_true( *dst_val == htonll( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  tlvlen = TLVLEN_W( width );

  {
    src = create_oxm_match_64w( OXM_OF_TUNNEL_ID_W, data, mask, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_tunnel_id( dst, src );

    dst_val = ( uint64_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint64_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint64_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint64_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, htonl( *src ) );
    assert_true( *dst_val == htonll( *src_val ) );
    assert_true( *dst_mask == htonll( *src_mask ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match_ipv6_exthdr() {
  const uint16_t data = data_16bit;
  const uint16_t mask = mask_16bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint16_t *src_val, *dst_val, *src_mask, *dst_mask;

  {
    src = create_oxm_match_16( OXM_OF_IPV6_EXTHDR, data, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_ipv6_exthdr( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htons( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  tlvlen = TLVLEN_W( width );

  {
    src = create_oxm_match_16w( OXM_OF_IPV6_EXTHDR_W, data, mask, false );
    dst = xcalloc( 1, tlvlen );

    hton_oxm_match_ipv6_exthdr( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint16_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint16_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, htonl( *src ) );
    assert_int_equal( *dst_val, htons( *src_val ) );
    assert_int_equal( *dst_mask, htons( *src_mask ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_hton_oxm_match() {
  {
    const uint32_t data = data_32bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint32_t *src_val, *dst_val;

    {
      src = create_oxm_match_32( OXM_OF_IN_PORT, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htonl( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_32( OXM_OF_IN_PHY_PORT, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htonl( *src_val ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint64_t data = data_64bit;
    const uint64_t mask = mask_64bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint64_t *src_val, *dst_val, *src_mask, *dst_mask;

    {
      src = create_oxm_match_64( OXM_OF_METADATA, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint64_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint64_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_true( *dst_val == htonll( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    tlvlen = TLVLEN_W( width );

    {
      src = create_oxm_match_64w( OXM_OF_METADATA_W, data, mask, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint64_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint64_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint64_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint64_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, htonl( *src ) );
      assert_true( *dst_val == htonll( *src_val ) );
      assert_true( *dst_mask == htonll( *src_mask ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    uint8_t data[6];
    uint8_t mask[6];
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    memcpy( data, data_48bit, sizeof( data ) );
    memcpy( mask, mask_48bit, sizeof( mask ) );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val, *src_mask, *dst_mask;

    {
      src = create_oxm_match_eth_addr( OXM_OF_ETH_DST, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_eth_addr( OXM_OF_ETH_SRC, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      xfree( src );
      xfree( dst );
    }

    tlvlen = TLVLEN_W( width );

    {
      src = create_oxm_match_eth_addr_w( OXM_OF_ETH_DST_W, data, mask, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint8_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint8_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, htonl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      assert_memory_equal( dst_mask, src_mask, width );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_eth_addr_w( OXM_OF_ETH_SRC_W, data, mask, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint8_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint8_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, htonl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      assert_memory_equal( dst_mask, src_mask, width );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint16_t data = data_16bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint16_t *src_val, *dst_val;

    {
      src = create_oxm_match_16( OXM_OF_ETH_TYPE, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htons( *src_val ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint16_t data = data_16bit;
    const uint16_t mask = mask_16bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint16_t *src_val, *dst_val, *src_mask, *dst_mask;

    {
      src = create_oxm_match_16( OXM_OF_VLAN_VID, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htons( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    tlvlen = TLVLEN_W( width );

    {
      src = create_oxm_match_16w( OXM_OF_VLAN_VID_W, data, mask, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint16_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint16_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htons( *src_val ) );
      assert_int_equal( *dst_mask, htons( *src_mask ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint8_t data = data_8bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val;

    {
      src = create_oxm_match_8( OXM_OF_VLAN_PCP, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, *src_val );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint8_t data = data_8bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val;

    {
      src = create_oxm_match_8( OXM_OF_IP_DSCP, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, *src_val );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint8_t data = data_8bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val;

    {
      src = create_oxm_match_8( OXM_OF_IP_ECN, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, *src_val );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint8_t data = data_8bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val;

    {
      src = create_oxm_match_8( OXM_OF_IP_PROTO, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, *src_val );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint32_t data = data_32bit;
    const uint32_t mask = mask_32bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint32_t *src_val, *dst_val, *src_mask, *dst_mask;

    {
      src = create_oxm_match_32( OXM_OF_IPV4_SRC, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htonl( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_32( OXM_OF_IPV4_DST, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htonl( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    tlvlen = TLVLEN_W( width );

    {
      src = create_oxm_match_32w( OXM_OF_IPV4_SRC_W, data, mask, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htonl( *src_val ) );
      assert_int_equal( *dst_mask, htonl( *src_mask ) );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_32w( OXM_OF_IPV4_SRC_W, data, mask, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htonl( *src_val ) );
      assert_int_equal( *dst_mask, htonl( *src_mask ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint16_t data = data_16bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint16_t *src_val, *dst_val;

    {
      src = create_oxm_match_16( OXM_OF_TCP_SRC, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htons( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_16( OXM_OF_TCP_DST, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htons( *src_val ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint16_t data = data_16bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint16_t *src_val, *dst_val;

    {
      src = create_oxm_match_16( OXM_OF_UDP_SRC, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htons( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_16( OXM_OF_UDP_DST, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htons( *src_val ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint16_t data = data_16bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint16_t *src_val, *dst_val;

    {
      src = create_oxm_match_16( OXM_OF_SCTP_SRC, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htons( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_16( OXM_OF_SCTP_DST, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htons( *src_val ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint8_t data = data_8bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val;

    {
      src = create_oxm_match_8( OXM_OF_ICMPV4_TYPE, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, *src_val );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint8_t data = data_8bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val;

    {
      src = create_oxm_match_8( OXM_OF_ICMPV4_CODE, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, *src_val );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint16_t data = data_16bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint16_t *src_val, *dst_val;

    {
      src = create_oxm_match_16( OXM_OF_ARP_OP, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htons( *src_val ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint32_t data = data_32bit;
    const uint32_t mask = mask_32bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint32_t *src_val, *dst_val, *src_mask, *dst_mask;

    {
      src = create_oxm_match_32( OXM_OF_ARP_SPA, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htonl( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_32( OXM_OF_ARP_TPA, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htonl( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    tlvlen = TLVLEN_W( width );

    {
      src = create_oxm_match_32w( OXM_OF_ARP_SPA_W, data, mask, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htonl( *src_val ) );
      assert_int_equal( *dst_mask, htonl( *src_mask ) );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_32w( OXM_OF_ARP_TPA_W, data, mask, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htonl( *src_val ) );
      assert_int_equal( *dst_mask, htonl( *src_mask ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    uint8_t data[6];
    uint8_t mask[6];
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    memcpy( data, data_48bit, sizeof( data ) );
    memcpy( mask, mask_48bit, sizeof( mask ) );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val, *src_mask, *dst_mask;

    {
      src = create_oxm_match_eth_addr( OXM_OF_ARP_SHA, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_eth_addr( OXM_OF_ARP_THA, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      xfree( src );
      xfree( dst );
    }

    tlvlen = TLVLEN_W( width );

    {
      src = create_oxm_match_eth_addr_w( OXM_OF_ARP_SHA_W, data, mask, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint8_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint8_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, htonl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      assert_memory_equal( dst_mask, src_mask, width );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_eth_addr_w( OXM_OF_ARP_THA_W, data, mask, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint8_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint8_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, htonl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      assert_memory_equal( dst_mask, src_mask, width );
      xfree( src );
      xfree( dst );
    }
  }
  {
    struct in6_addr data;
    struct in6_addr mask;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    memcpy( &data, &data_128bit, sizeof( data ) );
    memcpy( &mask, &mask_128bit, sizeof( mask ) );

    oxm_match_header *src, *dst;
    struct in6_addr *src_val, *dst_val, *src_mask, *dst_mask;

    {
      src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_SRC, data, mask, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( struct in6_addr * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( struct in6_addr * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_DST, data, mask, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( struct in6_addr * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( struct in6_addr * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      xfree( src );
      xfree( dst );
    }

    tlvlen = TLVLEN_W( width );

    {
      src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_SRC_W, data, mask, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( struct in6_addr * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( struct in6_addr * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( struct in6_addr * ) ( ( char * ) dst_val + width );
      src_mask = ( struct in6_addr * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, htonl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      assert_memory_equal( dst_mask, src_mask, width );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_DST_W, data, mask, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( struct in6_addr * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( struct in6_addr * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( struct in6_addr * ) ( ( char * ) dst_val + width );
      src_mask = ( struct in6_addr * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, htonl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      assert_memory_equal( dst_mask, src_mask, width );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint32_t data = data_32bit;
    const uint32_t mask = mask_32bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint32_t *src_val, *dst_val, *src_mask, *dst_mask;

    {
      src = create_oxm_match_32( OXM_OF_IPV6_FLABEL, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htonl( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    tlvlen = TLVLEN_W( width );

    {
      src = create_oxm_match_32w( OXM_OF_IPV6_FLABEL_W, data, mask, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htonl( *src_val ) );
      assert_int_equal( *dst_mask, htonl( *src_mask ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint8_t data = data_8bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val;

    {
      src = create_oxm_match_8( OXM_OF_ICMPV6_TYPE, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, *src_val );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint8_t data = data_8bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val;

    {
      src = create_oxm_match_8( OXM_OF_ICMPV6_CODE, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, *src_val );
      xfree( src );
      xfree( dst );
    }
  }
  {
    struct in6_addr data;
    struct in6_addr mask;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    memcpy( &data, &data_128bit, sizeof( data ) );
    memcpy( &mask, &mask_128bit, sizeof( mask ) );

    oxm_match_header *src, *dst;
    struct in6_addr *src_val, *dst_val;

    {
      src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_ND_TARGET, data, mask, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( struct in6_addr * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( struct in6_addr * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      xfree( src );
      xfree( dst );
    }
  }
  {
    uint8_t data[6];
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    memcpy( data, data_48bit, sizeof( data ) );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val;

    {
      src = create_oxm_match_eth_addr( OXM_OF_IPV6_ND_SLL, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_eth_addr( OXM_OF_IPV6_ND_TLL, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint32_t data = data_32bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint32_t *src_val, *dst_val;

    {
      src = create_oxm_match_32( OXM_OF_MPLS_LABEL, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htonl( *src_val ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint8_t data = data_8bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val;

    {
      src = create_oxm_match_8( OXM_OF_MPLS_TC, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, *src_val );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint8_t data = data_8bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val;

    {
      src = create_oxm_match_8( OXM_OF_MPLS_BOS, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, *src_val );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint32_t data = data_32bit;
    const uint32_t mask = mask_32bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint32_t *src_val, *dst_val, *src_mask, *dst_mask;

    {
      src = create_oxm_match_32( OXM_OF_PBB_ISID, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htonl( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    tlvlen = TLVLEN_W( width );

    {
      src = create_oxm_match_32w( OXM_OF_PBB_ISID_W, data, mask, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htonl( *src_val ) );
      assert_int_equal( *dst_mask, htonl( *src_mask ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint64_t data = data_64bit;
    const uint64_t mask = mask_64bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint64_t *src_val, *dst_val, *src_mask, *dst_mask;

    {
      src = create_oxm_match_64( OXM_OF_TUNNEL_ID, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint64_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint64_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_true( *dst_val == htonll( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    tlvlen = TLVLEN_W( width );

    {
      src = create_oxm_match_64w( OXM_OF_TUNNEL_ID_W, data, mask, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint64_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint64_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint64_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint64_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, htonl( *src ) );
      assert_true( *dst_val == htonll( *src_val ) );
      assert_true( *dst_mask == htonll( *src_mask ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint16_t data = data_16bit;
    const uint16_t mask = mask_16bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint16_t *src_val, *dst_val, *src_mask, *dst_mask;

    {
      src = create_oxm_match_16( OXM_OF_IPV6_EXTHDR, data, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htons( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    tlvlen = TLVLEN_W( width );

    {
      src = create_oxm_match_16w( OXM_OF_IPV6_EXTHDR_W, data, mask, false );
      dst = xcalloc( 1, tlvlen );

      hton_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint16_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint16_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, htonl( *src ) );
      assert_int_equal( *dst_val, htons( *src_val ) );
      assert_int_equal( *dst_mask, htons( *src_mask ) );
      xfree( src );
      xfree( dst );
    }
  }
}


static void
test_hton_oxm_match_with_undefined_match_type() {
  const uint32_t data = data_32bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;

  src = create_oxm_match_32( OXM_OF_IN_PORT, data, false );
  dst = xcalloc( 1, tlvlen );
  *src = OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, (OFPXMT_OFB_IPV6_EXTHDR + 1), 2);

  expect_assert_failure( hton_oxm_match( dst, src ) );

  xfree( src );
  xfree( dst );
}


char match_buf[4096];
char expected_match_buf[4096];
struct ofp_match *input_match = ( struct ofp_match * ) match_buf;
struct ofp_match *expected_match = ( struct ofp_match * ) expected_match_buf;


static void
create_ofp_match_helper_for_test_hton_match( oxm_match_header **match, oxm_match_header **expected, oxm_match_header *src ) {
  uint16_t len = ( uint16_t ) ( sizeof( oxm_match_header ) + OXM_LENGTH( *src ) );
  memcpy( *match, src, len );
  hton_oxm_match( *expected, src );
  *match = ( oxm_match_header * ) ( ( char * ) *match + len );
  *expected = ( oxm_match_header * ) ( ( char * ) *expected + len );

  input_match->length = ( uint16_t ) ( input_match->length + len );
  expected_match->length = htons( ( uint16_t ) ( ntohs( expected_match->length ) + len ) );

  xfree( src );
}


static void
test_hton_match() {
  oxm_match_header *src;
  oxm_match_header *match, *expected;

  memset( match_buf, 0, sizeof( match_buf ) );
  memset( expected_match_buf, 0, sizeof( expected_match_buf ) );

  input_match->type = OFPMT_OXM;
  input_match->length = offsetof( struct ofp_match, oxm_fields );
  expected_match->type = htons( OFPMT_OXM );
  expected_match->length = htons( offsetof( struct ofp_match, oxm_fields ) );

  match = ( oxm_match_header * ) input_match->oxm_fields;
  expected = ( oxm_match_header * ) expected_match->oxm_fields;

  src = create_oxm_match_32( OXM_OF_IN_PORT, data_32bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_32( OXM_OF_IN_PHY_PORT, data_32bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_64( OXM_OF_METADATA, data_64bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_64w( OXM_OF_METADATA_W, data_64bit, mask_64bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_eth_addr( OXM_OF_ETH_DST, data_48bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_eth_addr( OXM_OF_ETH_SRC, data_48bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_eth_addr_w( OXM_OF_ETH_DST_W, data_48bit, mask_48bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_eth_addr_w( OXM_OF_ETH_SRC_W, data_48bit, mask_48bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_16( OXM_OF_ETH_TYPE, data_16bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_16( OXM_OF_VLAN_VID, data_16bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_16w( OXM_OF_VLAN_VID_W, data_16bit, mask_16bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_8( OXM_OF_VLAN_PCP, data_8bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_8( OXM_OF_IP_DSCP, data_8bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_8( OXM_OF_IP_ECN, data_8bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_8( OXM_OF_IP_PROTO, data_8bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_32( OXM_OF_IPV4_SRC, data_32bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_32( OXM_OF_IPV4_DST, data_32bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_32w( OXM_OF_IPV4_SRC_W, data_32bit, mask_32bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_32w( OXM_OF_IPV4_SRC_W, data_32bit, mask_32bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_16( OXM_OF_TCP_SRC, data_16bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_16( OXM_OF_TCP_DST, data_16bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_16( OXM_OF_UDP_SRC, data_16bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_16( OXM_OF_UDP_DST, data_16bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_16( OXM_OF_SCTP_SRC, data_16bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_16( OXM_OF_SCTP_DST, data_16bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_8( OXM_OF_ICMPV4_TYPE, data_8bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_8( OXM_OF_ICMPV4_CODE, data_8bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_16( OXM_OF_ARP_OP, data_16bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_32( OXM_OF_ARP_SPA, data_32bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_32( OXM_OF_ARP_TPA, data_32bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_32w( OXM_OF_ARP_SPA_W, data_32bit, mask_32bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_32w( OXM_OF_ARP_TPA_W, data_32bit, mask_32bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_eth_addr( OXM_OF_ARP_SHA, data_48bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_eth_addr( OXM_OF_ARP_THA, data_48bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_eth_addr_w( OXM_OF_ARP_SHA_W, data_48bit, mask_48bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_eth_addr_w( OXM_OF_ARP_THA_W, data_48bit, mask_48bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_SRC, data_128bit, mask_128bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_DST, data_128bit, mask_128bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_SRC_W, data_128bit, mask_128bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_DST_W, data_128bit, mask_128bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_32( OXM_OF_IPV6_FLABEL, data_32bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_32w( OXM_OF_IPV6_FLABEL_W, data_32bit, mask_32bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_8( OXM_OF_ICMPV6_TYPE, data_8bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_8( OXM_OF_ICMPV6_CODE, data_8bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_ND_TARGET, data_128bit, mask_128bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_eth_addr( OXM_OF_IPV6_ND_SLL, data_48bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_eth_addr( OXM_OF_IPV6_ND_TLL, data_48bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_32( OXM_OF_MPLS_LABEL, data_32bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_8( OXM_OF_MPLS_TC, data_8bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_8( OXM_OF_MPLS_BOS, data_8bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_32( OXM_OF_PBB_ISID, data_32bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_32w( OXM_OF_PBB_ISID_W, data_32bit, mask_32bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_64( OXM_OF_TUNNEL_ID, data_64bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_64w( OXM_OF_TUNNEL_ID_W, data_64bit, mask_64bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_16( OXM_OF_IPV6_EXTHDR, data_16bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );
  src = create_oxm_match_16w( OXM_OF_IPV6_EXTHDR_W, data_16bit, mask_16bit, false );
  create_ofp_match_helper_for_test_hton_match( &match, &expected, src );

  uint16_t total_len = ( uint16_t ) ( input_match->length + PADLEN_TO_64( input_match->length ) );

  struct ofp_match *output_match = xcalloc( 1, total_len );
  hton_match( output_match, input_match );

  assert_memory_equal( output_match, expected_match, total_len );

  xfree( output_match );
}


static void
test_hton_match_with_undefined_match_type() {
  uint16_t oxm_len = ( uint16_t ) ( sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_IPV6_EXTHDR ) );
  uint16_t match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields ) + oxm_len );
  uint16_t alloc_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );

  struct ofp_match *match = xcalloc( 1, alloc_len );
  struct ofp_match *expected = xcalloc( 1, alloc_len );
  match->type = OFPMT_OXM;
  match->length = match_len;

  oxm_match_header *oxm = ( oxm_match_header * ) match->oxm_fields;
  *oxm = OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, ( OFPXMT_OFB_IPV6_EXTHDR + 1 ), 2);

  expect_assert_failure( hton_match( expected, match ) );

  xfree( match );
  xfree( expected );
}


static void
test_ntoh_oxm_match_in_port() {
  const uint32_t data = data_32bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint32_t *src_val, *dst_val;

  {
    src = create_oxm_match_32( OXM_OF_IN_PORT, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_in_port( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohl( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_32( OXM_OF_IN_PHY_PORT, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_in_port( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohl( *src_val ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_metadata() {
  const uint64_t data = data_64bit;
  const uint64_t mask = mask_64bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint64_t *src_val, *dst_val, *src_mask, *dst_mask;

  {
    src = create_oxm_match_64( OXM_OF_METADATA, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_metadata( dst, src );

    dst_val = ( uint64_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint64_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_true( *dst_val == ntohll( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  tlvlen = TLVLEN_W( width );

  {
    src = create_oxm_match_64w( OXM_OF_METADATA_W, data, mask, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_metadata( dst, src );

    dst_val = ( uint64_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint64_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint64_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint64_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_true( *dst_val == ntohll( *src_val ) );
    assert_true( *dst_mask == ntohll( *src_mask ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_eth_addr() {
  uint8_t data[6];
  uint8_t mask[6];
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  memcpy( data, data_48bit, sizeof( data ) );
  memcpy( mask, mask_48bit, sizeof( mask ) );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val, *src_mask, *dst_mask;

  {
    src = create_oxm_match_eth_addr( OXM_OF_ETH_DST, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_eth_addr( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_eth_addr( OXM_OF_ETH_SRC, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_eth_addr( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    xfree( src );
    xfree( dst );
  }

  tlvlen = TLVLEN_W( width );

  {
    src = create_oxm_match_eth_addr_w( OXM_OF_ETH_DST_W, data, mask, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_eth_addr( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint8_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint8_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    assert_memory_equal( dst_mask, src_mask, width );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_eth_addr_w( OXM_OF_ETH_SRC_W, data, mask, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_eth_addr( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint8_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint8_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    assert_memory_equal( dst_mask, src_mask, width );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_eth_type() {
  const uint16_t data = data_16bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint16_t *src_val, *dst_val;

  {
    src = create_oxm_match_16( OXM_OF_ETH_TYPE, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_eth_type( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohs( *src_val ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_vlan_vid() {
  const uint16_t data = data_16bit;
  const uint16_t mask = mask_16bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint16_t *src_val, *dst_val, *src_mask, *dst_mask;

  {
    src = create_oxm_match_16( OXM_OF_VLAN_VID, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_vlan_vid( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohs( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  tlvlen = TLVLEN_W( width );

  {
    src = create_oxm_match_16w( OXM_OF_VLAN_VID_W, data, mask, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_vlan_vid( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint16_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint16_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohs( *src_val ) );
    assert_int_equal( *dst_mask, ntohs( *src_mask ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_vlan_pcp() {
  const uint8_t data = data_8bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val;

  {
    src = create_oxm_match_8( OXM_OF_VLAN_PCP, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_vlan_pcp( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, *src_val );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_ip_dscp() {
  const uint8_t data = data_8bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val;

  {
    src = create_oxm_match_8( OXM_OF_IP_DSCP, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_ip_dscp( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, *src_val );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_ip_ecn() {
  const uint8_t data = data_8bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val;

  {
    src = create_oxm_match_8( OXM_OF_IP_ECN, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_ip_ecn( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, *src_val );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_ip_proto() {
  const uint8_t data = data_8bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val;

  {
    src = create_oxm_match_8( OXM_OF_IP_PROTO, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_ip_proto( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, *src_val );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_ipv4_addr() {
  const uint32_t data = data_32bit;
  const uint32_t mask = mask_32bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint32_t *src_val, *dst_val, *src_mask, *dst_mask;

  {
    src = create_oxm_match_32( OXM_OF_IPV4_SRC, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_ipv4_addr( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohl( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_32( OXM_OF_IPV4_DST, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_ipv4_addr( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohl( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  tlvlen = TLVLEN_W( width );

  {
    src = create_oxm_match_32w( OXM_OF_IPV4_SRC_W, data, mask, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_ipv4_addr( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohl( *src_val ) );
    assert_int_equal( *dst_mask, ntohl( *src_mask ) );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_32w( OXM_OF_IPV4_SRC_W, data, mask, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_ipv4_addr( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohl( *src_val ) );
    assert_int_equal( *dst_mask, ntohl( *src_mask ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_tcp_port() {
  const uint16_t data = data_16bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint16_t *src_val, *dst_val;

  {
    src = create_oxm_match_16( OXM_OF_TCP_SRC, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_tcp_port( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohs( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_16( OXM_OF_TCP_DST, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_tcp_port( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohs( *src_val ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_udp_port() {
  const uint16_t data = data_16bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint16_t *src_val, *dst_val;

  {
    src = create_oxm_match_16( OXM_OF_UDP_SRC, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_udp_port( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohs( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_16( OXM_OF_UDP_DST, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_udp_port( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohs( *src_val ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_sctp_port() {
  const uint16_t data = data_16bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint16_t *src_val, *dst_val;

  {
    src = create_oxm_match_16( OXM_OF_SCTP_SRC, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_sctp_port( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohs( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_16( OXM_OF_SCTP_DST, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_sctp_port( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohs( *src_val ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_icmpv4_type() {
  const uint8_t data = data_8bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val;

  {
    src = create_oxm_match_8( OXM_OF_ICMPV4_TYPE, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_icmpv4_type( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, *src_val );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_icmpv4_code() {
  const uint8_t data = data_8bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val;

  {
    src = create_oxm_match_8( OXM_OF_ICMPV4_CODE, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_icmpv4_code( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, *src_val );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_arp_op() {
  const uint16_t data = data_16bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint16_t *src_val, *dst_val;

  {
    src = create_oxm_match_16( OXM_OF_ARP_OP, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_arp_op( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohs( *src_val ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_arp_pa() {
  const uint32_t data = data_32bit;
  const uint32_t mask = mask_32bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint32_t *src_val, *dst_val, *src_mask, *dst_mask;

  {
    src = create_oxm_match_32( OXM_OF_ARP_SPA, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_arp_pa( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohl( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_32( OXM_OF_ARP_TPA, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_arp_pa( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohl( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  tlvlen = TLVLEN_W( width );

  {
    src = create_oxm_match_32w( OXM_OF_ARP_SPA_W, data, mask, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_arp_pa( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohl( *src_val ) );
    assert_int_equal( *dst_mask, ntohl( *src_mask ) );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_32w( OXM_OF_ARP_TPA_W, data, mask, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_arp_pa( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohl( *src_val ) );
    assert_int_equal( *dst_mask, ntohl( *src_mask ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_arp_ha() {
  uint8_t data[6];
  uint8_t mask[6];
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  memcpy( data, data_48bit, sizeof( data ) );
  memcpy( mask, mask_48bit, sizeof( mask ) );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val, *src_mask, *dst_mask;

  {
    src = create_oxm_match_eth_addr( OXM_OF_ARP_SHA, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_arp_ha( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_eth_addr( OXM_OF_ARP_THA, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_arp_ha( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    xfree( src );
    xfree( dst );
  }

  tlvlen = TLVLEN_W( width );

  {
    src = create_oxm_match_eth_addr_w( OXM_OF_ARP_SHA_W, data, mask, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_arp_ha( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint8_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint8_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    assert_memory_equal( dst_mask, src_mask, width );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_eth_addr_w( OXM_OF_ARP_THA_W, data, mask, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_arp_ha( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint8_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint8_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    assert_memory_equal( dst_mask, src_mask, width );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_ipv6_addr() {
  struct in6_addr data;
  struct in6_addr mask;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  memcpy( &data, &data_128bit, sizeof( data ) );
  memcpy( &mask, &mask_128bit, sizeof( mask ) );

  oxm_match_header *src, *dst;
  struct in6_addr *src_val, *dst_val, *src_mask, *dst_mask;

  {
    src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_SRC, data, mask, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_ipv6_addr( dst, src );

    dst_val = ( struct in6_addr * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( struct in6_addr * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_DST, data, mask, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_ipv6_addr( dst, src );

    dst_val = ( struct in6_addr * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( struct in6_addr * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    xfree( src );
    xfree( dst );
  }

  tlvlen = TLVLEN_W( width );

  {
    src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_SRC_W, data, mask, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_ipv6_addr( dst, src );

    dst_val = ( struct in6_addr * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( struct in6_addr * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( struct in6_addr * ) ( ( char * ) dst_val + width );
    src_mask = ( struct in6_addr * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    assert_memory_equal( dst_mask, src_mask, width );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_DST_W, data, mask, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_ipv6_addr( dst, src );

    dst_val = ( struct in6_addr * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( struct in6_addr * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( struct in6_addr * ) ( ( char * ) dst_val + width );
    src_mask = ( struct in6_addr * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    assert_memory_equal( dst_mask, src_mask, width );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_ipv6_flabel() {
  const uint32_t data = data_32bit;
  const uint32_t mask = mask_32bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint32_t *src_val, *dst_val, *src_mask, *dst_mask;

  {
    src = create_oxm_match_32( OXM_OF_IPV6_FLABEL, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_ipv6_flabel( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohl( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  tlvlen = TLVLEN_W( width );

  {
    src = create_oxm_match_32w( OXM_OF_IPV6_FLABEL_W, data, mask, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_ipv6_flabel( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohl( *src_val ) );
    assert_int_equal( *dst_mask, ntohl( *src_mask ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_icmpv6_type() {
  const uint8_t data = data_8bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val;

  {
    src = create_oxm_match_8( OXM_OF_ICMPV6_TYPE, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_icmpv6_type( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, *src_val );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_icmpv6_code() {
  const uint8_t data = data_8bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val;

  {
    src = create_oxm_match_8( OXM_OF_ICMPV6_CODE, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_icmpv6_code( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, *src_val );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_ipv6_nd_target() {
  struct in6_addr data;
  struct in6_addr mask;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  memcpy( &data, &data_128bit, sizeof( data ) );
  memcpy( &mask, &mask_128bit, sizeof( mask ) );

  oxm_match_header *src, *dst;
  struct in6_addr *src_val, *dst_val;

  {
    src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_ND_TARGET, data, mask, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_ipv6_nd_target( dst, src );

    dst_val = ( struct in6_addr * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( struct in6_addr * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_ipv6_nd_ll() {
  uint8_t data[6];
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  memcpy( data, data_48bit, sizeof( data ) );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val;

  {
    src = create_oxm_match_eth_addr( OXM_OF_IPV6_ND_SLL, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_ipv6_nd_ll( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    xfree( src );
    xfree( dst );
  }

  {
    src = create_oxm_match_eth_addr( OXM_OF_IPV6_ND_TLL, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_ipv6_nd_ll( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_memory_equal( dst_val, src_val, width );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_mpls_label() {
  const uint32_t data = data_32bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint32_t *src_val, *dst_val;

  {
    src = create_oxm_match_32( OXM_OF_MPLS_LABEL, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_mpls_label( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohl( *src_val ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_mpls_tc() {
  const uint8_t data = data_8bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val;

  {
    src = create_oxm_match_8( OXM_OF_MPLS_TC, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_mpls_tc( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, *src_val );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_mpls_bos() {
  const uint8_t data = data_8bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint8_t *src_val, *dst_val;

  {
    src = create_oxm_match_8( OXM_OF_MPLS_BOS, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_mpls_bos( dst, src );

    dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, *src_val );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_pbb_isid() {
  const uint32_t data = data_32bit;
  const uint32_t mask = mask_32bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint32_t *src_val, *dst_val, *src_mask, *dst_mask;

  {
    src = create_oxm_match_32( OXM_OF_PBB_ISID, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_pbb_isid( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohl( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  tlvlen = TLVLEN_W( width );

  {
    src = create_oxm_match_32w( OXM_OF_PBB_ISID_W, data, mask, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_pbb_isid( dst, src );

    dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohl( *src_val ) );
    assert_int_equal( *dst_mask, ntohl( *src_mask ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_tunnel_id() {
  const uint64_t data = data_64bit;
  const uint64_t mask = mask_64bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint64_t *src_val, *dst_val, *src_mask, *dst_mask;

  {
    src = create_oxm_match_64( OXM_OF_TUNNEL_ID, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_tunnel_id( dst, src );

    dst_val = ( uint64_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint64_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_true( *dst_val == ntohll( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  tlvlen = TLVLEN_W( width );

  {
    src = create_oxm_match_64w( OXM_OF_TUNNEL_ID_W, data, mask, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_tunnel_id( dst, src );

    dst_val = ( uint64_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint64_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint64_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint64_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_true( *dst_val == ntohll( *src_val ) );
    assert_true( *dst_mask == ntohll( *src_mask ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match_ipv6_exthdr() {
  const uint16_t data = data_16bit;
  const uint16_t mask = mask_16bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;
  uint16_t *src_val, *dst_val, *src_mask, *dst_mask;

  {
    src = create_oxm_match_16( OXM_OF_IPV6_EXTHDR, data, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_ipv6_exthdr( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohs( *src_val ) );
    xfree( src );
    xfree( dst );
  }

  tlvlen = TLVLEN_W( width );

  {
    src = create_oxm_match_16w( OXM_OF_IPV6_EXTHDR_W, data, mask, true );
    dst = xcalloc( 1, tlvlen );

    ntoh_oxm_match_ipv6_exthdr( dst, src );

    dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
    src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
    dst_mask = ( uint16_t * ) ( ( char * ) dst_val + width );
    src_mask = ( uint16_t * ) ( ( char * ) src_val + width );
    assert_int_equal( *dst, ntohl( *src ) );
    assert_int_equal( *dst_val, ntohs( *src_val ) );
    assert_int_equal( *dst_mask, ntohs( *src_mask ) );
    xfree( src );
    xfree( dst );
  }
}


static void
test_ntoh_oxm_match() {
  {
    const uint32_t data = data_32bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint32_t *src_val, *dst_val;

    {
      src = create_oxm_match_32( OXM_OF_IN_PORT, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohl( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_32( OXM_OF_IN_PHY_PORT, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohl( *src_val ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint64_t data = data_64bit;
    const uint64_t mask = mask_64bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint64_t *src_val, *dst_val, *src_mask, *dst_mask;

    {
      src = create_oxm_match_64( OXM_OF_METADATA, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint64_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint64_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_true( *dst_val == ntohll( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    tlvlen = TLVLEN_W( width );

    {
      src = create_oxm_match_64w( OXM_OF_METADATA_W, data, mask, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint64_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint64_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint64_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint64_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_true( *dst_val == ntohll( *src_val ) );
      assert_true( *dst_mask == ntohll( *src_mask ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    uint8_t data[6];
    uint8_t mask[6];
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    memcpy( data, data_48bit, sizeof( data ) );
    memcpy( mask, mask_48bit, sizeof( mask ) );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val, *src_mask, *dst_mask;

    {
      src = create_oxm_match_eth_addr( OXM_OF_ETH_DST, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_eth_addr( OXM_OF_ETH_SRC, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      xfree( src );
      xfree( dst );
    }

    tlvlen = TLVLEN_W( width );

    {
      src = create_oxm_match_eth_addr_w( OXM_OF_ETH_DST_W, data, mask, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint8_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint8_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      assert_memory_equal( dst_mask, src_mask, width );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_eth_addr_w( OXM_OF_ETH_SRC_W, data, mask, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint8_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint8_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      assert_memory_equal( dst_mask, src_mask, width );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint16_t data = data_16bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint16_t *src_val, *dst_val;

    {
      src = create_oxm_match_16( OXM_OF_ETH_TYPE, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohs( *src_val ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint16_t data = data_16bit;
    const uint16_t mask = mask_16bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint16_t *src_val, *dst_val, *src_mask, *dst_mask;

    {
      src = create_oxm_match_16( OXM_OF_VLAN_VID, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohs( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    tlvlen = TLVLEN_W( width );

    {
      src = create_oxm_match_16w( OXM_OF_VLAN_VID_W, data, mask, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint16_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint16_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohs( *src_val ) );
      assert_int_equal( *dst_mask, ntohs( *src_mask ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint8_t data = data_8bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val;

    {
      src = create_oxm_match_8( OXM_OF_VLAN_PCP, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, *src_val );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint8_t data = data_8bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val;

    {
      src = create_oxm_match_8( OXM_OF_IP_DSCP, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, *src_val );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint8_t data = data_8bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val;

    {
      src = create_oxm_match_8( OXM_OF_IP_ECN, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, *src_val );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint8_t data = data_8bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val;

    {
      src = create_oxm_match_8( OXM_OF_IP_PROTO, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, *src_val );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint32_t data = data_32bit;
    const uint32_t mask = mask_32bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint32_t *src_val, *dst_val, *src_mask, *dst_mask;

    {
      src = create_oxm_match_32( OXM_OF_IPV4_SRC, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohl( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_32( OXM_OF_IPV4_DST, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohl( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    tlvlen = TLVLEN_W( width );

    {
      src = create_oxm_match_32w( OXM_OF_IPV4_SRC_W, data, mask, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohl( *src_val ) );
      assert_int_equal( *dst_mask, ntohl( *src_mask ) );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_32w( OXM_OF_IPV4_SRC_W, data, mask, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohl( *src_val ) );
      assert_int_equal( *dst_mask, ntohl( *src_mask ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint16_t data = data_16bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint16_t *src_val, *dst_val;

    {
      src = create_oxm_match_16( OXM_OF_TCP_SRC, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohs( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_16( OXM_OF_TCP_DST, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohs( *src_val ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint16_t data = data_16bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint16_t *src_val, *dst_val;

    {
      src = create_oxm_match_16( OXM_OF_UDP_SRC, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohs( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_16( OXM_OF_UDP_DST, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohs( *src_val ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint16_t data = data_16bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint16_t *src_val, *dst_val;

    {
      src = create_oxm_match_16( OXM_OF_SCTP_SRC, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohs( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_16( OXM_OF_SCTP_DST, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohs( *src_val ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint8_t data = data_8bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val;

    {
      src = create_oxm_match_8( OXM_OF_ICMPV4_TYPE, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, *src_val );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint8_t data = data_8bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val;

    {
      src = create_oxm_match_8( OXM_OF_ICMPV4_CODE, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, *src_val );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint16_t data = data_16bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint16_t *src_val, *dst_val;

    {
      src = create_oxm_match_16( OXM_OF_ARP_OP, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohs( *src_val ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint32_t data = data_32bit;
    const uint32_t mask = mask_32bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint32_t *src_val, *dst_val, *src_mask, *dst_mask;

    {
      src = create_oxm_match_32( OXM_OF_ARP_SPA, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohl( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_32( OXM_OF_ARP_TPA, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohl( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    tlvlen = TLVLEN_W( width );

    {
      src = create_oxm_match_32w( OXM_OF_ARP_SPA_W, data, mask, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohl( *src_val ) );
      assert_int_equal( *dst_mask, ntohl( *src_mask ) );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_32w( OXM_OF_ARP_TPA_W, data, mask, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohl( *src_val ) );
      assert_int_equal( *dst_mask, ntohl( *src_mask ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    uint8_t data[6];
    uint8_t mask[6];
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    memcpy( data, data_48bit, sizeof( data ) );
    memcpy( mask, mask_48bit, sizeof( mask ) );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val, *src_mask, *dst_mask;

    {
      src = create_oxm_match_eth_addr( OXM_OF_ARP_SHA, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_eth_addr( OXM_OF_ARP_THA, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      xfree( src );
      xfree( dst );
    }

    tlvlen = TLVLEN_W( width );

    {
      src = create_oxm_match_eth_addr_w( OXM_OF_ARP_SHA_W, data, mask, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint8_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint8_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      assert_memory_equal( dst_mask, src_mask, width );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_eth_addr_w( OXM_OF_ARP_THA_W, data, mask, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint8_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint8_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      assert_memory_equal( dst_mask, src_mask, width );
      xfree( src );
      xfree( dst );
    }
  }
  {
    struct in6_addr data;
    struct in6_addr mask;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    memcpy( &data, &data_128bit, sizeof( data ) );
    memcpy( &mask, &mask_128bit, sizeof( mask ) );

    oxm_match_header *src, *dst;
    struct in6_addr *src_val, *dst_val, *src_mask, *dst_mask;

    {
      src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_SRC, data, mask, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( struct in6_addr * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( struct in6_addr * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_DST, data, mask, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( struct in6_addr * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( struct in6_addr * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      xfree( src );
      xfree( dst );
    }

    tlvlen = TLVLEN_W( width );

    {
      src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_SRC_W, data, mask, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( struct in6_addr * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( struct in6_addr * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( struct in6_addr * ) ( ( char * ) dst_val + width );
      src_mask = ( struct in6_addr * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      assert_memory_equal( dst_mask, src_mask, width );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_DST_W, data, mask, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( struct in6_addr * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( struct in6_addr * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( struct in6_addr * ) ( ( char * ) dst_val + width );
      src_mask = ( struct in6_addr * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      assert_memory_equal( dst_mask, src_mask, width );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint32_t data = data_32bit;
    const uint32_t mask = mask_32bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint32_t *src_val, *dst_val, *src_mask, *dst_mask;

    {
      src = create_oxm_match_32( OXM_OF_IPV6_FLABEL, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohl( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    tlvlen = TLVLEN_W( width );

    {
      src = create_oxm_match_32w( OXM_OF_IPV6_FLABEL_W, data, mask, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohl( *src_val ) );
      assert_int_equal( *dst_mask, ntohl( *src_mask ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint8_t data = data_8bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val;

    {
      src = create_oxm_match_8( OXM_OF_ICMPV6_TYPE, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, *src_val );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint8_t data = data_8bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val;

    {
      src = create_oxm_match_8( OXM_OF_ICMPV6_CODE, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, *src_val );
      xfree( src );
      xfree( dst );
    }
  }
  {
    struct in6_addr data;
    struct in6_addr mask;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    memcpy( &data, &data_128bit, sizeof( data ) );
    memcpy( &mask, &mask_128bit, sizeof( mask ) );

    oxm_match_header *src, *dst;
    struct in6_addr *src_val, *dst_val;

    {
      src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_ND_TARGET, data, mask, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( struct in6_addr * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( struct in6_addr * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      xfree( src );
      xfree( dst );
    }
  }
  {
    uint8_t data[6];
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    memcpy( data, data_48bit, sizeof( data ) );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val;

    {
      src = create_oxm_match_eth_addr( OXM_OF_IPV6_ND_SLL, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      xfree( src );
      xfree( dst );
    }

    {
      src = create_oxm_match_eth_addr( OXM_OF_IPV6_ND_TLL, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_memory_equal( dst_val, src_val, width );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint32_t data = data_32bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint32_t *src_val, *dst_val;

    {
      src = create_oxm_match_32( OXM_OF_MPLS_LABEL, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohl( *src_val ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint8_t data = data_8bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val;

    {
      src = create_oxm_match_8( OXM_OF_MPLS_TC, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, *src_val );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint8_t data = data_8bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint8_t *src_val, *dst_val;

    {
      src = create_oxm_match_8( OXM_OF_MPLS_BOS, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint8_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint8_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, *src_val );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint32_t data = data_32bit;
    const uint32_t mask = mask_32bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint32_t *src_val, *dst_val, *src_mask, *dst_mask;

    {
      src = create_oxm_match_32( OXM_OF_PBB_ISID, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohl( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    tlvlen = TLVLEN_W( width );

    {
      src = create_oxm_match_32w( OXM_OF_PBB_ISID_W, data, mask, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint32_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint32_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint32_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint32_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohl( *src_val ) );
      assert_int_equal( *dst_mask, ntohl( *src_mask ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint64_t data = data_64bit;
    const uint64_t mask = mask_64bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint64_t *src_val, *dst_val, *src_mask, *dst_mask;

    {
      src = create_oxm_match_64( OXM_OF_TUNNEL_ID, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint64_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint64_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_true( *dst_val == ntohll( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    tlvlen = TLVLEN_W( width );

    {
      src = create_oxm_match_64w( OXM_OF_TUNNEL_ID_W, data, mask, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint64_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint64_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint64_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint64_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_true( *dst_val == ntohll( *src_val ) );
      assert_true( *dst_mask == ntohll( *src_mask ) );
      xfree( src );
      xfree( dst );
    }
  }
  {
    const uint16_t data = data_16bit;
    const uint16_t mask = mask_16bit;
    const uint16_t width = sizeof( data );
    uint16_t tlvlen = TLVLEN( width );

    oxm_match_header *src, *dst;
    uint16_t *src_val, *dst_val, *src_mask, *dst_mask;

    {
      src = create_oxm_match_16( OXM_OF_IPV6_EXTHDR, data, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohs( *src_val ) );
      xfree( src );
      xfree( dst );
    }

    tlvlen = TLVLEN_W( width );

    {
      src = create_oxm_match_16w( OXM_OF_IPV6_EXTHDR_W, data, mask, true );
      dst = xcalloc( 1, tlvlen );

      ntoh_oxm_match( dst, src );

      dst_val = ( uint16_t * ) ( ( char * ) dst + sizeof( oxm_match_header ) );
      src_val = ( uint16_t * ) ( ( char * ) src + sizeof( oxm_match_header ) );
      dst_mask = ( uint16_t * ) ( ( char * ) dst_val + width );
      src_mask = ( uint16_t * ) ( ( char * ) src_val + width );
      assert_int_equal( *dst, ntohl( *src ) );
      assert_int_equal( *dst_val, ntohs( *src_val ) );
      assert_int_equal( *dst_mask, ntohs( *src_mask ) );
      xfree( src );
      xfree( dst );
    }
  }
}


static void
test_ntoh_oxm_match_with_undefined_match_type() {
  const uint32_t data = data_32bit;
  const uint16_t width = sizeof( data );
  uint16_t tlvlen = TLVLEN( width );

  oxm_match_header *src, *dst;

  src = create_oxm_match_32( OXM_OF_IN_PORT, data, true );
  dst = xcalloc( 1, tlvlen );
  *src = htonl( OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, (OFPXMT_OFB_IPV6_EXTHDR + 1), 2) );

  expect_assert_failure( ntoh_oxm_match( dst, src ) );

  xfree( src );
  xfree( dst );
}


static void
create_ofp_match_helper_for_test_ntoh_match( oxm_match_header **match, oxm_match_header **expected, oxm_match_header *src ) {
  uint16_t len = ( uint16_t ) ( sizeof( oxm_match_header ) + OXM_LENGTH( ntohl( *src ) ) );
  memcpy( *match, src, len );
  ntoh_oxm_match( *expected, src );
  *match = ( oxm_match_header * ) ( ( char * ) *match + len );
  *expected = ( oxm_match_header * ) ( ( char * ) *expected + len );

  input_match->length = htons( ( uint16_t ) ( ntohs( input_match->length ) + len ) );
  expected_match->length = ( uint16_t ) ( expected_match->length + len );

  xfree( src );
}


static void
test_ntoh_match() {
  oxm_match_header *src;
  oxm_match_header *match, *expected;

  memset( match_buf, 0, sizeof( match_buf ) );
  memset( expected_match_buf, 0, sizeof( expected_match_buf ) );

  input_match->type = htons( OFPMT_OXM );
  input_match->length = htons( offsetof( struct ofp_match, oxm_fields ) );
  expected_match->type = OFPMT_OXM;
  expected_match->length = offsetof( struct ofp_match, oxm_fields );

  match = ( oxm_match_header * ) input_match->oxm_fields;
  expected = ( oxm_match_header * ) expected_match->oxm_fields;

  src = create_oxm_match_32( OXM_OF_IN_PORT, data_32bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_32( OXM_OF_IN_PHY_PORT, data_32bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_64( OXM_OF_METADATA, data_64bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_64w( OXM_OF_METADATA_W, data_64bit, mask_64bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_eth_addr( OXM_OF_ETH_DST, data_48bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_eth_addr( OXM_OF_ETH_SRC, data_48bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_eth_addr_w( OXM_OF_ETH_DST_W, data_48bit, mask_48bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_eth_addr_w( OXM_OF_ETH_SRC_W, data_48bit, mask_48bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_16( OXM_OF_ETH_TYPE, data_16bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_16( OXM_OF_VLAN_VID, data_16bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_16w( OXM_OF_VLAN_VID_W, data_16bit, mask_16bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_8( OXM_OF_VLAN_PCP, data_8bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_8( OXM_OF_IP_DSCP, data_8bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_8( OXM_OF_IP_ECN, data_8bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_8( OXM_OF_IP_PROTO, data_8bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_32( OXM_OF_IPV4_SRC, data_32bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_32( OXM_OF_IPV4_DST, data_32bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_32w( OXM_OF_IPV4_SRC_W, data_32bit, mask_32bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_32w( OXM_OF_IPV4_SRC_W, data_32bit, mask_32bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_16( OXM_OF_TCP_SRC, data_16bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_16( OXM_OF_TCP_DST, data_16bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_16( OXM_OF_UDP_SRC, data_16bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_16( OXM_OF_UDP_DST, data_16bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_16( OXM_OF_SCTP_SRC, data_16bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_16( OXM_OF_SCTP_DST, data_16bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_8( OXM_OF_ICMPV4_TYPE, data_8bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_8( OXM_OF_ICMPV4_CODE, data_8bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_16( OXM_OF_ARP_OP, data_16bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_32( OXM_OF_ARP_SPA, data_32bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_32( OXM_OF_ARP_TPA, data_32bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_32w( OXM_OF_ARP_SPA_W, data_32bit, mask_32bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_32w( OXM_OF_ARP_TPA_W, data_32bit, mask_32bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_eth_addr( OXM_OF_ARP_SHA, data_48bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_eth_addr( OXM_OF_ARP_THA, data_48bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_eth_addr_w( OXM_OF_ARP_SHA_W, data_48bit, mask_48bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_eth_addr_w( OXM_OF_ARP_THA_W, data_48bit, mask_48bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_SRC, data_128bit, mask_128bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_DST, data_128bit, mask_128bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_SRC_W, data_128bit, mask_128bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_DST_W, data_128bit, mask_128bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_32( OXM_OF_IPV6_FLABEL, data_32bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_32w( OXM_OF_IPV6_FLABEL_W, data_32bit, mask_32bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_8( OXM_OF_ICMPV6_TYPE, data_8bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_8( OXM_OF_ICMPV6_CODE, data_8bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_ipv6_addr( OXM_OF_IPV6_ND_TARGET, data_128bit, mask_128bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_eth_addr( OXM_OF_IPV6_ND_SLL, data_48bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_eth_addr( OXM_OF_IPV6_ND_TLL, data_48bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_32( OXM_OF_MPLS_LABEL, data_32bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_8( OXM_OF_MPLS_TC, data_8bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_8( OXM_OF_MPLS_BOS, data_8bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_32( OXM_OF_PBB_ISID, data_32bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_32w( OXM_OF_PBB_ISID_W, data_32bit, mask_32bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_64( OXM_OF_TUNNEL_ID, data_64bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_64w( OXM_OF_TUNNEL_ID_W, data_64bit, mask_64bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_16( OXM_OF_IPV6_EXTHDR, data_16bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );
  src = create_oxm_match_16w( OXM_OF_IPV6_EXTHDR_W, data_16bit, mask_16bit, true );
  create_ofp_match_helper_for_test_ntoh_match( &match, &expected, src );

  uint16_t total_len = ( uint16_t ) ( expected_match->length + PADLEN_TO_64( expected_match->length ) );

  struct ofp_match *output_match = xcalloc( 1, total_len );
  ntoh_match( output_match, input_match );

  assert_memory_equal( output_match, expected_match, total_len );

  xfree( output_match );
}


static void
test_ntoh_match_with_undefined_match_type() {
  uint16_t oxm_len = ( uint16_t ) ( sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_IPV6_EXTHDR ) );
  uint16_t match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields ) + oxm_len );
  uint16_t alloc_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );

  struct ofp_match *match = xcalloc( 1, alloc_len );
  struct ofp_match *expected = xcalloc( 1, alloc_len );
  match->type = htons( OFPMT_OXM );
  match->length = htons( match_len );

  oxm_match_header *oxm = ( oxm_match_header * ) match->oxm_fields;
  *oxm = htonl( OXM_HEADER  (OFPXMC_OPENFLOW_BASIC, ( OFPXMT_OFB_IPV6_EXTHDR + 1 ), 2) );

  expect_assert_failure( ntoh_match( expected, match ) );

  xfree( match );
  xfree( expected );
}


/********************************************************************************
 * Run tests.
 ********************************************************************************/

int
main() {
  // FIXME: mockanize in setup()
  die = mock_die;

  const UnitTest tests[] = {
    unit_test( test_hton_oxm_match_header ),
    unit_test( test_hton_oxm_match_8 ),
    unit_test( test_hton_oxm_match_16 ),
    unit_test( test_hton_oxm_match_16w ),
    unit_test( test_hton_oxm_match_32 ),
    unit_test( test_hton_oxm_match_32w ),
    unit_test( test_hton_oxm_match_64 ),
    unit_test( test_hton_oxm_match_64w ),
    unit_test( test_hton_oxm_match_in_port ),
    unit_test( test_hton_oxm_match_metadata ),
    unit_test( test_hton_oxm_match_eth_addr ),
    unit_test( test_hton_oxm_match_eth_type ),
    unit_test( test_hton_oxm_match_vlan_vid ),
    unit_test( test_hton_oxm_match_vlan_pcp ),
    unit_test( test_hton_oxm_match_ip_dscp ),
    unit_test( test_hton_oxm_match_ip_ecn ),
    unit_test( test_hton_oxm_match_ip_proto ),
    unit_test( test_hton_oxm_match_ipv4_addr ),
    unit_test( test_hton_oxm_match_tcp_port ),
    unit_test( test_hton_oxm_match_udp_port ),
    unit_test( test_hton_oxm_match_sctp_port ),
    unit_test( test_hton_oxm_match_icmpv4_type ),
    unit_test( test_hton_oxm_match_icmpv4_code ),
    unit_test( test_hton_oxm_match_arp_op ),
    unit_test( test_hton_oxm_match_arp_pa ),
    unit_test( test_hton_oxm_match_arp_ha ),
    unit_test( test_hton_oxm_match_ipv6_addr ),
    unit_test( test_hton_oxm_match_ipv6_flabel ),
    unit_test( test_hton_oxm_match_icmpv6_type ),
    unit_test( test_hton_oxm_match_icmpv6_code ),
    unit_test( test_hton_oxm_match_ipv6_nd_target ),
    unit_test( test_hton_oxm_match_ipv6_nd_ll ),
    unit_test( test_hton_oxm_match_mpls_label ),
    unit_test( test_hton_oxm_match_mpls_tc ),
    unit_test( test_hton_oxm_match_mpls_bos ),
    unit_test( test_hton_oxm_match_pbb_isid ),
    unit_test( test_hton_oxm_match_tunnel_id ),
    unit_test( test_hton_oxm_match_ipv6_exthdr ),
    unit_test( test_hton_oxm_match ),
    unit_test( test_hton_oxm_match_with_undefined_match_type ),
    unit_test( test_hton_match ),
    unit_test( test_hton_match_with_undefined_match_type ),
    unit_test( test_ntoh_oxm_match_in_port ),
    unit_test( test_ntoh_oxm_match_metadata ),
    unit_test( test_ntoh_oxm_match_eth_addr ),
    unit_test( test_ntoh_oxm_match_eth_type ),
    unit_test( test_ntoh_oxm_match_vlan_vid ),
    unit_test( test_ntoh_oxm_match_vlan_pcp ),
    unit_test( test_ntoh_oxm_match_ip_dscp ),
    unit_test( test_ntoh_oxm_match_ip_ecn ),
    unit_test( test_ntoh_oxm_match_ip_proto ),
    unit_test( test_ntoh_oxm_match_ipv4_addr ),
    unit_test( test_ntoh_oxm_match_tcp_port ),
    unit_test( test_ntoh_oxm_match_udp_port ),
    unit_test( test_ntoh_oxm_match_sctp_port ),
    unit_test( test_ntoh_oxm_match_icmpv4_type ),
    unit_test( test_ntoh_oxm_match_icmpv4_code ),
    unit_test( test_ntoh_oxm_match_arp_op ),
    unit_test( test_ntoh_oxm_match_arp_pa ),
    unit_test( test_ntoh_oxm_match_arp_ha ),
    unit_test( test_ntoh_oxm_match_ipv6_addr ),
    unit_test( test_ntoh_oxm_match_ipv6_flabel ),
    unit_test( test_ntoh_oxm_match_icmpv6_type ),
    unit_test( test_ntoh_oxm_match_icmpv6_code ),
    unit_test( test_ntoh_oxm_match_ipv6_nd_target ),
    unit_test( test_ntoh_oxm_match_ipv6_nd_ll ),
    unit_test( test_ntoh_oxm_match_mpls_label ),
    unit_test( test_ntoh_oxm_match_mpls_tc ),
    unit_test( test_ntoh_oxm_match_mpls_bos ),
    unit_test( test_ntoh_oxm_match_pbb_isid ),
    unit_test( test_ntoh_oxm_match_tunnel_id ),
    unit_test( test_ntoh_oxm_match_ipv6_exthdr ),
    unit_test( test_ntoh_oxm_match ),
    unit_test( test_ntoh_oxm_match_with_undefined_match_type ),
    unit_test( test_ntoh_match ),
    unit_test( test_ntoh_match_with_undefined_match_type ),
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
