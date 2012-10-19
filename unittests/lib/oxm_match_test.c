/*
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
#include "cmockery_trema.h"
#include "oxm_match.h"
#include "checks.h"
#include "wrapper.h"
#include "oxm_byteorder.h"


bool
append_oxm_match( oxm_matches *matches, oxm_match_header *entry );
bool
append_oxm_match_8( oxm_matches *matches, oxm_match_header header, uint8_t value );
bool
append_oxm_match_16( oxm_matches *matches, oxm_match_header header, uint16_t value );
bool
append_oxm_match_16w( oxm_matches *matches, oxm_match_header header, uint16_t value, uint16_t mask );
bool
append_oxm_match_32( oxm_matches *matches, oxm_match_header header, uint32_t value );
bool
append_oxm_match_32w( oxm_matches *matches, oxm_match_header header, uint32_t value, uint32_t mask );
bool
append_oxm_match_64( oxm_matches *matches, oxm_match_header header, uint64_t value );
bool
append_oxm_match_64w( oxm_matches *matches, oxm_match_header header, uint64_t value, uint64_t mask );
bool
append_oxm_match_eth_addr( oxm_matches *matches, oxm_match_header header, uint8_t addr[ OFP_ETH_ALEN ] );
bool
append_oxm_match_eth_addr_w( oxm_matches *matches, oxm_match_header header,
                            uint8_t addr[ OFP_ETH_ALEN ], uint8_t mask[ OFP_ETH_ALEN ] );
bool
append_oxm_match_ipv6_addr( oxm_matches *matches, oxm_match_header header, struct in6_addr addr, struct in6_addr mask );


#define HDR_8BIT     OXM_OF_VLAN_PCP
#define HDR_16BIT    OXM_OF_VLAN_VID
#define HDR_16BIT_W  OXM_OF_VLAN_VID_W
#define HDR_32BIT    OXM_OF_IPV4_SRC
#define HDR_32BIT_W  OXM_OF_IPV4_SRC_W
#define HDR_48BIT    OXM_OF_ETH_DST
#define HDR_48BIT_W  OXM_OF_ETH_DST_W
#define HDR_64BIT    OXM_OF_METADATA
#define HDR_64BIT_W  OXM_OF_METADATA_W
#define HDR_128BIT   OXM_OF_IPV6_SRC
#define HDR_128BIT_W OXM_OF_IPV6_SRC_W

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


/********************************************************************************
 * Mocks.
 ********************************************************************************/

void
mock_debug( const char *format, ... ) {
  // Do nothing.
  UNUSED( format );
}


/********************************************************************************
 * Tests.
 ********************************************************************************/

static void
test_create_and_delete_oxm_matches() {
  oxm_matches *matches = create_oxm_matches();
  bool ret;

  assert_true( matches != NULL );
  assert_int_equal( matches->n_matches, 0 );

  ret = delete_oxm_matches( matches );
  assert_true( ret );

  matches = NULL;
  expect_assert_failure( delete_oxm_matches( NULL ) );
}


static void
test_get_oxm_matches_length() {
  uint16_t chk_len = 0;

  uint16_t len = get_oxm_matches_length( NULL );
  assert_int_equal( len, 0 );

  oxm_matches *matches = create_oxm_matches();

  len = get_oxm_matches_length( matches );
  assert_int_equal( len, 0 );

  chk_len = ( uint16_t ) ( sizeof( oxm_match_header ) + OXM_LENGTH( HDR_8BIT )
                         + sizeof( oxm_match_header ) + OXM_LENGTH( HDR_16BIT )
                         + sizeof( oxm_match_header ) + OXM_LENGTH( HDR_16BIT_W )
                         + sizeof( oxm_match_header ) + OXM_LENGTH( HDR_32BIT )
                         + sizeof( oxm_match_header ) + OXM_LENGTH( HDR_32BIT_W )
                         + sizeof( oxm_match_header ) + OXM_LENGTH( HDR_48BIT )
                         + sizeof( oxm_match_header ) + OXM_LENGTH( HDR_48BIT_W )
                         + sizeof( oxm_match_header ) + OXM_LENGTH( HDR_64BIT )
                         + sizeof( oxm_match_header ) + OXM_LENGTH( HDR_64BIT_W )
                         + sizeof( oxm_match_header ) + OXM_LENGTH( HDR_128BIT )
                         + sizeof( oxm_match_header ) + OXM_LENGTH( HDR_128BIT_W ) );

  uint8_t tmp_data_48bit[6];
  uint8_t tmp_mask_48bit[6];
  memcpy( tmp_data_48bit, data_48bit, sizeof( tmp_data_48bit ) );
  memcpy( tmp_mask_48bit, mask_48bit, sizeof( tmp_mask_48bit ) );

  struct in6_addr zero_mask_128bit;
  memset( &zero_mask_128bit, 0, sizeof( zero_mask_128bit ) );

  append_oxm_match_8( matches, HDR_8BIT, data_8bit );
  append_oxm_match_16( matches, HDR_16BIT, data_16bit );
  append_oxm_match_16w( matches, HDR_16BIT_W, data_16bit, mask_16bit );
  append_oxm_match_32( matches, HDR_32BIT, data_32bit );
  append_oxm_match_32w( matches, HDR_32BIT_W, data_32bit, mask_32bit );
  append_oxm_match_eth_addr( matches, HDR_48BIT, tmp_data_48bit );
  append_oxm_match_eth_addr_w( matches, HDR_48BIT_W, tmp_data_48bit, tmp_mask_48bit );
  append_oxm_match_64( matches, HDR_64BIT, data_64bit );
  append_oxm_match_64w( matches, HDR_64BIT_W, data_64bit, mask_64bit );
  append_oxm_match_ipv6_addr( matches, HDR_128BIT, data_128bit, zero_mask_128bit );
  append_oxm_match_ipv6_addr( matches, HDR_128BIT_W, data_128bit, mask_128bit );
  assert_int_equal( matches->n_matches, 11 );

  len = get_oxm_matches_length( matches );
  assert_int_equal( len, chk_len );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match() {
  const oxm_match_header type = HDR_32BIT;
  const uint32_t data = data_32bit;
  const uint16_t width = sizeof( data );
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();
  oxm_match_header *hdr = ( oxm_match_header * ) xcalloc( 1, ( uint16_t ) ( offset + width ) );
  uint32_t *val = ( uint32_t * ) ( ( char * ) hdr + offset );

  *hdr = type;
  *val = data;

  expect_assert_failure( append_oxm_match( matches, NULL ) );
  expect_assert_failure( append_oxm_match( NULL, hdr ) );
  expect_assert_failure( append_oxm_match( NULL, NULL ) );

  bool ret = append_oxm_match( matches, hdr );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint32_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint32_t * ) ( ( char * ) chk_hdr + offset );

  assert_true( chk_hdr == hdr );
  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_8() {
  const oxm_match_header type = HDR_8BIT;
  const uint8_t data = data_8bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_8( NULL, type, data ) );

  bool ret = append_oxm_match_8( matches, type, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint8_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint8_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_16() {
  const oxm_match_header type = HDR_16BIT;
  const uint16_t data = data_16bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_16( NULL, type, data ) );

  bool ret = append_oxm_match_16( matches, type, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint16_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint16_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_16w() {
  const oxm_match_header type = HDR_16BIT_W;
  const uint16_t data = data_16bit;
  const uint16_t mask = mask_16bit;
  const uint16_t width = sizeof( data );
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_16w( NULL, type, data, mask ) );

  bool ret = append_oxm_match_16w( matches, type, data, mask );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint16_t *chk_val;
  uint16_t *chk_mask;

  chk_hdr = matches->list->data;
  chk_val = ( uint16_t * ) ( ( char * ) chk_hdr + offset );
  chk_mask = ( uint16_t * ) ( ( char * ) chk_hdr + offset + width );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );
  assert_int_equal( *chk_mask, mask );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_32() {
  const oxm_match_header type = HDR_32BIT;
  const uint32_t data = data_32bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_32( NULL, type, data ) );

  bool ret = append_oxm_match_32( matches, type, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint32_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint32_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_32w() {
  const oxm_match_header type = HDR_32BIT_W;
  const uint32_t data = data_32bit;
  const uint32_t mask = mask_32bit;
  const uint16_t width = sizeof( data );
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_32w( NULL, type, data, mask ) );

  bool ret = append_oxm_match_32w( matches, type, data, mask );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint32_t *chk_val;
  uint32_t *chk_mask;

  chk_hdr = matches->list->data;
  chk_val = ( uint32_t * ) ( ( char * ) chk_hdr + offset );
  chk_mask = ( uint32_t * ) ( ( char * ) chk_hdr + offset + width );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );
  assert_int_equal( *chk_mask, mask );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_64() {
  const oxm_match_header type = HDR_64BIT;
  const uint64_t data = data_64bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_64( NULL, type, data ) );

  bool ret = append_oxm_match_64( matches, type, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint64_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint64_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_true( memcmp( chk_val, &data, sizeof( data ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_64w() {
  const oxm_match_header type = HDR_64BIT_W;
  const uint64_t data = data_64bit;
  const uint64_t mask = mask_64bit;
  const uint16_t width = sizeof( data );
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_64w( NULL, type, data, mask ) );

  bool ret = append_oxm_match_64w( matches, type, data, mask );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint64_t *chk_val;
  uint64_t *chk_mask;

  chk_hdr = matches->list->data;
  chk_val = ( uint64_t * ) ( ( char * ) chk_hdr + offset );
  chk_mask = ( uint64_t * ) ( ( char * ) chk_hdr + offset + width );

  assert_int_equal( *chk_hdr, type );
  assert_true( memcmp( chk_val, &data, sizeof( data ) ) == 0 );
  assert_true( memcmp( chk_mask, &mask, sizeof( mask ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_eth_addr() {
  const oxm_match_header type = HDR_48BIT;
  uint8_t data[6];
  const uint16_t offset = sizeof( oxm_match_header );

  memcpy( data, data_48bit, sizeof( data ) );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_eth_addr( NULL, type, data ) );

  bool ret = append_oxm_match_eth_addr( matches, type, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint8_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint8_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_true( memcmp( chk_val, &data, sizeof( data ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_eth_addr_w() {
  const oxm_match_header type = HDR_48BIT_W;
  uint8_t data[6];
  uint8_t mask[6];
  const uint16_t width = sizeof( data );
  const uint16_t offset = sizeof( oxm_match_header );

  memcpy( data, data_48bit, sizeof( data ) );
  memcpy( mask, mask_48bit, sizeof( mask ) );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_eth_addr_w( NULL, type, data, mask ) );

  bool ret = append_oxm_match_eth_addr_w( matches, type, data, mask );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint8_t *chk_val;
  uint8_t *chk_mask;

  chk_hdr = matches->list->data;
  chk_val = ( uint8_t * ) ( ( char * ) chk_hdr + offset );
  chk_mask = ( uint8_t * ) ( ( char * ) chk_hdr + offset + width );

  assert_int_equal( *chk_hdr, type );
  assert_true( memcmp( chk_val, &data, sizeof( data ) ) == 0 );
  assert_true( memcmp( chk_mask, &mask, sizeof( mask ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_ipv6_addr() {
  const oxm_match_header type1 = HDR_128BIT;
  const oxm_match_header type2 = HDR_128BIT_W;
  struct in6_addr data;
  struct in6_addr mask;
  const uint16_t width = sizeof( data );
  const uint16_t offset = sizeof( oxm_match_header );

  memcpy( &data, &data_128bit, sizeof( data ) );
  memcpy( &mask, &mask_128bit, sizeof( mask ) );

  expect_assert_failure( append_oxm_match_ipv6_addr( NULL, type1, data, mask ) );

  // val only
  oxm_matches *matches = create_oxm_matches();

  bool ret = append_oxm_match_ipv6_addr( matches, type1, data, mask );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  struct in6_addr *chk_val;
  struct in6_addr *chk_mask;

  chk_hdr = matches->list->data;
  chk_val = ( struct in6_addr * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type1 );
  assert_true( memcmp( chk_val, &data, sizeof( data ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );


  // val and mask
  matches = create_oxm_matches();

  ret = append_oxm_match_ipv6_addr( matches, type2, data, mask );
  assert_true( ret );

  chk_hdr = matches->list->data;
  chk_val = ( struct in6_addr * ) ( ( char * ) chk_hdr + offset );
  chk_mask = ( struct in6_addr * ) ( ( char * ) chk_hdr + offset + width );

  assert_int_equal( *chk_hdr, type2 );
  assert_true( memcmp( chk_val, &data, sizeof( data ) ) == 0 );
  assert_true( memcmp( chk_mask, &mask, sizeof( mask ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_in_port() {
  const oxm_match_header type = OXM_OF_IN_PORT;
  const uint32_t data = data_32bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_in_port( NULL, data ) );

  bool ret = append_oxm_match_in_port( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint32_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint32_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_in_phy_port() {
  const oxm_match_header type = OXM_OF_IN_PHY_PORT;
  const uint32_t data = data_32bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_in_phy_port( NULL, data ) );

  bool ret = append_oxm_match_in_phy_port( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint32_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint32_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_metadata() {
  const oxm_match_header type1 = OXM_OF_METADATA;
  const oxm_match_header type2 = OXM_OF_METADATA_W;
  uint64_t data = data_64bit;
  uint64_t mask = mask_64bit;
  uint64_t no_mask = 0;
  const uint16_t width = sizeof( data );
  const uint16_t offset = sizeof( oxm_match_header );

  expect_assert_failure( append_oxm_match_metadata( NULL, data, no_mask ) );

  // val only
  oxm_matches *matches = create_oxm_matches();

  bool ret = append_oxm_match_metadata( matches, data, no_mask );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint64_t *chk_val;
  uint64_t *chk_mask;

  chk_hdr = matches->list->data;
  chk_val = ( uint64_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type1 );
  assert_true( memcmp( chk_val, &data, sizeof( data ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );


  // val and mask
  matches = create_oxm_matches();

  ret = append_oxm_match_metadata( matches, data, mask );
  assert_true( ret );

  chk_hdr = matches->list->data;
  chk_val = ( uint64_t * ) ( ( char * ) chk_hdr + offset );
  chk_mask = ( uint64_t * ) ( ( char * ) chk_hdr + offset + width );

  assert_int_equal( *chk_hdr, type2 );
  assert_true( memcmp( chk_val, &data, sizeof( data ) ) == 0 );
  assert_true( memcmp( chk_mask, &mask, sizeof( mask ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_eth_dst() {
  const oxm_match_header type1 = OXM_OF_ETH_DST;
  const oxm_match_header type2 = OXM_OF_ETH_DST_W;
  uint8_t data[6];
  uint8_t mask[6];
  uint8_t no_mask[6];
  const uint16_t width = sizeof( data );
  const uint16_t offset = sizeof( oxm_match_header );

  memcpy( data, data_48bit, sizeof( data ) );
  memcpy( mask, mask_48bit, sizeof( mask ) );
  memset( no_mask, 0, sizeof( mask ) );

  expect_assert_failure( append_oxm_match_eth_dst( NULL, data, no_mask ) );

  // val only
  oxm_matches *matches = create_oxm_matches();

  bool ret = append_oxm_match_eth_dst( matches, data, no_mask );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint8_t *chk_val;
  uint8_t *chk_mask;

  chk_hdr = matches->list->data;
  chk_val = ( uint8_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type1 );
  assert_true( memcmp( chk_val, data, sizeof( data ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );


  // val and mask
  matches = create_oxm_matches();

  ret = append_oxm_match_eth_dst( matches, data, mask );
  assert_true( ret );

  chk_hdr = matches->list->data;
  chk_val = ( uint8_t * ) ( ( char * ) chk_hdr + offset );
  chk_mask = ( uint8_t * ) ( ( char * ) chk_hdr + offset + width );

  assert_int_equal( *chk_hdr, type2 );
  assert_true( memcmp( chk_val, data, sizeof( data ) ) == 0 );
  assert_true( memcmp( chk_mask, mask, sizeof( mask ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_eth_src() {
  const oxm_match_header type1 = OXM_OF_ETH_SRC;
  const oxm_match_header type2 = OXM_OF_ETH_SRC_W;
  uint8_t data[6];
  uint8_t mask[6];
  uint8_t no_mask[6];
  const uint16_t width = sizeof( data );
  const uint16_t offset = sizeof( oxm_match_header );

  memcpy( data, data_48bit, sizeof( data ) );
  memcpy( mask, mask_48bit, sizeof( mask ) );
  memset( no_mask, 0, sizeof( mask ) );

  expect_assert_failure( append_oxm_match_eth_src( NULL, data, no_mask ) );

  // val only
  oxm_matches *matches = create_oxm_matches();

  bool ret = append_oxm_match_eth_src( matches, data, no_mask );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint8_t *chk_val;
  uint8_t *chk_mask;

  chk_hdr = matches->list->data;
  chk_val = ( uint8_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type1 );
  assert_true( memcmp( chk_val, data, sizeof( data ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );


  // val and mask
  matches = create_oxm_matches();

  ret = append_oxm_match_eth_src( matches, data, mask );
  assert_true( ret );

  chk_hdr = matches->list->data;
  chk_val = ( uint8_t * ) ( ( char * ) chk_hdr + offset );
  chk_mask = ( uint8_t * ) ( ( char * ) chk_hdr + offset + width );

  assert_int_equal( *chk_hdr, type2 );
  assert_true( memcmp( chk_val, data, sizeof( data ) ) == 0 );
  assert_true( memcmp( chk_mask, mask, sizeof( mask ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_eth_type() {
  const oxm_match_header type = OXM_OF_ETH_TYPE;
  const uint16_t data = data_16bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_eth_type( NULL, data ) );

  bool ret = append_oxm_match_eth_type( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint16_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint16_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_vlan_vid() {
  const oxm_match_header type1 = OXM_OF_VLAN_VID;
  const oxm_match_header type2 = OXM_OF_VLAN_VID_W;
  uint16_t data = data_16bit;
  uint16_t mask = mask_16bit;
  uint16_t no_mask = 0;
  const uint16_t width = sizeof( data );
  const uint16_t offset = sizeof( oxm_match_header );

  expect_assert_failure( append_oxm_match_vlan_vid( NULL, data, no_mask ) );

  // val only
  oxm_matches *matches = create_oxm_matches();

  bool ret = append_oxm_match_vlan_vid( matches, data, no_mask );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint16_t *chk_val;
  uint16_t *chk_mask;

  chk_hdr = matches->list->data;
  chk_val = ( uint16_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type1 );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );


  // val and mask
  matches = create_oxm_matches();

  ret = append_oxm_match_vlan_vid( matches, data, mask );
  assert_true( ret );

  chk_hdr = matches->list->data;
  chk_val = ( uint16_t * ) ( ( char * ) chk_hdr + offset );
  chk_mask = ( uint16_t * ) ( ( char * ) chk_hdr + offset + width );

  assert_int_equal( *chk_hdr, type2 );
  assert_int_equal( *chk_val, data );
  assert_int_equal( *chk_mask, mask );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_vlan_pcp() {
  const oxm_match_header type = OXM_OF_VLAN_PCP;
  const uint8_t data = data_8bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_vlan_pcp( NULL, data ) );

  bool ret = append_oxm_match_vlan_pcp( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint8_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint8_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_ip_dscp() {
  const oxm_match_header type = OXM_OF_IP_DSCP;
  const uint8_t data = data_8bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_ip_dscp( NULL, data ) );

  bool ret = append_oxm_match_ip_dscp( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint8_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint8_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_ip_ecn() {
  const oxm_match_header type = OXM_OF_IP_ECN;
  const uint8_t data = data_8bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_ip_ecn( NULL, data ) );

  bool ret = append_oxm_match_ip_ecn( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint8_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint8_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_ip_proto() {
  const oxm_match_header type = OXM_OF_IP_PROTO;
  const uint8_t data = data_8bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_ip_proto( NULL, data ) );

  bool ret = append_oxm_match_ip_proto( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint8_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint8_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_ipv4_src() {
  const oxm_match_header type1 = OXM_OF_IPV4_SRC;
  const oxm_match_header type2 = OXM_OF_IPV4_SRC_W;
  uint32_t data = data_32bit;
  uint32_t mask = mask_32bit;
  uint32_t no_mask = 0;
  const uint16_t width = sizeof( data );
  const uint16_t offset = sizeof( oxm_match_header );

  expect_assert_failure( append_oxm_match_ipv4_src( NULL, data, no_mask ) );

  // val only
  oxm_matches *matches = create_oxm_matches();

  bool ret = append_oxm_match_ipv4_src( matches, data, no_mask );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint32_t *chk_val;
  uint32_t *chk_mask;

  chk_hdr = matches->list->data;
  chk_val = ( uint32_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type1 );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );


  // val and mask
  matches = create_oxm_matches();

  ret = append_oxm_match_ipv4_src( matches, data, mask );
  assert_true( ret );

  chk_hdr = matches->list->data;
  chk_val = ( uint32_t * ) ( ( char * ) chk_hdr + offset );
  chk_mask = ( uint32_t * ) ( ( char * ) chk_hdr + offset + width );

  assert_int_equal( *chk_hdr, type2 );
  assert_int_equal( *chk_val, data );
  assert_int_equal( *chk_mask, mask );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_ipv4_dst() {
  const oxm_match_header type1 = OXM_OF_IPV4_DST;
  const oxm_match_header type2 = OXM_OF_IPV4_DST_W;
  uint32_t data = data_32bit;
  uint32_t mask = mask_32bit;
  uint32_t no_mask = 0;
  const uint16_t width = sizeof( data );
  const uint16_t offset = sizeof( oxm_match_header );

  expect_assert_failure( append_oxm_match_ipv4_dst( NULL, data, no_mask ) );

  // val only
  oxm_matches *matches = create_oxm_matches();

  bool ret = append_oxm_match_ipv4_dst( matches, data, no_mask );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint32_t *chk_val;
  uint32_t *chk_mask;

  chk_hdr = matches->list->data;
  chk_val = ( uint32_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type1 );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );


  // val and mask
  matches = create_oxm_matches();

  ret = append_oxm_match_ipv4_dst( matches, data, mask );
  assert_true( ret );

  chk_hdr = matches->list->data;
  chk_val = ( uint32_t * ) ( ( char * ) chk_hdr + offset );
  chk_mask = ( uint32_t * ) ( ( char * ) chk_hdr + offset + width );

  assert_int_equal( *chk_hdr, type2 );
  assert_int_equal( *chk_val, data );
  assert_int_equal( *chk_mask, mask );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_tcp_src() {
  const oxm_match_header type = OXM_OF_TCP_SRC;
  const uint16_t data = data_16bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_tcp_src( NULL, data ) );

  bool ret = append_oxm_match_tcp_src( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint16_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint16_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_tcp_dst() {
  const oxm_match_header type = OXM_OF_TCP_DST;
  const uint16_t data = data_16bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_tcp_dst( NULL, data ) );

  bool ret = append_oxm_match_tcp_dst( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint16_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint16_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_udp_src() {
  const oxm_match_header type = OXM_OF_UDP_SRC;
  const uint16_t data = data_16bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_udp_src( NULL, data ) );

  bool ret = append_oxm_match_udp_src( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint16_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint16_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_udp_dst() {
  const oxm_match_header type = OXM_OF_UDP_DST;
  const uint16_t data = data_16bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_udp_dst( NULL, data ) );

  bool ret = append_oxm_match_udp_dst( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint16_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint16_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_sctp_src() {
  const oxm_match_header type = OXM_OF_SCTP_SRC;
  const uint16_t data = data_16bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_sctp_src( NULL, data ) );

  bool ret = append_oxm_match_sctp_src( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint16_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint16_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_sctp_dst() {
  const oxm_match_header type = OXM_OF_SCTP_DST;
  const uint16_t data = data_16bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_sctp_dst( NULL, data ) );

  bool ret = append_oxm_match_sctp_dst( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint16_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint16_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_icmpv4_type() {
  const oxm_match_header type = OXM_OF_ICMPV4_TYPE;
  const uint8_t data = data_8bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_icmpv4_type( NULL, data ) );

  bool ret = append_oxm_match_icmpv4_type( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint8_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint8_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_icmpv4_code() {
  const oxm_match_header type = OXM_OF_ICMPV4_CODE;
  const uint8_t data = data_8bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_icmpv4_code( NULL, data ) );

  bool ret = append_oxm_match_icmpv4_code( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint8_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint8_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_arp_op() {
  const oxm_match_header type = OXM_OF_ARP_OP;
  const uint16_t data = data_16bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_arp_op( NULL, data ) );

  bool ret = append_oxm_match_arp_op( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint16_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint16_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_arp_spa() {
  const oxm_match_header type1 = OXM_OF_ARP_SPA;
  const oxm_match_header type2 = OXM_OF_ARP_SPA_W;
  uint32_t data = data_32bit;
  uint32_t mask = mask_32bit;
  uint32_t no_mask = 0;
  const uint16_t width = sizeof( data );
  const uint16_t offset = sizeof( oxm_match_header );

  expect_assert_failure( append_oxm_match_arp_spa( NULL, data, no_mask ) );

  // val only
  oxm_matches *matches = create_oxm_matches();

  bool ret = append_oxm_match_arp_spa( matches, data, no_mask );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint32_t *chk_val;
  uint32_t *chk_mask;

  chk_hdr = matches->list->data;
  chk_val = ( uint32_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type1 );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );


  // val and mask
  matches = create_oxm_matches();

  ret = append_oxm_match_arp_spa( matches, data, mask );
  assert_true( ret );

  chk_hdr = matches->list->data;
  chk_val = ( uint32_t * ) ( ( char * ) chk_hdr + offset );
  chk_mask = ( uint32_t * ) ( ( char * ) chk_hdr + offset + width );

  assert_int_equal( *chk_hdr, type2 );
  assert_int_equal( *chk_val, data );
  assert_int_equal( *chk_mask, mask );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_arp_tpa() {
  const oxm_match_header type1 = OXM_OF_ARP_TPA;
  const oxm_match_header type2 = OXM_OF_ARP_TPA_W;
  uint32_t data = data_32bit;
  uint32_t mask = mask_32bit;
  uint32_t no_mask = 0;
  const uint16_t width = sizeof( data );
  const uint16_t offset = sizeof( oxm_match_header );

  expect_assert_failure( append_oxm_match_arp_tpa( NULL, data, no_mask ) );

  // val only
  oxm_matches *matches = create_oxm_matches();

  bool ret = append_oxm_match_arp_tpa( matches, data, no_mask );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint32_t *chk_val;
  uint32_t *chk_mask;

  chk_hdr = matches->list->data;
  chk_val = ( uint32_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type1 );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );


  // val and mask
  matches = create_oxm_matches();

  ret = append_oxm_match_arp_tpa( matches, data, mask );
  assert_true( ret );

  chk_hdr = matches->list->data;
  chk_val = ( uint32_t * ) ( ( char * ) chk_hdr + offset );
  chk_mask = ( uint32_t * ) ( ( char * ) chk_hdr + offset + width );

  assert_int_equal( *chk_hdr, type2 );
  assert_int_equal( *chk_val, data );
  assert_int_equal( *chk_mask, mask );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_arp_sha() {
  const oxm_match_header type1 = OXM_OF_ARP_SHA;
  const oxm_match_header type2 = OXM_OF_ARP_SHA_W;
  uint8_t data[6];
  uint8_t mask[6];
  uint8_t no_mask[6];
  const uint16_t width = sizeof( data );
  const uint16_t offset = sizeof( oxm_match_header );

  memcpy( data, data_48bit, sizeof( data ) );
  memcpy( mask, mask_48bit, sizeof( mask ) );
  memset( no_mask, 0, sizeof( mask ) );

  expect_assert_failure( append_oxm_match_arp_sha( NULL, data, no_mask ) );

  // val only
  oxm_matches *matches = create_oxm_matches();

  bool ret = append_oxm_match_arp_sha( matches, data, no_mask );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint8_t *chk_val;
  uint8_t *chk_mask;

  chk_hdr = matches->list->data;
  chk_val = ( uint8_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type1 );
  assert_true( memcmp( chk_val, data, sizeof( data ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );


  // val and mask
  matches = create_oxm_matches();

  ret = append_oxm_match_arp_sha( matches, data, mask );
  assert_true( ret );

  chk_hdr = matches->list->data;
  chk_val = ( uint8_t * ) ( ( char * ) chk_hdr + offset );
  chk_mask = ( uint8_t * ) ( ( char * ) chk_hdr + offset + width );

  assert_int_equal( *chk_hdr, type2 );
  assert_true( memcmp( chk_val, data, sizeof( data ) ) == 0 );
  assert_true( memcmp( chk_mask, mask, sizeof( mask ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_arp_tha() {
  const oxm_match_header type1 = OXM_OF_ARP_THA;
  const oxm_match_header type2 = OXM_OF_ARP_THA_W;
  uint8_t data[6];
  uint8_t mask[6];
  uint8_t no_mask[6];
  const uint16_t width = sizeof( data );
  const uint16_t offset = sizeof( oxm_match_header );

  memcpy( data, data_48bit, sizeof( data ) );
  memcpy( mask, mask_48bit, sizeof( mask ) );
  memset( no_mask, 0, sizeof( mask ) );

  expect_assert_failure( append_oxm_match_arp_tha( NULL, data, no_mask ) );

  // val only
  oxm_matches *matches = create_oxm_matches();

  bool ret = append_oxm_match_arp_tha( matches, data, no_mask );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint8_t *chk_val;
  uint8_t *chk_mask;

  chk_hdr = matches->list->data;
  chk_val = ( uint8_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type1 );
  assert_true( memcmp( chk_val, data, sizeof( data ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );


  // val and mask
  matches = create_oxm_matches();

  ret = append_oxm_match_arp_tha( matches, data, mask );
  assert_true( ret );

  chk_hdr = matches->list->data;
  chk_val = ( uint8_t * ) ( ( char * ) chk_hdr + offset );
  chk_mask = ( uint8_t * ) ( ( char * ) chk_hdr + offset + width );

  assert_int_equal( *chk_hdr, type2 );
  assert_true( memcmp( chk_val, data, sizeof( data ) ) == 0 );
  assert_true( memcmp( chk_mask, mask, sizeof( mask ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_ipv6_src() {
  const oxm_match_header type1 = OXM_OF_IPV6_SRC;
  const oxm_match_header type2 = OXM_OF_IPV6_SRC_W;
  struct in6_addr data;
  struct in6_addr mask;
  struct in6_addr no_mask;
  const uint16_t width = sizeof( data );
  const uint16_t offset = sizeof( oxm_match_header );

  memcpy( &data, &data_128bit, sizeof( data ) );
  memcpy( &mask, &mask_128bit, sizeof( mask ) );
  memset( &no_mask, 0, sizeof( mask ) );

  expect_assert_failure( append_oxm_match_ipv6_src( NULL, data, no_mask ) );

  // val only
  oxm_matches *matches = create_oxm_matches();

  bool ret = append_oxm_match_ipv6_src( matches, data, no_mask );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  struct in6_addr *chk_val;
  struct in6_addr *chk_mask;

  chk_hdr = matches->list->data;
  chk_val = ( struct in6_addr * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type1 );
  assert_true( memcmp( chk_val, &data, sizeof( data ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );


  // val and mask
  matches = create_oxm_matches();

  ret = append_oxm_match_ipv6_src( matches, data, mask );
  assert_true( ret );

  chk_hdr = matches->list->data;
  chk_val = ( struct in6_addr * ) ( ( char * ) chk_hdr + offset );
  chk_mask = ( struct in6_addr * ) ( ( char * ) chk_hdr + offset + width );

  assert_int_equal( *chk_hdr, type2 );
  assert_true( memcmp( chk_val, &data, sizeof( data ) ) == 0 );
  assert_true( memcmp( chk_mask, &mask, sizeof( mask ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_ipv6_dst() {
  const oxm_match_header type1 = OXM_OF_IPV6_DST;
  const oxm_match_header type2 = OXM_OF_IPV6_DST_W;
  struct in6_addr data;
  struct in6_addr mask;
  struct in6_addr no_mask;
  const uint16_t width = sizeof( data );
  const uint16_t offset = sizeof( oxm_match_header );

  memcpy( &data, &data_128bit, sizeof( data ) );
  memcpy( &mask, &mask_128bit, sizeof( mask ) );
  memset( &no_mask, 0, sizeof( mask ) );

  expect_assert_failure( append_oxm_match_ipv6_dst( NULL, data, no_mask ) );

  // val only
  oxm_matches *matches = create_oxm_matches();

  bool ret = append_oxm_match_ipv6_dst( matches, data, no_mask );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  struct in6_addr *chk_val;
  struct in6_addr *chk_mask;

  chk_hdr = matches->list->data;
  chk_val = ( struct in6_addr * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type1 );
  assert_true( memcmp( chk_val, &data, sizeof( data ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );


  // val and mask
  matches = create_oxm_matches();

  ret = append_oxm_match_ipv6_dst( matches, data, mask );
  assert_true( ret );

  chk_hdr = matches->list->data;
  chk_val = ( struct in6_addr * ) ( ( char * ) chk_hdr + offset );
  chk_mask = ( struct in6_addr * ) ( ( char * ) chk_hdr + offset + width );

  assert_int_equal( *chk_hdr, type2 );
  assert_true( memcmp( chk_val, &data, sizeof( data ) ) == 0 );
  assert_true( memcmp( chk_mask, &mask, sizeof( mask ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_ipv6_flabel() {
  const oxm_match_header type1 = OXM_OF_IPV6_FLABEL;
  const oxm_match_header type2 = OXM_OF_IPV6_FLABEL_W;
  uint32_t data = data_32bit;
  uint32_t mask = mask_32bit;
  uint32_t no_mask = 0;
  const uint16_t width = sizeof( data );
  const uint16_t offset = sizeof( oxm_match_header );

  expect_assert_failure( append_oxm_match_ipv6_flabel( NULL, data, no_mask ) );

  // val only
  oxm_matches *matches = create_oxm_matches();

  bool ret = append_oxm_match_ipv6_flabel( matches, data, no_mask );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint32_t *chk_val;
  uint32_t *chk_mask;

  chk_hdr = matches->list->data;
  chk_val = ( uint32_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type1 );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );


  // val and mask
  matches = create_oxm_matches();

  ret = append_oxm_match_ipv6_flabel( matches, data, mask );
  assert_true( ret );

  chk_hdr = matches->list->data;
  chk_val = ( uint32_t * ) ( ( char * ) chk_hdr + offset );
  chk_mask = ( uint32_t * ) ( ( char * ) chk_hdr + offset + width );

  assert_int_equal( *chk_hdr, type2 );
  assert_int_equal( *chk_val, data );
  assert_int_equal( *chk_mask, mask );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_icmpv6_type() {
  const oxm_match_header type = OXM_OF_ICMPV6_TYPE;
  const uint8_t data = data_8bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_icmpv6_type( NULL, data ) );

  bool ret = append_oxm_match_icmpv6_type( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint8_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint8_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_icmpv6_code() {
  const oxm_match_header type = OXM_OF_ICMPV6_CODE;
  const uint8_t data = data_8bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_icmpv6_code( NULL, data ) );

  bool ret = append_oxm_match_icmpv6_code( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint8_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint8_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_ipv6_nd_target() {
  const oxm_match_header type = OXM_OF_IPV6_ND_TARGET;
  struct in6_addr data;
  const uint16_t offset = sizeof( oxm_match_header );

  memcpy( &data, &data_128bit, sizeof( data ) );

  expect_assert_failure( append_oxm_match_ipv6_nd_target( NULL, data ) );

  oxm_matches *matches = create_oxm_matches();

  bool ret = append_oxm_match_ipv6_nd_target( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  struct in6_addr *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( struct in6_addr * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_true( memcmp( chk_val, &data, sizeof( data ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_ipv6_nd_sll() {
  const oxm_match_header type = OXM_OF_IPV6_ND_SLL;
  uint8_t data[6];
  const uint16_t offset = sizeof( oxm_match_header );

  memcpy( data, data_48bit, sizeof( data ) );

  expect_assert_failure( append_oxm_match_ipv6_nd_sll( NULL, data ) );

  oxm_matches *matches = create_oxm_matches();

  bool ret = append_oxm_match_ipv6_nd_sll( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint8_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint8_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_true( memcmp( chk_val, data, sizeof( data ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_ipv6_nd_tll() {
  const oxm_match_header type = OXM_OF_IPV6_ND_TLL;
  uint8_t data[6];
  const uint16_t offset = sizeof( oxm_match_header );

  memcpy( data, data_48bit, sizeof( data ) );

  expect_assert_failure( append_oxm_match_ipv6_nd_tll( NULL, data ) );

  oxm_matches *matches = create_oxm_matches();

  bool ret = append_oxm_match_ipv6_nd_tll( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint8_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint8_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_true( memcmp( chk_val, data, sizeof( data ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_mpls_label() {
  const oxm_match_header type = OXM_OF_MPLS_LABEL;
  uint32_t data;
  const uint16_t offset = sizeof( oxm_match_header );

  memcpy( &data, &data_32bit, sizeof( data ) );

  expect_assert_failure( append_oxm_match_mpls_label( NULL, data ) );

  oxm_matches *matches = create_oxm_matches();

  bool ret = append_oxm_match_mpls_label( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint32_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint32_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_true( memcmp( chk_val, &data, sizeof( data ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_mpls_tc() {
  const oxm_match_header type = OXM_OF_MPLS_TC;
  const uint8_t data = data_8bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_mpls_tc( NULL, data ) );

  bool ret = append_oxm_match_mpls_tc( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint8_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint8_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_mpls_bos() {
  const oxm_match_header type = OXM_OF_MPLS_BOS;
  const uint8_t data = data_8bit;
  const uint16_t offset = sizeof( oxm_match_header );

  oxm_matches *matches = create_oxm_matches();

  expect_assert_failure( append_oxm_match_mpls_bos( NULL, data ) );

  bool ret = append_oxm_match_mpls_bos( matches, data );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint8_t *chk_val;

  chk_hdr = matches->list->data;
  chk_val = ( uint8_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_pbb_isid() {
  const oxm_match_header type1 = OXM_OF_PBB_ISID;
  const oxm_match_header type2 = OXM_OF_PBB_ISID_W;
  uint32_t data = data_32bit;
  uint32_t mask = mask_32bit;
  uint32_t no_mask = 0;
  const uint16_t width = sizeof( data );
  const uint16_t offset = sizeof( oxm_match_header );

  expect_assert_failure( append_oxm_match_pbb_isid( NULL, data, no_mask ) );

  // val only
  oxm_matches *matches = create_oxm_matches();

  bool ret = append_oxm_match_pbb_isid( matches, data, no_mask );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint32_t *chk_val;
  uint32_t *chk_mask;

  chk_hdr = matches->list->data;
  chk_val = ( uint32_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type1 );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );


  // val and mask
  matches = create_oxm_matches();

  ret = append_oxm_match_pbb_isid( matches, data, mask );
  assert_true( ret );

  chk_hdr = matches->list->data;
  chk_val = ( uint32_t * ) ( ( char * ) chk_hdr + offset );
  chk_mask = ( uint32_t * ) ( ( char * ) chk_hdr + offset + width );

  assert_int_equal( *chk_hdr, type2 );
  assert_int_equal( *chk_val, data );
  assert_int_equal( *chk_mask, mask );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_tunnel_id() {
  const oxm_match_header type1 = OXM_OF_TUNNEL_ID;
  const oxm_match_header type2 = OXM_OF_TUNNEL_ID_W;
  uint64_t data = data_64bit;
  uint64_t mask = mask_64bit;
  uint64_t no_mask = 0;
  const uint16_t width = sizeof( data );
  const uint16_t offset = sizeof( oxm_match_header );

  expect_assert_failure( append_oxm_match_tunnel_id( NULL, data, no_mask ) );

  // val only
  oxm_matches *matches = create_oxm_matches();

  bool ret = append_oxm_match_tunnel_id( matches, data, no_mask );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint64_t *chk_val;
  uint64_t *chk_mask;

  chk_hdr = matches->list->data;
  chk_val = ( uint64_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type1 );
  assert_true( memcmp( chk_val, &data, sizeof( data ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );


  // val and mask
  matches = create_oxm_matches();

  ret = append_oxm_match_tunnel_id( matches, data, mask );
  assert_true( ret );

  chk_hdr = matches->list->data;
  chk_val = ( uint64_t * ) ( ( char * ) chk_hdr + offset );
  chk_mask = ( uint64_t * ) ( ( char * ) chk_hdr + offset + width );

  assert_int_equal( *chk_hdr, type2 );
  assert_true( memcmp( chk_val, &data, sizeof( data ) ) == 0 );
  assert_true( memcmp( chk_mask, &mask, sizeof( mask ) ) == 0 );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_append_oxm_match_ipv6_exthdr() {
  const oxm_match_header type1 = OXM_OF_IPV6_EXTHDR;
  const oxm_match_header type2 = OXM_OF_IPV6_EXTHDR_W;
  uint16_t data = data_16bit;
  uint16_t mask = mask_16bit;
  uint16_t no_mask = 0;
  const uint16_t width = sizeof( data );
  const uint16_t offset = sizeof( oxm_match_header );

  expect_assert_failure( append_oxm_match_ipv6_exthdr( NULL, data, no_mask ) );

  // val only
  oxm_matches *matches = create_oxm_matches();

  bool ret = append_oxm_match_ipv6_exthdr( matches, data, no_mask );
  assert_true( ret );

  oxm_match_header *chk_hdr;
  uint16_t *chk_val;
  uint16_t *chk_mask;

  chk_hdr = matches->list->data;
  chk_val = ( uint16_t * ) ( ( char * ) chk_hdr + offset );

  assert_int_equal( *chk_hdr, type1 );
  assert_int_equal( *chk_val, data );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );


  // val and mask
  matches = create_oxm_matches();

  ret = append_oxm_match_ipv6_exthdr( matches, data, mask );
  assert_true( ret );

  chk_hdr = matches->list->data;
  chk_val = ( uint16_t * ) ( ( char * ) chk_hdr + offset );
  chk_mask = ( uint16_t * ) ( ( char * ) chk_hdr + offset + width );

  assert_int_equal( *chk_hdr, type2 );
  assert_int_equal( *chk_val, data );
  assert_int_equal( *chk_mask, mask );

  assert_int_equal( matches->n_matches, 1 );

  delete_oxm_matches( matches );
}


static void
test_parse_ofp_match() {
  oxm_matches *expected;
  uint8_t d_48bit[ OFP_ETH_ALEN ];
  uint8_t m_48bit[ OFP_ETH_ALEN ];

  memcpy( d_48bit, data_48bit, sizeof( d_48bit ) );
  memcpy( m_48bit, mask_48bit, sizeof( m_48bit ) );

  expect_assert_failure( parse_ofp_match( NULL ) );

  {
    expected = create_oxm_matches();

    append_oxm_match_in_port( expected, data_32bit );
    append_oxm_match_in_phy_port( expected, data_32bit );
    append_oxm_match_metadata( expected, data_64bit, data_64bit );
    append_oxm_match_eth_dst( expected, d_48bit, m_48bit );
    append_oxm_match_eth_src( expected, d_48bit, m_48bit );
    append_oxm_match_eth_type( expected, data_16bit );
    append_oxm_match_vlan_vid( expected, data_16bit, mask_16bit );
    append_oxm_match_vlan_pcp( expected, data_8bit );
    append_oxm_match_ip_dscp( expected, data_8bit );
    append_oxm_match_ip_ecn( expected, data_8bit );
    append_oxm_match_ip_proto( expected, data_8bit );
    append_oxm_match_ipv4_src( expected, data_32bit, mask_32bit );
    append_oxm_match_ipv4_dst( expected, data_32bit, mask_32bit );
    append_oxm_match_tcp_src( expected, data_16bit );
    append_oxm_match_tcp_dst( expected, data_16bit );
    append_oxm_match_udp_src( expected, data_16bit );
    append_oxm_match_udp_dst( expected, data_16bit );
    append_oxm_match_sctp_src( expected, data_16bit );
    append_oxm_match_sctp_dst( expected, data_16bit );
    append_oxm_match_icmpv4_type( expected, data_8bit );
    append_oxm_match_icmpv4_code( expected, data_8bit );
    append_oxm_match_arp_op( expected, data_16bit );
    append_oxm_match_arp_spa( expected, data_32bit, mask_32bit );
    append_oxm_match_arp_tpa( expected, data_32bit, mask_32bit );
    append_oxm_match_arp_sha( expected, d_48bit, m_48bit );
    append_oxm_match_arp_tha( expected, d_48bit, m_48bit );
    append_oxm_match_ipv6_src( expected, data_128bit, mask_128bit );
    append_oxm_match_ipv6_dst( expected, data_128bit, mask_128bit );
    append_oxm_match_ipv6_flabel( expected, data_32bit, mask_32bit );
    append_oxm_match_icmpv6_type( expected, data_8bit );
    append_oxm_match_icmpv6_code( expected, data_8bit );
    append_oxm_match_ipv6_nd_target( expected, data_128bit );
    append_oxm_match_ipv6_nd_sll( expected, d_48bit );
    append_oxm_match_ipv6_nd_tll( expected, d_48bit );
    append_oxm_match_mpls_label( expected, data_32bit );
    append_oxm_match_mpls_tc( expected, data_8bit );
    append_oxm_match_mpls_bos( expected, data_8bit );
    append_oxm_match_pbb_isid( expected, data_32bit, mask_32bit );
    append_oxm_match_tunnel_id( expected, data_64bit, mask_64bit );
    append_oxm_match_ipv6_exthdr( expected, data_16bit, mask_16bit );

    uint16_t match_len = ( uint16_t ) ( sizeof( oxm_match_header ) + get_oxm_matches_length( expected ) );
    uint16_t alloc_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );
    struct ofp_match *input_match = xcalloc( 1, alloc_len );
    construct_ofp_match( input_match, expected );

    oxm_matches *output = parse_ofp_match( input_match );
    assert_true( output != NULL );
    assert_int_equal( output->n_matches, expected->n_matches );

    uint16_t num = 0;
    list_element *output_list, *expected_list;
    output_list = output->list;
    expected_list = expected->list;
    while ( expected_list != NULL ) {
      assert_true( output_list != NULL );

      oxm_match_header *output_oxm, *expected_oxm;
      output_oxm = output_list->data;
      expected_oxm = expected_list->data;

      uint16_t oxm_len = OXM_LENGTH( *expected_oxm );
      assert_memory_equal( output_oxm, expected_oxm, oxm_len );

      output_list = output_list->next;
      expected_list = expected_list->next;
      num++;
    }

    assert_int_equal( output->n_matches, num );
    assert_true( output_list == NULL );

    xfree( input_match );
    delete_oxm_matches( expected );
    delete_oxm_matches( output );
  }
}


static void
test_construct_ofp_match() {
  oxm_matches *expected;
  uint8_t d_48bit[ OFP_ETH_ALEN ];
  uint8_t m_48bit[ OFP_ETH_ALEN ];

  memcpy( d_48bit, data_48bit, sizeof( d_48bit ) );
  memcpy( m_48bit, mask_48bit, sizeof( m_48bit ) );

  expect_assert_failure( construct_ofp_match( NULL, NULL ) );

  {
    expected = create_oxm_matches();

    append_oxm_match_in_port( expected, data_32bit );
    append_oxm_match_in_phy_port( expected, data_32bit );
    append_oxm_match_metadata( expected, data_64bit, data_64bit );
    append_oxm_match_eth_dst( expected, d_48bit, m_48bit );
    append_oxm_match_eth_src( expected, d_48bit, m_48bit );
    append_oxm_match_eth_type( expected, data_16bit );
    append_oxm_match_vlan_vid( expected, data_16bit, mask_16bit );
    append_oxm_match_vlan_pcp( expected, data_8bit );
    append_oxm_match_ip_dscp( expected, data_8bit );
    append_oxm_match_ip_ecn( expected, data_8bit );
    append_oxm_match_ip_proto( expected, data_8bit );
    append_oxm_match_ipv4_src( expected, data_32bit, mask_32bit );
    append_oxm_match_ipv4_dst( expected, data_32bit, mask_32bit );
    append_oxm_match_tcp_src( expected, data_16bit );
    append_oxm_match_tcp_dst( expected, data_16bit );
    append_oxm_match_udp_src( expected, data_16bit );
    append_oxm_match_udp_dst( expected, data_16bit );
    append_oxm_match_sctp_src( expected, data_16bit );
    append_oxm_match_sctp_dst( expected, data_16bit );
    append_oxm_match_icmpv4_type( expected, data_8bit );
    append_oxm_match_icmpv4_code( expected, data_8bit );
    append_oxm_match_arp_op( expected, data_16bit );
    append_oxm_match_arp_spa( expected, data_32bit, mask_32bit );
    append_oxm_match_arp_tpa( expected, data_32bit, mask_32bit );
    append_oxm_match_arp_sha( expected, d_48bit, m_48bit );
    append_oxm_match_arp_tha( expected, d_48bit, m_48bit );
    append_oxm_match_ipv6_src( expected, data_128bit, mask_128bit );
    append_oxm_match_ipv6_dst( expected, data_128bit, mask_128bit );
    append_oxm_match_ipv6_flabel( expected, data_32bit, mask_32bit );
    append_oxm_match_icmpv6_type( expected, data_8bit );
    append_oxm_match_icmpv6_code( expected, data_8bit );
    append_oxm_match_ipv6_nd_target( expected, data_128bit );
    append_oxm_match_ipv6_nd_sll( expected, d_48bit );
    append_oxm_match_ipv6_nd_tll( expected, d_48bit );
    append_oxm_match_mpls_label( expected, data_32bit );
    append_oxm_match_mpls_tc( expected, data_8bit );
    append_oxm_match_mpls_bos( expected, data_8bit );
    append_oxm_match_pbb_isid( expected, data_32bit, mask_32bit );
    append_oxm_match_tunnel_id( expected, data_64bit, mask_64bit );
    append_oxm_match_ipv6_exthdr( expected, data_16bit, mask_16bit );

    uint16_t match_len = ( uint16_t ) ( sizeof( oxm_match_header ) + get_oxm_matches_length( expected ) );
    uint16_t alloc_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );
    struct ofp_match *output_match = xcalloc( 1, alloc_len );

    construct_ofp_match( output_match, expected );

    assert_int_equal( ntohs( output_match->type ), OFPMT_OXM );
    assert_int_equal( ntohs( output_match->length ), match_len );

    list_element *expected_list = expected->list;

    oxm_match_header *output_oxm = ( oxm_match_header * ) output_match->oxm_fields;

    while ( expected_list != NULL ) {
      oxm_match_header *expected_oxm;

      expected_oxm = expected_list->data;

      uint16_t oxm_len = ( uint16_t ) ( sizeof( oxm_match_header ) + OXM_LENGTH( *expected_oxm ) );
      hton_oxm_match( expected_oxm, expected_oxm );

      assert_memory_equal( output_oxm, expected_oxm, oxm_len );

      output_oxm = ( oxm_match_header * ) ( ( char * ) output_oxm + oxm_len );
      expected_list = expected_list->next;
    }

    uint16_t pad_len = PADLEN_TO_64( match_len );
    if ( pad_len > 0 ) {
      void *pad = xmalloc( pad_len );
      memset( pad, 0, pad_len );
      assert_memory_equal( ( char * ) output_match + match_len, pad, pad_len );
      xfree( pad );
    }

    xfree( output_match );
    delete_oxm_matches( expected );
  }
}


static void
test_duplicate_oxm_matches() {
  oxm_matches *expected;
  uint8_t d_48bit[ OFP_ETH_ALEN ];
  uint8_t m_48bit[ OFP_ETH_ALEN ];

  memcpy( d_48bit, data_48bit, sizeof( d_48bit ) );
  memcpy( m_48bit, mask_48bit, sizeof( m_48bit ) );

  expect_assert_failure( duplicate_oxm_matches( NULL ) );

  {
    expected = create_oxm_matches();

    append_oxm_match_in_port( expected, data_32bit );
    append_oxm_match_in_phy_port( expected, data_32bit );
    append_oxm_match_metadata( expected, data_64bit, data_64bit );
    append_oxm_match_eth_dst( expected, d_48bit, m_48bit );
    append_oxm_match_eth_src( expected, d_48bit, m_48bit );
    append_oxm_match_eth_type( expected, data_16bit );
    append_oxm_match_vlan_vid( expected, data_16bit, mask_16bit );
    append_oxm_match_vlan_pcp( expected, data_8bit );
    append_oxm_match_ip_dscp( expected, data_8bit );
    append_oxm_match_ip_ecn( expected, data_8bit );
    append_oxm_match_ip_proto( expected, data_8bit );
    append_oxm_match_ipv4_src( expected, data_32bit, mask_32bit );
    append_oxm_match_ipv4_dst( expected, data_32bit, mask_32bit );
    append_oxm_match_tcp_src( expected, data_16bit );
    append_oxm_match_tcp_dst( expected, data_16bit );
    append_oxm_match_udp_src( expected, data_16bit );
    append_oxm_match_udp_dst( expected, data_16bit );
    append_oxm_match_sctp_src( expected, data_16bit );
    append_oxm_match_sctp_dst( expected, data_16bit );
    append_oxm_match_icmpv4_type( expected, data_8bit );
    append_oxm_match_icmpv4_code( expected, data_8bit );
    append_oxm_match_arp_op( expected, data_16bit );
    append_oxm_match_arp_spa( expected, data_32bit, mask_32bit );
    append_oxm_match_arp_tpa( expected, data_32bit, mask_32bit );
    append_oxm_match_arp_sha( expected, d_48bit, m_48bit );
    append_oxm_match_arp_tha( expected, d_48bit, m_48bit );
    append_oxm_match_ipv6_src( expected, data_128bit, mask_128bit );
    append_oxm_match_ipv6_dst( expected, data_128bit, mask_128bit );
    append_oxm_match_ipv6_flabel( expected, data_32bit, mask_32bit );
    append_oxm_match_icmpv6_type( expected, data_8bit );
    append_oxm_match_icmpv6_code( expected, data_8bit );
    append_oxm_match_ipv6_nd_target( expected, data_128bit );
    append_oxm_match_ipv6_nd_sll( expected, d_48bit );
    append_oxm_match_ipv6_nd_tll( expected, d_48bit );
    append_oxm_match_mpls_label( expected, data_32bit );
    append_oxm_match_mpls_tc( expected, data_8bit );
    append_oxm_match_mpls_bos( expected, data_8bit );
    append_oxm_match_pbb_isid( expected, data_32bit, mask_32bit );
    append_oxm_match_tunnel_id( expected, data_64bit, mask_64bit );
    append_oxm_match_ipv6_exthdr( expected, data_16bit, mask_16bit );

    oxm_matches *output = duplicate_oxm_matches( expected );
    assert_true( output != NULL );
    assert_int_equal( output->n_matches, expected->n_matches );

    uint16_t num = 0;
    list_element *output_list, *expected_list;
    output_list = output->list;
    expected_list = expected->list;
    while ( expected_list != NULL ) {
      assert_true( output_list != NULL );

      oxm_match_header *output_oxm, *expected_oxm;
      output_oxm = output_list->data;
      expected_oxm = expected_list->data;

      uint16_t oxm_len = OXM_LENGTH( *expected_oxm );
      assert_memory_equal( output_oxm, expected_oxm, oxm_len );

      output_list = output_list->next;
      expected_list = expected_list->next;
      num++;
    }

    assert_int_equal( output->n_matches, num );
    assert_true( output_list == NULL );

    delete_oxm_matches( expected );
    delete_oxm_matches( output );
  }
}


static void
test_compare_oxm_match_with_in_port() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_in_port( x, 1 );
  append_oxm_match_in_port( y, 1 );
  append_oxm_match_in_port( z, 2 );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_in_phy_port() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_in_phy_port( x, 1 );
  append_oxm_match_in_phy_port( y, 1 );
  append_oxm_match_in_phy_port( z, 2 );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_metadata() {
  oxm_matches *x, *y, *z;
  {
    uint64_t x_data = 0xffffffffffffffff;
    uint64_t y_data = 0xffffffffffffffff;
    uint64_t z_data = 0xfffffffffffffffe;

    uint64_t x_mask = 0;
    uint64_t y_mask = 0;
    uint64_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_metadata( x, x_data, x_mask );
    append_oxm_match_metadata( y, y_data, y_mask );
    append_oxm_match_metadata( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_false( compare_oxm_match( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_true( compare_oxm_match( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint64_t x_data = 0xffffffffffffffff;
    uint64_t y_data = 0xffffffffffffffff;
    uint64_t z_data = 0xfffffffffffffffe;

    uint64_t x_mask = 0xfffffffffffffffe;
    uint64_t y_mask = 0xfffffffffffffffe;
    uint64_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_metadata( x, x_data, x_mask );
    append_oxm_match_metadata( y, y_data, y_mask );
    append_oxm_match_metadata( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_true( compare_oxm_match( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_with_eth_dst() {
  oxm_matches *x, *y, *z;
  {
    uint8_t x_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t y_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t z_data[6] = { 0x11, 0x22, 0x00, 0x44, 0x55, 0x66 };

    uint8_t x_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t y_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t z_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_eth_dst( x, x_data, x_mask );
    append_oxm_match_eth_dst( y, y_data, y_mask );
    append_oxm_match_eth_dst( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_false( compare_oxm_match( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_true( compare_oxm_match( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint8_t x_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t y_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t z_data[6] = { 0x11, 0x22, 0x00, 0x44, 0x55, 0x66 };

    uint8_t x_mask[6] = { 0xff, 0xff, 0x00, 0xff, 0xff, 0xff };
    uint8_t y_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t z_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_eth_dst( x, x_data, x_mask );
    append_oxm_match_eth_dst( y, y_data, y_mask );
    append_oxm_match_eth_dst( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_true( compare_oxm_match( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_with_eth_src() {
  oxm_matches *x, *y, *z;
  {
    uint8_t x_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t y_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t z_data[6] = { 0x11, 0x22, 0x00, 0x44, 0x55, 0x66 };

    uint8_t x_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t y_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t z_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_eth_src( x, x_data, x_mask );
    append_oxm_match_eth_src( y, y_data, y_mask );
    append_oxm_match_eth_src( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_false( compare_oxm_match( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_true( compare_oxm_match( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint8_t x_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t y_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t z_data[6] = { 0x11, 0x22, 0x00, 0x44, 0x55, 0x66 };

    uint8_t x_mask[6] = { 0xff, 0xff, 0x00, 0xff, 0xff, 0xff };
    uint8_t y_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t z_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_eth_src( x, x_data, x_mask );
    append_oxm_match_eth_src( y, y_data, y_mask );
    append_oxm_match_eth_src( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_true( compare_oxm_match( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_with_eth_type() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_eth_type( x, 1 );
  append_oxm_match_eth_type( y, 1 );
  append_oxm_match_eth_type( z, 2 );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_in_port( y, 10 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_vlan_vid() {
  oxm_matches *x, *y, *z;
  {
    uint16_t x_data = 0xffff;
    uint16_t y_data = 0xffff;
    uint16_t z_data = 0xfffe;

    uint16_t x_mask = 0;
    uint16_t y_mask = 0;
    uint16_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_vlan_vid( x, x_data, x_mask );
    append_oxm_match_vlan_vid( y, y_data, y_mask );
    append_oxm_match_vlan_vid( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_false( compare_oxm_match( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_true( compare_oxm_match( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint16_t x_data = 0xffff;
    uint16_t y_data = 0xffff;
    uint16_t z_data = 0xfffe;

    uint16_t x_mask = 0xfffe;
    uint16_t y_mask = 0xfffe;
    uint16_t z_mask = 0;


    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_vlan_vid( x, x_data, x_mask );
    append_oxm_match_vlan_vid( y, y_data, y_mask );
    append_oxm_match_vlan_vid( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_true( compare_oxm_match( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_with_vlan_pcp() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_vlan_pcp( x, 1 );
  append_oxm_match_vlan_pcp( y, 1 );
  append_oxm_match_vlan_pcp( z, 2 );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_ip_dscp() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_ip_dscp( x, 1 );
  append_oxm_match_ip_dscp( y, 1 );
  append_oxm_match_ip_dscp( z, 2 );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_ip_ecn() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_ip_ecn( x, 1 );
  append_oxm_match_ip_ecn( y, 1 );
  append_oxm_match_ip_ecn( z, 2 );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_ip_proto() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_ip_proto( x, 1 );
  append_oxm_match_ip_proto( y, 1 );
  append_oxm_match_ip_proto( z, 2 );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_ipv4_src() {
  oxm_matches *x, *y, *z;
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0;
    uint32_t y_mask = 0;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv4_src( x, x_data, x_mask );
    append_oxm_match_ipv4_src( y, y_data, y_mask );
    append_oxm_match_ipv4_src( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_false( compare_oxm_match( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_true( compare_oxm_match( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0xfffffffe;
    uint32_t y_mask = 0xfffffffe;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv4_src( x, x_data, x_mask );
    append_oxm_match_ipv4_src( y, y_data, y_mask );
    append_oxm_match_ipv4_src( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_true( compare_oxm_match( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_with_ipv4_dst() {
  oxm_matches *x, *y, *z;
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0;
    uint32_t y_mask = 0;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv4_dst( x, x_data, x_mask );
    append_oxm_match_ipv4_dst( y, y_data, y_mask );
    append_oxm_match_ipv4_dst( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_false( compare_oxm_match( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_true( compare_oxm_match( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0xfffffffe;
    uint32_t y_mask = 0xfffffffe;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv4_dst( x, x_data, x_mask );
    append_oxm_match_ipv4_dst( y, y_data, y_mask );
    append_oxm_match_ipv4_dst( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_true( compare_oxm_match( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_with_tcp_src() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_tcp_src( x, 1 );
  append_oxm_match_tcp_src( y, 1 );
  append_oxm_match_tcp_src( z, 2 );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_tcp_dst() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_tcp_dst( x, 1 );
  append_oxm_match_tcp_dst( y, 1 );
  append_oxm_match_tcp_dst( z, 2 );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_udp_src() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_udp_src( x, 1 );
  append_oxm_match_udp_src( y, 1 );
  append_oxm_match_udp_src( z, 2 );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_udp_dst() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_udp_dst( x, 1 );
  append_oxm_match_udp_dst( y, 1 );
  append_oxm_match_udp_dst( z, 2 );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_sctp_src() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_sctp_src( x, 1 );
  append_oxm_match_sctp_src( y, 1 );
  append_oxm_match_sctp_src( z, 2 );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_sctp_dst() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_sctp_dst( x, 1 );
  append_oxm_match_sctp_dst( y, 1 );
  append_oxm_match_sctp_dst( z, 2 );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_icmpv4_type() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_icmpv4_type( x, 1 );
  append_oxm_match_icmpv4_type( y, 1 );
  append_oxm_match_icmpv4_type( z, 2 );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_icmpv4_code() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_icmpv4_code( x, 1 );
  append_oxm_match_icmpv4_code( y, 1 );
  append_oxm_match_icmpv4_code( z, 2 );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_arp_op() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_arp_op( x, 1 );
  append_oxm_match_arp_op( y, 1 );
  append_oxm_match_arp_op( z, 2 );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_arp_spa() {
  oxm_matches *x, *y, *z;
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0;
    uint32_t y_mask = 0;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_arp_spa( x, x_data, x_mask );
    append_oxm_match_arp_spa( y, y_data, y_mask );
    append_oxm_match_arp_spa( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_false( compare_oxm_match( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_true( compare_oxm_match( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0xfffffffe;
    uint32_t y_mask = 0xfffffffe;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_arp_spa( x, x_data, x_mask );
    append_oxm_match_arp_spa( y, y_data, y_mask );
    append_oxm_match_arp_spa( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_true( compare_oxm_match( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_with_arp_tpa() {
  oxm_matches *x, *y, *z;
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0;
    uint32_t y_mask = 0;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_arp_tpa( x, x_data, x_mask );
    append_oxm_match_arp_tpa( y, y_data, y_mask );
    append_oxm_match_arp_tpa( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_false( compare_oxm_match( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_true( compare_oxm_match( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0xfffffffe;
    uint32_t y_mask = 0xfffffffe;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_arp_tpa( x, x_data, x_mask );
    append_oxm_match_arp_tpa( y, y_data, y_mask );
    append_oxm_match_arp_tpa( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_true( compare_oxm_match( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_with_arp_sha() {
  oxm_matches *x, *y, *z;
  {
    uint8_t x_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t y_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t z_data[6] = { 0x11, 0x22, 0x00, 0x44, 0x55, 0x66 };

    uint8_t x_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t y_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t z_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_arp_sha( x, x_data, x_mask );
    append_oxm_match_arp_sha( y, y_data, y_mask );
    append_oxm_match_arp_sha( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_false( compare_oxm_match( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_true( compare_oxm_match( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint8_t x_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t y_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t z_data[6] = { 0x11, 0x22, 0x00, 0x44, 0x55, 0x66 };

    uint8_t x_mask[6] = { 0xff, 0xff, 0x00, 0xff, 0xff, 0xff };
    uint8_t y_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t z_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_arp_sha( x, x_data, x_mask );
    append_oxm_match_arp_sha( y, y_data, y_mask );
    append_oxm_match_arp_sha( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_true( compare_oxm_match( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_with_arp_tha() {
  oxm_matches *x, *y, *z;
  {
    uint8_t x_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t y_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t z_data[6] = { 0x11, 0x22, 0x00, 0x44, 0x55, 0x66 };

    uint8_t x_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t y_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t z_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_arp_tha( x, x_data, x_mask );
    append_oxm_match_arp_tha( y, y_data, y_mask );
    append_oxm_match_arp_tha( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_false( compare_oxm_match( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_true( compare_oxm_match( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint8_t x_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t y_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t z_data[6] = { 0x11, 0x22, 0x00, 0x44, 0x55, 0x66 };

    uint8_t x_mask[6] = { 0xff, 0xff, 0x00, 0xff, 0xff, 0xff };
    uint8_t y_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t z_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_arp_tha( x, x_data, x_mask );
    append_oxm_match_arp_tha( y, y_data, y_mask );
    append_oxm_match_arp_tha( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_true( compare_oxm_match( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_with_ipv6_src() {
  oxm_matches *x, *y, *z;
  {
    struct in6_addr x_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf } } };
    struct in6_addr y_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf } } };
    struct in6_addr z_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0x1 } } };

    struct in6_addr x_mask;
    struct in6_addr y_mask;
    struct in6_addr z_mask;

    memset( &x_mask, 0, sizeof( x_mask ) );
    memset( &y_mask, 0, sizeof( y_mask ) );
    memset( &z_mask, 0, sizeof( z_mask ) );

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv6_src( x, x_data, x_mask );
    append_oxm_match_ipv6_src( y, y_data, y_mask );
    append_oxm_match_ipv6_src( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_false( compare_oxm_match( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_true( compare_oxm_match( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    struct in6_addr x_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf } } };
    struct in6_addr y_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf } } };
    struct in6_addr z_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0x1 } } };

    struct in6_addr x_mask;
    struct in6_addr y_mask;
    struct in6_addr z_mask;

    memset( &x_mask, 0xff, sizeof( x_mask ) );
    memset( &y_mask, 0xff, sizeof( y_mask ) );
    memset( &z_mask, 0, sizeof( z_mask ) );

    x_mask.s6_addr[15] = 0x00;
    y_mask.s6_addr[15] = 0x00;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv6_src( x, x_data, x_mask );
    append_oxm_match_ipv6_src( y, y_data, y_mask );
    append_oxm_match_ipv6_src( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_true( compare_oxm_match( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_with_ipv6_dst() {
  oxm_matches *x, *y, *z;
  {
    struct in6_addr x_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf } } };
    struct in6_addr y_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf } } };
    struct in6_addr z_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0x1 } } };

    struct in6_addr x_mask;
    struct in6_addr y_mask;
    struct in6_addr z_mask;

    memset( &x_mask, 0, sizeof( x_mask ) );
    memset( &y_mask, 0, sizeof( y_mask ) );
    memset( &z_mask, 0, sizeof( z_mask ) );

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv6_dst( x, x_data, x_mask );
    append_oxm_match_ipv6_dst( y, y_data, y_mask );
    append_oxm_match_ipv6_dst( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_false( compare_oxm_match( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_true( compare_oxm_match( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    struct in6_addr x_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf } } };
    struct in6_addr y_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf } } };
    struct in6_addr z_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0x1 } } };

    struct in6_addr x_mask;
    struct in6_addr y_mask;
    struct in6_addr z_mask;

    memset( &x_mask, 0xff, sizeof( x_mask ) );
    memset( &y_mask, 0xff, sizeof( y_mask ) );
    memset( &z_mask, 0, sizeof( z_mask ) );

    x_mask.s6_addr[15] = 0x00;
    y_mask.s6_addr[15] = 0x00;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv6_dst( x, x_data, x_mask );
    append_oxm_match_ipv6_dst( y, y_data, y_mask );
    append_oxm_match_ipv6_dst( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_true( compare_oxm_match( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_with_ipv6_flabel() {
  oxm_matches *x, *y, *z;
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0;
    uint32_t y_mask = 0;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv6_flabel( x, x_data, x_mask );
    append_oxm_match_ipv6_flabel( y, y_data, y_mask );
    append_oxm_match_ipv6_flabel( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_false( compare_oxm_match( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_true( compare_oxm_match( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0xfffffffe;
    uint32_t y_mask = 0xfffffffe;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv6_flabel( x, x_data, x_mask );
    append_oxm_match_ipv6_flabel( y, y_data, y_mask );
    append_oxm_match_ipv6_flabel( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_true( compare_oxm_match( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_with_icmpv6_type() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_icmpv6_type( x, 1 );
  append_oxm_match_icmpv6_type( y, 1 );
  append_oxm_match_icmpv6_type( z, 2 );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_icmpv6_code() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_icmpv6_code( x, 1 );
  append_oxm_match_icmpv6_code( y, 1 );
  append_oxm_match_icmpv6_code( z, 2 );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_ipv6_nd_target() {
  oxm_matches *x, *y, *z;
  struct in6_addr x_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf } } };
  struct in6_addr y_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf } } };
  struct in6_addr z_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0x1 } } };

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_ipv6_nd_target( x, x_data );
  append_oxm_match_ipv6_nd_target( y, y_data );
  append_oxm_match_ipv6_nd_target( z, z_data );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_ipv6_nd_sll() {
  oxm_matches *x, *y, *z;
  uint8_t x_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
  uint8_t y_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
  uint8_t z_data[6] = { 0x11, 0x22, 0x00, 0x44, 0x55, 0x66 };

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_ipv6_nd_sll( x, x_data );
  append_oxm_match_ipv6_nd_sll( y, y_data );
  append_oxm_match_ipv6_nd_sll( z, z_data );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_ipv6_nd_tll() {
  oxm_matches *x, *y, *z;
  uint8_t x_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
  uint8_t y_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
  uint8_t z_data[6] = { 0x11, 0x22, 0x00, 0x44, 0x55, 0x66 };

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_ipv6_nd_tll( x, x_data );
  append_oxm_match_ipv6_nd_tll( y, y_data );
  append_oxm_match_ipv6_nd_tll( z, z_data );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_mpls_label() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_mpls_label( x, 1 );
  append_oxm_match_mpls_label( y, 1 );
  append_oxm_match_mpls_label( z, 2 );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_mpls_tc() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_mpls_tc( x, 1 );
  append_oxm_match_mpls_tc( y, 1 );
  append_oxm_match_mpls_tc( z, 2 );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_mpls_bos() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_mpls_bos( x, 1 );
  append_oxm_match_mpls_bos( y, 1 );
  append_oxm_match_mpls_bos( z, 2 );

  assert_true( compare_oxm_match( x, y ) );
  assert_false( compare_oxm_match( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_true( compare_oxm_match( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_with_pbb_isid() {
  oxm_matches *x, *y, *z;
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0;
    uint32_t y_mask = 0;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_pbb_isid( x, x_data, x_mask );
    append_oxm_match_pbb_isid( y, y_data, y_mask );
    append_oxm_match_pbb_isid( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_false( compare_oxm_match( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_true( compare_oxm_match( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0xfffffffe;
    uint32_t y_mask = 0xfffffffe;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_pbb_isid( x, x_data, x_mask );
    append_oxm_match_pbb_isid( y, y_data, y_mask );
    append_oxm_match_pbb_isid( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_true( compare_oxm_match( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_with_tunnel_id() {
  oxm_matches *x, *y, *z;
  {
    uint64_t x_data = 0xffffffffffffffff;
    uint64_t y_data = 0xffffffffffffffff;
    uint64_t z_data = 0xfffffffffffffffe;

    uint64_t x_mask = 0;
    uint64_t y_mask = 0;
    uint64_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_tunnel_id( x, x_data, x_mask );
    append_oxm_match_tunnel_id( y, y_data, y_mask );
    append_oxm_match_tunnel_id( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_false( compare_oxm_match( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_true( compare_oxm_match( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint64_t x_data = 0xffffffffffffffff;
    uint64_t y_data = 0xffffffffffffffff;
    uint64_t z_data = 0xfffffffffffffffe;

    uint64_t x_mask = 0xfffffffffffffffe;
    uint64_t y_mask = 0xfffffffffffffffe;
    uint64_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_tunnel_id( x, x_data, x_mask );
    append_oxm_match_tunnel_id( y, y_data, y_mask );
    append_oxm_match_tunnel_id( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_true( compare_oxm_match( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_with_ipv6_exthdr() {
  oxm_matches *x, *y, *z;
  {
    uint16_t x_data = 0xffff;
    uint16_t y_data = 0xffff;
    uint16_t z_data = 0xfffe;

    uint16_t x_mask = 0;
    uint16_t y_mask = 0;
    uint16_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv6_exthdr( x, x_data, x_mask );
    append_oxm_match_ipv6_exthdr( y, y_data, y_mask );
    append_oxm_match_ipv6_exthdr( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_false( compare_oxm_match( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_true( compare_oxm_match( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint16_t x_data = 0xffff;
    uint16_t y_data = 0xffff;
    uint16_t z_data = 0xfffe;

    uint16_t x_mask = 0xfffe;
    uint16_t y_mask = 0xfffe;
    uint16_t z_mask = 0;


    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv6_exthdr( x, x_data, x_mask );
    append_oxm_match_ipv6_exthdr( y, y_data, y_mask );
    append_oxm_match_ipv6_exthdr( z, z_data, z_mask );

    assert_true( compare_oxm_match( x, y ) );
    assert_true( compare_oxm_match( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_strict_with_in_port() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_in_port( x, 1 );
  append_oxm_match_in_port( y, 1 );
  append_oxm_match_in_port( z, 2 );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_in_phy_port() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_in_phy_port( x, 1 );
  append_oxm_match_in_phy_port( y, 1 );
  append_oxm_match_in_phy_port( z, 2 );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_metadata() {
  oxm_matches *x, *y, *z;
  {
    uint64_t x_data = 0xffffffffffffffff;
    uint64_t y_data = 0xffffffffffffffff;
    uint64_t z_data = 0xfffffffffffffffe;

    uint64_t x_mask = 0;
    uint64_t y_mask = 0;
    uint64_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_metadata( x, x_data, x_mask );
    append_oxm_match_metadata( y, y_data, y_mask );
    append_oxm_match_metadata( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_false( compare_oxm_match_strict( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint64_t x_data = 0xffffffffffffffff;
    uint64_t y_data = 0xffffffffffffffff;
    uint64_t z_data = 0xfffffffffffffffe;

    uint64_t x_mask = 0xfffffffffffffffe;
    uint64_t y_mask = 0xfffffffffffffffe;
    uint64_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_metadata( x, x_data, x_mask );
    append_oxm_match_metadata( y, y_data, y_mask );
    append_oxm_match_metadata( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_strict_with_eth_dst() {
  oxm_matches *x, *y, *z;
  {
    uint8_t x_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t y_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t z_data[6] = { 0x11, 0x22, 0x00, 0x44, 0x55, 0x66 };

    uint8_t x_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t y_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t z_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_eth_dst( x, x_data, x_mask );
    append_oxm_match_eth_dst( y, y_data, y_mask );
    append_oxm_match_eth_dst( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_false( compare_oxm_match_strict( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint8_t x_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t y_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t z_data[6] = { 0x11, 0x22, 0x00, 0x44, 0x55, 0x66 };

    uint8_t x_mask[6] = { 0xff, 0xff, 0x00, 0xff, 0xff, 0xff };
    uint8_t y_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t z_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_eth_dst( x, x_data, x_mask );
    append_oxm_match_eth_dst( y, y_data, y_mask );
    append_oxm_match_eth_dst( z, z_data, z_mask );

    assert_false( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_strict_with_eth_src() {
  oxm_matches *x, *y, *z;
  {
    uint8_t x_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t y_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t z_data[6] = { 0x11, 0x22, 0x00, 0x44, 0x55, 0x66 };

    uint8_t x_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t y_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t z_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_eth_src( x, x_data, x_mask );
    append_oxm_match_eth_src( y, y_data, y_mask );
    append_oxm_match_eth_src( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_false( compare_oxm_match_strict( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint8_t x_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t y_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t z_data[6] = { 0x11, 0x22, 0x00, 0x44, 0x55, 0x66 };

    uint8_t x_mask[6] = { 0xff, 0xff, 0x00, 0xff, 0xff, 0xff };
    uint8_t y_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t z_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_eth_src( x, x_data, x_mask );
    append_oxm_match_eth_src( y, y_data, y_mask );
    append_oxm_match_eth_src( z, z_data, z_mask );

    assert_false( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_strict_with_eth_type() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_eth_type( x, 1 );
  append_oxm_match_eth_type( y, 1 );
  append_oxm_match_eth_type( z, 2 );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_in_port( y, 10 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_vlan_vid() {
  oxm_matches *x, *y, *z;
  {
    uint16_t x_data = 0xffff;
    uint16_t y_data = 0xffff;
    uint16_t z_data = 0xfffe;

    uint16_t x_mask = 0;
    uint16_t y_mask = 0;
    uint16_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_vlan_vid( x, x_data, x_mask );
    append_oxm_match_vlan_vid( y, y_data, y_mask );
    append_oxm_match_vlan_vid( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_false( compare_oxm_match_strict( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint16_t x_data = 0xffff;
    uint16_t y_data = 0xffff;
    uint16_t z_data = 0xfffe;

    uint16_t x_mask = 0;
    uint16_t y_mask = 0;
    uint16_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_vlan_vid( x, x_data, x_mask );
    append_oxm_match_vlan_vid( y, y_data, y_mask );
    append_oxm_match_vlan_vid( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_strict_with_vlan_pcp() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_vlan_pcp( x, 1 );
  append_oxm_match_vlan_pcp( y, 1 );
  append_oxm_match_vlan_pcp( z, 2 );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_ip_dscp() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_ip_dscp( x, 1 );
  append_oxm_match_ip_dscp( y, 1 );
  append_oxm_match_ip_dscp( z, 2 );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_ip_ecn() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_ip_ecn( x, 1 );
  append_oxm_match_ip_ecn( y, 1 );
  append_oxm_match_ip_ecn( z, 2 );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_ip_proto() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_ip_proto( x, 1 );
  append_oxm_match_ip_proto( y, 1 );
  append_oxm_match_ip_proto( z, 2 );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_ipv4_src() {
  oxm_matches *x, *y, *z;
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0;
    uint32_t y_mask = 0;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv4_src( x, x_data, x_mask );
    append_oxm_match_ipv4_src( y, y_data, y_mask );
    append_oxm_match_ipv4_src( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_false( compare_oxm_match_strict( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0xfffffffe;
    uint32_t y_mask = 0xfffffffe;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv4_src( x, x_data, x_mask );
    append_oxm_match_ipv4_src( y, y_data, y_mask );
    append_oxm_match_ipv4_src( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_strict_with_ipv4_dst() {
  oxm_matches *x, *y, *z;
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0;
    uint32_t y_mask = 0;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv4_dst( x, x_data, x_mask );
    append_oxm_match_ipv4_dst( y, y_data, y_mask );
    append_oxm_match_ipv4_dst( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_false( compare_oxm_match_strict( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0xfffffffe;
    uint32_t y_mask = 0xfffffffe;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv4_dst( x, x_data, x_mask );
    append_oxm_match_ipv4_dst( y, y_data, y_mask );
    append_oxm_match_ipv4_dst( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_strict_with_tcp_src() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_tcp_src( x, 1 );
  append_oxm_match_tcp_src( y, 1 );
  append_oxm_match_tcp_src( z, 2 );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_tcp_dst() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_tcp_dst( x, 1 );
  append_oxm_match_tcp_dst( y, 1 );
  append_oxm_match_tcp_dst( z, 2 );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_udp_src() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_udp_src( x, 1 );
  append_oxm_match_udp_src( y, 1 );
  append_oxm_match_udp_src( z, 2 );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_udp_dst() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_udp_dst( x, 1 );
  append_oxm_match_udp_dst( y, 1 );
  append_oxm_match_udp_dst( z, 2 );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_sctp_src() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_sctp_src( x, 1 );
  append_oxm_match_sctp_src( y, 1 );
  append_oxm_match_sctp_src( z, 2 );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_sctp_dst() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_sctp_dst( x, 1 );
  append_oxm_match_sctp_dst( y, 1 );
  append_oxm_match_sctp_dst( z, 2 );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_icmpv4_type() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_icmpv4_type( x, 1 );
  append_oxm_match_icmpv4_type( y, 1 );
  append_oxm_match_icmpv4_type( z, 2 );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_icmpv4_code() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_icmpv4_code( x, 1 );
  append_oxm_match_icmpv4_code( y, 1 );
  append_oxm_match_icmpv4_code( z, 2 );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_arp_op() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_arp_op( x, 1 );
  append_oxm_match_arp_op( y, 1 );
  append_oxm_match_arp_op( z, 2 );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_arp_spa() {
  oxm_matches *x, *y, *z;
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0;
    uint32_t y_mask = 0;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_arp_spa( x, x_data, x_mask );
    append_oxm_match_arp_spa( y, y_data, y_mask );
    append_oxm_match_arp_spa( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_false( compare_oxm_match_strict( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0xfffffffe;
    uint32_t y_mask = 0xfffffffe;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_arp_spa( x, x_data, x_mask );
    append_oxm_match_arp_spa( y, y_data, y_mask );
    append_oxm_match_arp_spa( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_strict_with_arp_tpa() {
  oxm_matches *x, *y, *z;
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0;
    uint32_t y_mask = 0;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_arp_tpa( x, x_data, x_mask );
    append_oxm_match_arp_tpa( y, y_data, y_mask );
    append_oxm_match_arp_tpa( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_false( compare_oxm_match_strict( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0xfffffffe;
    uint32_t y_mask = 0xfffffffe;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_arp_tpa( x, x_data, x_mask );
    append_oxm_match_arp_tpa( y, y_data, y_mask );
    append_oxm_match_arp_tpa( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_strict_with_arp_sha() {
  oxm_matches *x, *y, *z;
  {
    uint8_t x_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t y_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t z_data[6] = { 0x11, 0x22, 0x00, 0x44, 0x55, 0x66 };

    uint8_t x_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t y_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t z_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_arp_sha( x, x_data, x_mask );
    append_oxm_match_arp_sha( y, y_data, y_mask );
    append_oxm_match_arp_sha( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_false( compare_oxm_match_strict( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint8_t x_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t y_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t z_data[6] = { 0x11, 0x22, 0x00, 0x44, 0x55, 0x66 };

    uint8_t x_mask[6] = { 0xff, 0xff, 0x00, 0xff, 0xff, 0xff };
    uint8_t y_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t z_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_arp_sha( x, x_data, x_mask );
    append_oxm_match_arp_sha( y, y_data, y_mask );
    append_oxm_match_arp_sha( z, z_data, z_mask );

    assert_false( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_strict_with_arp_tha() {
  oxm_matches *x, *y, *z;
  {
    uint8_t x_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t y_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t z_data[6] = { 0x11, 0x22, 0x00, 0x44, 0x55, 0x66 };

    uint8_t x_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t y_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t z_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_arp_tha( x, x_data, x_mask );
    append_oxm_match_arp_tha( y, y_data, y_mask );
    append_oxm_match_arp_tha( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_false( compare_oxm_match_strict( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint8_t x_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t y_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t z_data[6] = { 0x11, 0x22, 0x00, 0x44, 0x55, 0x66 };

    uint8_t x_mask[6] = { 0xff, 0xff, 0x00, 0xff, 0xff, 0xff };
    uint8_t y_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t z_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_arp_tha( x, x_data, x_mask );
    append_oxm_match_arp_tha( y, y_data, y_mask );
    append_oxm_match_arp_tha( z, z_data, z_mask );

    assert_false( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_strict_with_ipv6_src() {
  oxm_matches *x, *y, *z;
  {
    struct in6_addr x_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf } } };
    struct in6_addr y_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf } } };
    struct in6_addr z_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0x1 } } };

    struct in6_addr x_mask;
    struct in6_addr y_mask;
    struct in6_addr z_mask;

    memset( &x_mask, 0, sizeof( x_mask ) );
    memset( &y_mask, 0, sizeof( y_mask ) );
    memset( &z_mask, 0, sizeof( z_mask ) );

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv6_src( x, x_data, x_mask );
    append_oxm_match_ipv6_src( y, y_data, y_mask );
    append_oxm_match_ipv6_src( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_false( compare_oxm_match_strict( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    struct in6_addr x_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf } } };
    struct in6_addr y_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf } } };
    struct in6_addr z_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0x1 } } };

    struct in6_addr x_mask;
    struct in6_addr y_mask;
    struct in6_addr z_mask;

    memset( &x_mask, 0xff, sizeof( x_mask ) );
    memset( &y_mask, 0xff, sizeof( y_mask ) );
    memset( &z_mask, 0, sizeof( z_mask ) );

    x_mask.s6_addr[15] = 0x00;
    y_mask.s6_addr[15] = 0x00;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv6_src( x, x_data, x_mask );
    append_oxm_match_ipv6_src( y, y_data, y_mask );
    append_oxm_match_ipv6_src( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_strict_with_ipv6_dst() {
  oxm_matches *x, *y, *z;
  {
    struct in6_addr x_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf } } };
    struct in6_addr y_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf } } };
    struct in6_addr z_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0x1 } } };

    struct in6_addr x_mask;
    struct in6_addr y_mask;
    struct in6_addr z_mask;

    memset( &x_mask, 0, sizeof( x_mask ) );
    memset( &y_mask, 0, sizeof( y_mask ) );
    memset( &z_mask, 0, sizeof( z_mask ) );

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv6_dst( x, x_data, x_mask );
    append_oxm_match_ipv6_dst( y, y_data, y_mask );
    append_oxm_match_ipv6_dst( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_false( compare_oxm_match_strict( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    struct in6_addr x_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf } } };
    struct in6_addr y_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf } } };
    struct in6_addr z_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0x1 } } };

    struct in6_addr x_mask;
    struct in6_addr y_mask;
    struct in6_addr z_mask;

    memset( &x_mask, 0xff, sizeof( x_mask ) );
    memset( &y_mask, 0xff, sizeof( y_mask ) );
    memset( &z_mask, 0, sizeof( z_mask ) );

    x_mask.s6_addr[15] = 0x00;
    y_mask.s6_addr[15] = 0x00;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv6_dst( x, x_data, x_mask );
    append_oxm_match_ipv6_dst( y, y_data, y_mask );
    append_oxm_match_ipv6_dst( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_strict_with_ipv6_flabel() {
  oxm_matches *x, *y, *z;
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0;
    uint32_t y_mask = 0;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv6_flabel( x, x_data, x_mask );
    append_oxm_match_ipv6_flabel( y, y_data, y_mask );
    append_oxm_match_ipv6_flabel( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_false( compare_oxm_match_strict( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0xfffffffe;
    uint32_t y_mask = 0xfffffffe;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv6_flabel( x, x_data, x_mask );
    append_oxm_match_ipv6_flabel( y, y_data, y_mask );
    append_oxm_match_ipv6_flabel( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_strict_with_icmpv6_type() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_icmpv6_type( x, 1 );
  append_oxm_match_icmpv6_type( y, 1 );
  append_oxm_match_icmpv6_type( z, 2 );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_icmpv6_code() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_icmpv6_code( x, 1 );
  append_oxm_match_icmpv6_code( y, 1 );
  append_oxm_match_icmpv6_code( z, 2 );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_ipv6_nd_target() {
  oxm_matches *x, *y, *z;
  struct in6_addr x_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf } } };
  struct in6_addr y_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf } } };
  struct in6_addr z_data = { { { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0x1 } } };

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_ipv6_nd_target( x, x_data );
  append_oxm_match_ipv6_nd_target( y, y_data );
  append_oxm_match_ipv6_nd_target( z, z_data );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_ipv6_nd_sll() {
  oxm_matches *x, *y, *z;
  uint8_t x_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
  uint8_t y_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
  uint8_t z_data[6] = { 0x11, 0x22, 0x00, 0x44, 0x55, 0x66 };

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_ipv6_nd_sll( x, x_data );
  append_oxm_match_ipv6_nd_sll( y, y_data );
  append_oxm_match_ipv6_nd_sll( z, z_data );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_ipv6_nd_tll() {
  oxm_matches *x, *y, *z;
  uint8_t x_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
  uint8_t y_data[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
  uint8_t z_data[6] = { 0x11, 0x22, 0x00, 0x44, 0x55, 0x66 };

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_ipv6_nd_tll( x, x_data );
  append_oxm_match_ipv6_nd_tll( y, y_data );
  append_oxm_match_ipv6_nd_tll( z, z_data );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_mpls_label() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_mpls_label( x, 1 );
  append_oxm_match_mpls_label( y, 1 );
  append_oxm_match_mpls_label( z, 2 );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_mpls_tc() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_mpls_tc( x, 1 );
  append_oxm_match_mpls_tc( y, 1 );
  append_oxm_match_mpls_tc( z, 2 );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_mpls_bos() {
  oxm_matches *x, *y, *z;

  x = create_oxm_matches();
  y = create_oxm_matches();
  z = create_oxm_matches();

  append_oxm_match_mpls_bos( x, 1 );
  append_oxm_match_mpls_bos( y, 1 );
  append_oxm_match_mpls_bos( z, 2 );

  assert_true( compare_oxm_match_strict( x, y ) );
  assert_false( compare_oxm_match_strict( x, z ) );

  append_oxm_match_eth_type( y, 0x0800 );

  assert_false( compare_oxm_match_strict( x, y ) );

  delete_oxm_matches( x );
  delete_oxm_matches( y );
  delete_oxm_matches( z );
}


static void
test_compare_oxm_match_strict_with_pbb_isid() {
  oxm_matches *x, *y, *z;
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0;
    uint32_t y_mask = 0;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_pbb_isid( x, x_data, x_mask );
    append_oxm_match_pbb_isid( y, y_data, y_mask );
    append_oxm_match_pbb_isid( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_false( compare_oxm_match_strict( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint32_t x_data = 0xfca80003;
    uint32_t y_data = 0xfca80003;
    uint32_t z_data = 0xfca80002;

    uint32_t x_mask = 0xfffffffe;
    uint32_t y_mask = 0xfffffffe;
    uint32_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_pbb_isid( x, x_data, x_mask );
    append_oxm_match_pbb_isid( y, y_data, y_mask );
    append_oxm_match_pbb_isid( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_strict_with_tunnel_id() {
  oxm_matches *x, *y, *z;
  {
    uint64_t x_data = 0xffffffffffffffff;
    uint64_t y_data = 0xffffffffffffffff;
    uint64_t z_data = 0xfffffffffffffffe;

    uint64_t x_mask = 0;
    uint64_t y_mask = 0;
    uint64_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_tunnel_id( x, x_data, x_mask );
    append_oxm_match_tunnel_id( y, y_data, y_mask );
    append_oxm_match_tunnel_id( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_false( compare_oxm_match_strict( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint64_t x_data = 0xffffffffffffffff;
    uint64_t y_data = 0xffffffffffffffff;
    uint64_t z_data = 0xfffffffffffffffe;

    uint64_t x_mask = 0xfffffffffffffffe;
    uint64_t y_mask = 0xfffffffffffffffe;
    uint64_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_tunnel_id( x, x_data, x_mask );
    append_oxm_match_tunnel_id( y, y_data, y_mask );
    append_oxm_match_tunnel_id( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


static void
test_compare_oxm_match_strict_with_ipv6_exthdr() {
  oxm_matches *x, *y, *z;
  {
    uint16_t x_data = 0xffff;
    uint16_t y_data = 0xffff;
    uint16_t z_data = 0xfffe;

    uint16_t x_mask = 0;
    uint16_t y_mask = 0;
    uint16_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv6_exthdr( x, x_data, x_mask );
    append_oxm_match_ipv6_exthdr( y, y_data, y_mask );
    append_oxm_match_ipv6_exthdr( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    append_oxm_match_eth_type( y, 0x0800 );

    assert_false( compare_oxm_match_strict( x, y ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
  {
    uint16_t x_data = 0xffff;
    uint16_t y_data = 0xffff;
    uint16_t z_data = 0xfffe;

    uint16_t x_mask = 0xfffe;
    uint16_t y_mask = 0xfffe;
    uint16_t z_mask = 0;

    x = create_oxm_matches();
    y = create_oxm_matches();
    z = create_oxm_matches();

    append_oxm_match_ipv6_exthdr( x, x_data, x_mask );
    append_oxm_match_ipv6_exthdr( y, y_data, y_mask );
    append_oxm_match_ipv6_exthdr( z, z_data, z_mask );

    assert_true( compare_oxm_match_strict( x, y ) );
    assert_false( compare_oxm_match_strict( x, z ) );

    delete_oxm_matches( x );
    delete_oxm_matches( y );
    delete_oxm_matches( z );
  }
}


/********************************************************************************
 * Run tests.
 ********************************************************************************/

int
main() {
  const UnitTest tests[] = {
    unit_test( test_create_and_delete_oxm_matches ),
    unit_test( test_get_oxm_matches_length ),
    unit_test( test_append_oxm_match ),
    unit_test( test_append_oxm_match_8 ),
    unit_test( test_append_oxm_match_16 ),
    unit_test( test_append_oxm_match_16w ),
    unit_test( test_append_oxm_match_32 ),
    unit_test( test_append_oxm_match_32w ),
    unit_test( test_append_oxm_match_64 ),
    unit_test( test_append_oxm_match_64w ),
    unit_test( test_append_oxm_match_eth_addr ),
    unit_test( test_append_oxm_match_eth_addr_w ),
    unit_test( test_append_oxm_match_ipv6_addr ),
    unit_test( test_append_oxm_match_in_port ),
    unit_test( test_append_oxm_match_in_phy_port ),
    unit_test( test_append_oxm_match_metadata ),
    unit_test( test_append_oxm_match_eth_dst ),
    unit_test( test_append_oxm_match_eth_src ),
    unit_test( test_append_oxm_match_eth_type ),
    unit_test( test_append_oxm_match_vlan_vid ),
    unit_test( test_append_oxm_match_vlan_pcp ),
    unit_test( test_append_oxm_match_ip_dscp ),
    unit_test( test_append_oxm_match_ip_ecn ),
    unit_test( test_append_oxm_match_ip_proto ),
    unit_test( test_append_oxm_match_ipv4_src ),
    unit_test( test_append_oxm_match_ipv4_dst ),
    unit_test( test_append_oxm_match_tcp_src ),
    unit_test( test_append_oxm_match_tcp_dst ),
    unit_test( test_append_oxm_match_udp_src ),
    unit_test( test_append_oxm_match_udp_dst ),
    unit_test( test_append_oxm_match_sctp_src ),
    unit_test( test_append_oxm_match_sctp_dst ),
    unit_test( test_append_oxm_match_icmpv4_type ),
    unit_test( test_append_oxm_match_icmpv4_code ),
    unit_test( test_append_oxm_match_arp_op ),
    unit_test( test_append_oxm_match_arp_spa ),
    unit_test( test_append_oxm_match_arp_tpa ),
    unit_test( test_append_oxm_match_arp_sha ),
    unit_test( test_append_oxm_match_arp_tha ),
    unit_test( test_append_oxm_match_ipv6_src ),
    unit_test( test_append_oxm_match_ipv6_dst ),
    unit_test( test_append_oxm_match_ipv6_flabel ),
    unit_test( test_append_oxm_match_icmpv6_type ),
    unit_test( test_append_oxm_match_icmpv6_code ),
    unit_test( test_append_oxm_match_ipv6_nd_target ),
    unit_test( test_append_oxm_match_ipv6_nd_sll ),
    unit_test( test_append_oxm_match_ipv6_nd_tll ),
    unit_test( test_append_oxm_match_mpls_label ),
    unit_test( test_append_oxm_match_mpls_tc ),
    unit_test( test_append_oxm_match_mpls_bos ),
    unit_test( test_append_oxm_match_pbb_isid ),
    unit_test( test_append_oxm_match_tunnel_id ),
    unit_test( test_append_oxm_match_ipv6_exthdr ),

    unit_test( test_parse_ofp_match ),
    unit_test( test_construct_ofp_match ),
    unit_test( test_duplicate_oxm_matches ),

    unit_test( test_compare_oxm_match_with_in_port ),
    unit_test( test_compare_oxm_match_with_in_phy_port ),
    unit_test( test_compare_oxm_match_with_metadata ),
    unit_test( test_compare_oxm_match_with_eth_dst ),
    unit_test( test_compare_oxm_match_with_eth_src ),
    unit_test( test_compare_oxm_match_with_eth_type ),
    unit_test( test_compare_oxm_match_with_vlan_vid ),
    unit_test( test_compare_oxm_match_with_vlan_pcp ),
    unit_test( test_compare_oxm_match_with_ip_dscp ),
    unit_test( test_compare_oxm_match_with_ip_ecn ),
    unit_test( test_compare_oxm_match_with_ip_proto ),
    unit_test( test_compare_oxm_match_with_ipv4_src ),
    unit_test( test_compare_oxm_match_with_ipv4_dst ),
    unit_test( test_compare_oxm_match_with_tcp_src ),
    unit_test( test_compare_oxm_match_with_tcp_dst ),
    unit_test( test_compare_oxm_match_with_udp_src ),
    unit_test( test_compare_oxm_match_with_udp_dst ),
    unit_test( test_compare_oxm_match_with_sctp_src ),
    unit_test( test_compare_oxm_match_with_sctp_dst ),
    unit_test( test_compare_oxm_match_with_icmpv4_type ),
    unit_test( test_compare_oxm_match_with_icmpv4_code ),
    unit_test( test_compare_oxm_match_with_arp_op ),
    unit_test( test_compare_oxm_match_with_arp_spa ),
    unit_test( test_compare_oxm_match_with_arp_tpa ),
    unit_test( test_compare_oxm_match_with_arp_sha ),
    unit_test( test_compare_oxm_match_with_arp_tha ),
    unit_test( test_compare_oxm_match_with_ipv6_src ),
    unit_test( test_compare_oxm_match_with_ipv6_dst ),
    unit_test( test_compare_oxm_match_with_ipv6_flabel ),
    unit_test( test_compare_oxm_match_with_icmpv6_type ),
    unit_test( test_compare_oxm_match_with_icmpv6_code ),
    unit_test( test_compare_oxm_match_with_ipv6_nd_target ),
    unit_test( test_compare_oxm_match_with_ipv6_nd_sll ),
    unit_test( test_compare_oxm_match_with_ipv6_nd_tll ),
    unit_test( test_compare_oxm_match_with_mpls_label ),
    unit_test( test_compare_oxm_match_with_mpls_tc ),
    unit_test( test_compare_oxm_match_with_mpls_bos ),
    unit_test( test_compare_oxm_match_with_pbb_isid ),
    unit_test( test_compare_oxm_match_with_tunnel_id ),
    unit_test( test_compare_oxm_match_with_ipv6_exthdr ),
    unit_test( test_compare_oxm_match_strict_with_in_port ),
    unit_test( test_compare_oxm_match_strict_with_in_phy_port ),
    unit_test( test_compare_oxm_match_strict_with_metadata ),
    unit_test( test_compare_oxm_match_strict_with_eth_dst ),
    unit_test( test_compare_oxm_match_strict_with_eth_src ),
    unit_test( test_compare_oxm_match_strict_with_eth_type ),
    unit_test( test_compare_oxm_match_strict_with_vlan_vid ),
    unit_test( test_compare_oxm_match_strict_with_vlan_pcp ),
    unit_test( test_compare_oxm_match_strict_with_ip_dscp ),
    unit_test( test_compare_oxm_match_strict_with_ip_ecn ),
    unit_test( test_compare_oxm_match_strict_with_ip_proto ),
    unit_test( test_compare_oxm_match_strict_with_ipv4_src ),
    unit_test( test_compare_oxm_match_strict_with_ipv4_dst ),
    unit_test( test_compare_oxm_match_strict_with_tcp_src ),
    unit_test( test_compare_oxm_match_strict_with_tcp_dst ),
    unit_test( test_compare_oxm_match_strict_with_udp_src ),
    unit_test( test_compare_oxm_match_strict_with_udp_dst ),
    unit_test( test_compare_oxm_match_strict_with_sctp_src ),
    unit_test( test_compare_oxm_match_strict_with_sctp_dst ),
    unit_test( test_compare_oxm_match_strict_with_icmpv4_type ),
    unit_test( test_compare_oxm_match_strict_with_icmpv4_code ),
    unit_test( test_compare_oxm_match_strict_with_arp_op ),
    unit_test( test_compare_oxm_match_strict_with_arp_spa ),
    unit_test( test_compare_oxm_match_strict_with_arp_tpa ),
    unit_test( test_compare_oxm_match_strict_with_arp_sha ),
    unit_test( test_compare_oxm_match_strict_with_arp_tha ),
    unit_test( test_compare_oxm_match_strict_with_ipv6_src ),
    unit_test( test_compare_oxm_match_strict_with_ipv6_dst ),
    unit_test( test_compare_oxm_match_strict_with_ipv6_flabel ),
    unit_test( test_compare_oxm_match_strict_with_icmpv6_type ),
    unit_test( test_compare_oxm_match_strict_with_icmpv6_code ),
    unit_test( test_compare_oxm_match_strict_with_ipv6_nd_target ),
    unit_test( test_compare_oxm_match_strict_with_ipv6_nd_sll ),
    unit_test( test_compare_oxm_match_strict_with_ipv6_nd_tll ),
    unit_test( test_compare_oxm_match_strict_with_mpls_label ),
    unit_test( test_compare_oxm_match_strict_with_mpls_tc ),
    unit_test( test_compare_oxm_match_strict_with_mpls_bos ),
    unit_test( test_compare_oxm_match_strict_with_pbb_isid ),
    unit_test( test_compare_oxm_match_strict_with_tunnel_id ),
    unit_test( test_compare_oxm_match_strict_with_ipv6_exthdr ),
  };
  return run_tests( tests );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
