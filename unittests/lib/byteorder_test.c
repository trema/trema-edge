/*
 * Unit tests for byteorder converters.
 *
 * Author: Yasunobu Chiba
 *
 * Copyright (C) 2008-2012 NEC Corporation
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
#include <openflow.h>
#include <stdlib.h>
#include <string.h>
#include "buffer.h"
#include "byteorder.h"
#include "checks.h"
#include "cmockery_trema.h"
#include "log.h"
#include "utility.h"
#include "wrapper.h"
#include "oxm_byteorder.h"
#include "openflow_message.h"

#define FAKE_PID 1234;

pid_t
mock_getpid() {
  return FAKE_PID;
}


void
mock_die( const char *format, ... ) {
  UNUSED( format );

  mock_assert( false, "mock_die", __FILE__, __LINE__ );
}

void
mock_debug( const char *format, ... ) {
  // Do nothing.
  UNUSED( format );
}


/********************************************************************************
 * Helpers.
 ********************************************************************************/

static const uint8_t MAC_ADDR_X[ OFP_ETH_ALEN ] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x07 };
static const uint8_t MAC_ADDR_Y[ OFP_ETH_ALEN ] = { 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d };
static const uint32_t IP_ADDR_X = 0x01020304;
static const uint32_t IP_ADDR_Y = 0x0a090807;
static const uint16_t TP_PORT_X = 1024;
static const uint16_t TP_PORT_Y = 2048;
static const char *PORT_NAME = "port 1";
static const uint64_t COOKIE = 0x0102030405060708ULL;
static const uint64_t PACKET_COUNT = 10000;
static const uint64_t BYTE_COUNT = 10000000;
static const uint32_t PORT_FEATURES = ( OFPPF_10MB_HD | OFPPF_10MB_FD | OFPPF_100MB_HD |
                                        OFPPF_100MB_FD | OFPPF_1GB_HD | OFPPF_1GB_FD |
                                        OFPPF_10GB_FD | OFPPF_40GB_FD | OFPPF_100GB_FD |
                                        OFPPF_1TB_FD | OFPPF_OTHER | OFPPF_COPPER |
                                        OFPPF_FIBER | OFPPF_AUTONEG | OFPPF_PAUSE |
                                        OFPPF_PAUSE_ASYM );

extern uint16_t get_instructions_length( const openflow_instructions *instructions );

static oxm_match_header *oxm_match_testdata[2] = { NULL, NULL };
static uint16_t oxm_match_testdata_len[2] = { 0, 0 };
struct ofp_match *expected_ofp_match = NULL;
static uint16_t expected_ofp_match_len = 0;

static void
delete_oxm_match_testdata( void ) {
  if ( oxm_match_testdata[0] != NULL ) {
    xfree( oxm_match_testdata[0] );
    oxm_match_testdata[0] = NULL;
  }
  if ( oxm_match_testdata[1] != NULL ) {
    xfree( oxm_match_testdata[1] );
    oxm_match_testdata[1] = NULL;
  }
  if ( expected_ofp_match != NULL ) {
    xfree( expected_ofp_match );
    expected_ofp_match = NULL;
  }
  memset( oxm_match_testdata_len, 0, sizeof( oxm_match_testdata_len ) );
  expected_ofp_match_len = 0;
}


static void
create_oxm_match_testdata( void ) {
  uint16_t offset = sizeof( oxm_match_header );
  uint32_t type;
  uint16_t match_len;
  uint32_t *val32;
  oxm_match_header *match;
  struct ofp_match *ofp_match;
  uint16_t ofp_match_len;
  uint16_t ofp_match_len_with_pad;
  void *v;

  delete_oxm_match_testdata();

  type = OXM_OF_IN_PORT;
  match_len = ( uint16_t ) ( offset + OXM_LENGTH( type ) );
  match = ( oxm_match_header * ) xcalloc( 1, match_len );
  *match = type;
  val32 = ( uint32_t * ) ( ( char * ) match + offset );
  *val32 = 0x01020304;

  oxm_match_testdata[0] = match;
  oxm_match_testdata_len[0] = match_len;


  type = OXM_OF_IN_PHY_PORT;
  match_len = ( uint16_t ) ( offset + OXM_LENGTH( type ) );
  match = ( oxm_match_header * ) xcalloc( 1, match_len );
  *match = type;
  val32 = ( uint32_t * ) ( ( char * ) match + offset );
  *val32 = 0x05060708;

  oxm_match_testdata[1] = match;
  oxm_match_testdata_len[1] = match_len;

  ofp_match_len = ( uint16_t ) ( offsetof( struct ofp_match, oxm_fields )
                                + oxm_match_testdata_len[0]
                                + oxm_match_testdata_len[1] );
  ofp_match_len_with_pad = ( uint16_t ) ( ofp_match_len + PADLEN_TO_64( ofp_match_len ) );
  ofp_match = ( struct ofp_match * ) xcalloc( 1, ofp_match_len_with_pad );
  ofp_match->type = OFPMT_OXM;
  ofp_match->length = ofp_match_len;
  v = ( char * ) ofp_match + offsetof( struct ofp_match, oxm_fields );
  memcpy( v, oxm_match_testdata[0], oxm_match_testdata_len[0] );
  v = ( char * ) v + oxm_match_testdata_len[0];
  memcpy( v, oxm_match_testdata[1], oxm_match_testdata_len[1] );

  expected_ofp_match = ofp_match;
  expected_ofp_match_len = ofp_match_len_with_pad;
}

static struct ofp_action_header *action_testdata[2] = { NULL, NULL };
static uint16_t action_testdata_len[2] = { 0, 0 };


static void
delete_action_testdata( void ) {
  if ( action_testdata[0] != NULL ) {
    xfree( action_testdata[0] );
    action_testdata[0] = NULL;
  }
  if ( action_testdata[1] != NULL ) {
    xfree( action_testdata[1] );
    action_testdata[1] = NULL;
  }
  memset( action_testdata_len, 0, sizeof( action_testdata_len ) );
}


static void
create_action_testdata( void ) {
  uint16_t action_len;
  struct ofp_action_output *action;

  delete_action_testdata();

  action_len = ( uint16_t ) ( sizeof( struct ofp_action_output ) );
  action = ( struct ofp_action_output * ) xcalloc( 1, action_len );
  action->type = OFPAT_OUTPUT;
  action->len = action_len;
  action->port = 0x01020304;
  action->max_len = 0x0506;

  action_testdata[0] = ( struct ofp_action_header * ) action;
  action_testdata_len[0] = action_len;


  action_len = ( uint16_t ) ( sizeof( struct ofp_action_output ) );
  action = ( struct ofp_action_output * ) xcalloc( 1, action_len );
  action->type = OFPAT_OUTPUT;
  action->len = action_len;
  action->port = 0x0708090A;
  action->max_len = 0x0B0C;

  action_testdata[1] = ( struct ofp_action_header * ) action;
  action_testdata_len[1] = action_len;
}

static struct ofp_instruction *instruction_testdata[2] = { NULL, NULL };
static uint16_t instruction_testdata_len[2] = { 0, 0 };
struct ofp_instruction *expected_ofp_instruction = NULL;
static uint16_t expected_ofp_instruction_len = 0;


static void
delete_instruction_testdata( void ) {
  if ( instruction_testdata[0] != NULL ) {
    xfree( instruction_testdata[0] );
    instruction_testdata[0] = NULL;
  }
  if ( instruction_testdata[1] != NULL ) {
    xfree( instruction_testdata[1] );
    instruction_testdata[1] = NULL;
  }
  if ( expected_ofp_instruction != NULL ) {
    xfree( expected_ofp_instruction );
    expected_ofp_instruction = NULL;
  }
  memset( instruction_testdata_len, 0, sizeof( instruction_testdata_len ) );
  expected_ofp_instruction_len = 0;
}


static struct ofp_meter_band_stats *meter_band_stats_testdata[2] = { NULL, NULL };
static uint16_t meter_band_stats_testdata_len[2] = { 0, 0 };


static void
delete_meter_band_stats_testdata( void ) {
  if ( meter_band_stats_testdata[0] != NULL ) {
    xfree( meter_band_stats_testdata[0] );
    meter_band_stats_testdata[0] = NULL;
  }
  if ( meter_band_stats_testdata[1] != NULL ) {
    xfree( meter_band_stats_testdata[1] );
    meter_band_stats_testdata[1] = NULL;
  }
  memset( meter_band_stats_testdata_len, 0, sizeof( meter_band_stats_testdata_len ) );
}


static void
create_meter_band_stats_testdata( void ) {
  uint16_t option_len;
  struct ofp_meter_band_stats *option;

  delete_meter_band_stats_testdata();

  option_len = ( uint16_t ) ( sizeof( struct ofp_meter_band_stats ) );
  option = ( struct ofp_meter_band_stats * ) xcalloc( 1, option_len );
  option->packet_band_count = 0x0102030405060708ULL;
  option->byte_band_count   = 0x0203040506070809ULL;

  meter_band_stats_testdata[0] = ( struct ofp_meter_band_stats * ) option;
  meter_band_stats_testdata_len[0] = option_len;


  option_len = ( uint16_t ) ( sizeof( struct ofp_meter_band_stats ) );
  option = ( struct ofp_meter_band_stats * ) xcalloc( 1, option_len );
  option->packet_band_count = 0x030405060708090aULL;
  option->byte_band_count   = 0x0405060708090a0bULL;

  meter_band_stats_testdata[1] = ( struct ofp_meter_band_stats * ) option;
  meter_band_stats_testdata_len[1] = option_len;
}


static struct ofp_meter_band_header *meter_band_header_testdata[2] = { NULL, NULL };
static uint16_t meter_band_header_testdata_len[2] = { 0, 0 };


static void
delete_meter_band_header_testdata( void ) {
  if ( meter_band_header_testdata[0] != NULL ) {
    xfree( meter_band_header_testdata[0] );
    meter_band_header_testdata[0] = NULL;
  }
  if ( meter_band_header_testdata[1] != NULL ) {
    xfree( meter_band_header_testdata[1] );
    meter_band_header_testdata[1] = NULL;
  }
  memset( meter_band_header_testdata_len, 0, sizeof( meter_band_header_testdata_len ) );
}


static void
create_meter_band_header_testdata( void ) {
  uint16_t option_len;
  struct ofp_meter_band_header *option;

  delete_meter_band_header_testdata();

  option_len = ( uint16_t ) ( sizeof( struct ofp_meter_band_drop ) );
  option = ( struct ofp_meter_band_header * ) xcalloc( 1, option_len );
  option->type = OFPMBT_DROP;
  option->len = option_len;
  option->rate = 0x01020304;
  option->burst_size = 0x0506;

  meter_band_header_testdata[0] = ( struct ofp_meter_band_header * ) option;
  meter_band_header_testdata_len[0] = option_len;


  option_len = ( uint16_t ) ( sizeof( struct ofp_meter_band_dscp_remark ) );
  option = ( struct ofp_meter_band_header * ) xcalloc( 1, option_len );
  option->type = OFPMBT_DSCP_REMARK;
  option->len = option_len;
  option->rate = 0x0708090A;
  option->burst_size = 0x0B0C;

  meter_band_header_testdata[1] = ( struct ofp_meter_band_header * ) option;
  meter_band_header_testdata_len[1] = option_len;
}


static void
create_instruction_testdata( void ) {
  uint16_t instruction_len;
  uint16_t ofp_instruction_len;
  struct ofp_instruction *inst;
  struct ofp_instruction_meter *instruction;
  void *d;

  delete_instruction_testdata();

  instruction_len = ( uint16_t ) ( sizeof( struct ofp_instruction_meter ) );
  instruction = ( struct ofp_instruction_meter * ) xcalloc( 1, instruction_len );
  instruction->type = OFPIT_METER;
  instruction->len = instruction_len;
  instruction->meter_id = 0x01020304;

  instruction_testdata[0] = ( struct ofp_instruction * ) instruction;
  instruction_testdata_len[0] = instruction_len;


  instruction_len = ( uint16_t ) ( sizeof( struct ofp_instruction_meter ) );
  instruction = ( struct ofp_instruction_meter * ) xcalloc( 1, instruction_len );
  instruction->type = OFPIT_METER;
  instruction->len = instruction_len;
  instruction->meter_id = 0x05060708;

  instruction_testdata[1] = ( struct ofp_instruction * ) instruction;
  instruction_testdata_len[1] = instruction_len;

  ofp_instruction_len = ( uint16_t ) ( instruction_testdata_len[0] + instruction_testdata_len[1] );
  inst = ( struct ofp_instruction * ) xcalloc( 1, ofp_instruction_len );
  memcpy( inst, instruction_testdata[0], instruction_testdata_len[0] );
  d = ( char * ) inst + instruction_testdata_len[0];
  memcpy( d, instruction_testdata[1], instruction_testdata_len[1] );

  expected_ofp_instruction = inst;
  expected_ofp_instruction_len = ofp_instruction_len;
}


static struct ofp_bucket *bucket_testdata[2] = { NULL, NULL };
static uint16_t bucket_testdata_len[2] = { 0, 0 };


static void
delete_bucket_testdata( void ) {
  if ( bucket_testdata[0] != NULL ) {
    xfree( bucket_testdata[0] );
    bucket_testdata[0] = NULL;
  }
  if ( bucket_testdata[1] != NULL ) {
    xfree( bucket_testdata[1] );
    bucket_testdata[1] = NULL;
  }
  memset( bucket_testdata_len, 0, sizeof( bucket_testdata_len ) );
}


static void
create_bucket_testdata( void ) {
  uint16_t action_len;
  uint16_t bucket_len;
  struct ofp_bucket *bucket;
  struct ofp_action_output *act;

  delete_bucket_testdata();

  action_len = sizeof( struct ofp_action_output );
  bucket_len = ( uint16_t ) ( offsetof( struct ofp_bucket, actions ) + action_len );
  bucket = ( struct ofp_bucket * ) xcalloc( 1, bucket_len );
  bucket->len = bucket_len;
  bucket->weight = 0x1234;
  bucket->watch_port = 0x11223344;
  bucket->watch_group = 0x55667788;
  act = ( struct ofp_action_output * ) bucket->actions;
  act->type = OFPAT_OUTPUT;
  act->len = action_len;
  act->port = 0x01020304;
  act->max_len = 0x0506;

  bucket_testdata[0] = ( struct ofp_bucket * ) bucket;
  bucket_testdata_len[0] = bucket_len;


  action_len = sizeof( struct ofp_action_output );
  bucket_len = ( uint16_t ) ( offsetof( struct ofp_bucket, actions ) + action_len );
  bucket = ( struct ofp_bucket * ) xcalloc( 1, bucket_len );
  bucket->len = bucket_len;
  bucket->weight = 0x5678;
  bucket->watch_port = 0x12233445;
  bucket->watch_group = 0x56677889;
  act = ( struct ofp_action_output * ) bucket->actions;
  act->type = OFPAT_OUTPUT;
  act->len = action_len;
  act->port = 0x0708090A;
  act->max_len = 0x0B0C;

  bucket_testdata[1] = ( struct ofp_bucket * ) bucket;
  bucket_testdata_len[1] = bucket_len;
}


static struct ofp_action_output *
create_action_output() {
  struct ofp_action_output *action = xmalloc( sizeof( struct ofp_action_output ) );
  memset( action, 0, sizeof( struct ofp_action_output ) );

  action->type = htons( OFPAT_OUTPUT );
  action->len = htons( 16 );
  action->port = htonl( 1 );
  action->max_len = htons( 2048 );

  return action;
}


static struct ofp_action_header *
create_action_copy_ttl_out() {
  struct ofp_action_header *action = xmalloc( sizeof( struct ofp_action_header ) );
  memset( action, 0, sizeof( struct ofp_action_header ) );

  action->type = htons( OFPAT_COPY_TTL_OUT );
  action->len = htons( 8 );

  return action;
}


static struct ofp_action_header *
create_action_copy_ttl_in() {
  struct ofp_action_header *action = xmalloc( sizeof( struct ofp_action_header ) );
  memset( action, 0, sizeof( struct ofp_action_header ) );

  action->type = htons( OFPAT_COPY_TTL_IN );
  action->len = htons( 8 );

  return action;
}


static struct ofp_action_mpls_ttl *
create_action_set_mpls_ttl() {
  struct ofp_action_mpls_ttl *action = xmalloc( sizeof( struct ofp_action_mpls_ttl ) );
  memset( action, 0, sizeof( struct ofp_action_mpls_ttl ) );

  action->type = htons( OFPAT_SET_MPLS_TTL );
  action->len = htons( 8 );
  action->mpls_ttl = 255;

  return action;
}


static struct ofp_action_header *
create_action_dec_mpls_ttl() {
  struct ofp_action_header *action = xmalloc( sizeof( struct ofp_action_header ) );
  memset( action, 0, sizeof( struct ofp_action_header ) );

  action->type = htons( OFPAT_DEC_MPLS_TTL );
  action->len = htons( 8 );

  return action;
}


static struct ofp_action_push *
create_action_push_vlan() {
  struct ofp_action_push *action = xmalloc( sizeof( struct ofp_action_push ) );
  memset( action, 0, sizeof( struct ofp_action_push ) );

  action->type = htons( OFPAT_PUSH_VLAN );
  action->len = htons( 8 );
  action->ethertype = htons ( 0x0800 );

  return action;
}


static struct ofp_action_header *
create_action_pop_vlan() {
  struct ofp_action_header *action = xmalloc( sizeof( struct ofp_action_header ) );
  memset( action, 0, sizeof( struct ofp_action_header ) );

  action->type = htons( OFPAT_POP_VLAN );
  action->len = htons( 8 );

  return action;
}


static struct ofp_action_push *
create_action_push_mpls() {
  struct ofp_action_push *action = xmalloc( sizeof( struct ofp_action_push ) );
  memset( action, 0, sizeof( struct ofp_action_push ) );

  action->type = htons( OFPAT_PUSH_MPLS );
  action->len = htons( 8 );
  action->ethertype = htons ( 0x0800 );

  return action;
}


static struct ofp_action_pop_mpls *
create_action_pop_mpls() {
  struct ofp_action_pop_mpls *action = xmalloc( sizeof( struct ofp_action_pop_mpls ) );
  memset( action, 0, sizeof( struct ofp_action_pop_mpls ) );

  action->type = htons( OFPAT_POP_MPLS );
  action->len = htons( 8 );
  action->ethertype = htons ( 0x0800 );

  return action;
}


static struct ofp_action_set_queue *
create_action_set_queue() {
  struct ofp_action_set_queue *action = xmalloc( sizeof( struct ofp_action_set_queue ) );
  memset( action, 0, sizeof( struct ofp_action_set_queue ) );

  action->type = htons( OFPAT_SET_QUEUE );
  action->len = htons( 8 );
  action->queue_id = htonl( 8 );

  return action;
}


static struct ofp_action_group *
create_action_group() {
  struct ofp_action_group *action = xmalloc( sizeof( struct ofp_action_group ) );
  memset( action, 0, sizeof( struct ofp_action_group ) );

  action->type = htons( OFPAT_GROUP );
  action->len = htons( 8 );
  action->group_id = htonl( 1 );

  return action;
}


static struct ofp_action_nw_ttl *
create_action_set_nw_ttl() {
  struct ofp_action_nw_ttl *action = xmalloc( sizeof( struct ofp_action_nw_ttl ) );
  memset( action, 0, sizeof( struct ofp_action_nw_ttl ) );

  action->type = htons( OFPAT_SET_NW_TTL );
  action->len = htons( 8 );
  action->nw_ttl = 255;

  return action;
}


static struct ofp_action_header *
create_action_dec_nw_ttl() {
  struct ofp_action_header *action = xmalloc( sizeof( struct ofp_action_header ) );
  memset( action, 0, sizeof( struct ofp_action_header ) );

  action->type = htons( OFPAT_DEC_NW_TTL );
  action->len = htons( 8 );

  return action;
}


static struct ofp_action_set_field *
create_action_set_field( bool hb) {
  uint16_t len = ( uint16_t ) ( offsetof( struct ofp_action_set_field, field ) + sizeof( oxm_match_header ) + OXM_LENGTH( OXM_OF_VLAN_VID ) );
  uint16_t total_len = ( uint16_t ) ( len + PADLEN_TO_64( len ) );
  struct ofp_action_set_field *action = xcalloc( 1, total_len );

  oxm_match_header *oxm;
  uint16_t *val;
  action->type = ( uint16_t ) ( hb ? OFPAT_SET_FIELD : htons( OFPAT_SET_FIELD ) );
  action->len = ( uint16_t ) ( hb ? total_len : htons( total_len ) );
  oxm = ( oxm_match_header * ) action->field;
  *oxm = ( uint32_t ) ( hb ? OXM_OF_VLAN_VID : htonl( OXM_OF_VLAN_VID ) );
  val = ( uint16_t * ) ( oxm + 1 );
  *val = ( uint16_t ) ( hb ? 100 : htons( 100 ) );

  return action;
}


static struct ofp_action_push *
create_action_push_pbb() {
  struct ofp_action_push *action = xmalloc( sizeof( struct ofp_action_push ) );
  memset( action, 0, sizeof( struct ofp_action_push ) );

  action->type = htons( OFPAT_PUSH_PBB );
  action->len = htons( 8 );
  action->ethertype = htons ( 0x0800 );

  return action;
}


static struct ofp_action_header *
create_action_pop_pbb() {
  struct ofp_action_header *action = xmalloc( sizeof( struct ofp_action_header ) );
  memset( action, 0, sizeof( struct ofp_action_header ) );

  action->type = htons( OFPAT_POP_PBB );
  action->len = htons( 8 );

  return action;
}

static struct ofp_action_experimenter_header *
create_action_experimenter() {
  struct ofp_action_experimenter_header *action = xmalloc( sizeof( struct ofp_action_experimenter_header ) );
  memset( action, 0, sizeof( struct ofp_action_experimenter_header ) );

  action->type = htons( OFPAT_EXPERIMENTER );
  action->len = htons( 8 );
  action->experimenter = htonl( 2048 );

  return action;
}


static struct ofp_action_header *
create_action_header() {
  struct ofp_action_header *action = xmalloc( sizeof( struct ofp_action_header ) );
  memset( action, 0, sizeof( struct ofp_action_header ) );

  action->type = htons( 1 );
  action->len = htons( 8 );

  return action;
}

/********************************************************************************
 * ntoh_port() test.
 ********************************************************************************/

void
test_ntoh_port() {
  struct ofp_port dst;
  struct ofp_port src;

  memset( &src, 0, sizeof( struct ofp_port ) );
  memset( &dst, 0, sizeof( struct ofp_port ) );

  src.port_no = htonl( 1 );
  memcpy( src.hw_addr, MAC_ADDR_X, sizeof( src.hw_addr ) );
  memset( src.name, '\0', OFP_MAX_PORT_NAME_LEN );
  memcpy( src.name, PORT_NAME, strlen( PORT_NAME ) );
  src.config = htonl( OFPPC_PORT_DOWN );
  src.state = htonl( OFPPS_LINK_DOWN );
  src.curr = htonl( OFPPF_1GB_FD | OFPPF_COPPER | OFPPF_PAUSE );
  src.advertised = htonl( PORT_FEATURES );
  src.supported = htonl( PORT_FEATURES );
  src.peer = htonl( PORT_FEATURES );
  src.curr_speed = htonl( 100 );
  src.max_speed = htonl( 1000 );

  ntoh_port( &dst, &src );

  assert_int_equal( htonl( dst.port_no ), src.port_no );
  assert_memory_equal( dst.hw_addr, src.hw_addr, sizeof( src.hw_addr ) );
  assert_memory_equal( dst.name, src.name, OFP_MAX_PORT_NAME_LEN );
  assert_int_equal( ( int ) htonl( dst.config ), ( int ) src.config );
  assert_int_equal( ( int ) htonl( dst.state ), ( int ) src.state );
  assert_int_equal( ( int ) htonl( dst.curr ), ( int ) src.curr );
  assert_int_equal( ( int ) htonl( dst.advertised ), ( int ) src.advertised );
  assert_int_equal( ( int ) htonl( dst.supported ), ( int ) src.supported );
  assert_int_equal( ( int ) htonl( dst.peer ), ( int ) src.peer );
  assert_int_equal( ( int ) htonl( dst.curr_speed ), ( int ) src.curr_speed );
  assert_int_equal( ( int ) htonl( dst.max_speed ), ( int ) src.max_speed );
}


/********************************************************************************
 * ntoh_action_output() test.
 ********************************************************************************/

void
test_ntoh_action_output() {

  struct ofp_action_output dst;

  memset( &dst, 0, sizeof( struct ofp_action_output ) );

  struct ofp_action_output *src = create_action_output();

  ntoh_action_output( &dst, src );

  assert_int_equal( htons( dst.type ), src->type );
  assert_int_equal( htons( dst.len ), src->len );
  assert_int_equal( ( int ) htonl( dst.port ), ( int ) src->port );
  assert_int_equal( htons( dst.max_len ), src->max_len );

  xfree( src );
}

/********************************************************************************
 * ntoh_action_set_field() test.
 ********************************************************************************/

void
test_ntoh_action_set_field() {
  char buf[256] = {};
  struct ofp_action_set_field *dst = ( struct ofp_action_set_field * ) buf;

  struct ofp_action_set_field *src = create_action_set_field( false );
  struct ofp_action_set_field *expected = create_action_set_field( true );

  ntoh_action_set_field( dst, src );

  assert_memory_equal( dst, expected, expected->len );

  xfree( src );
  xfree( expected );
}

/********************************************************************************
 * hton_action_set_field() test.
 ********************************************************************************/

void
test_hton_action_set_field() {
  char buf[256] = {};
  struct ofp_action_set_field *dst = ( struct ofp_action_set_field * ) buf;

  struct ofp_action_set_field *src = create_action_set_field( true );
  struct ofp_action_set_field *expected = create_action_set_field( false );

  hton_action_set_field( dst, src );

  assert_memory_equal( dst, expected, ntohs( expected->len ) );

  xfree( src );
  xfree( expected );
}

/********************************************************************************
 * ntoh_action_set_queue() test.
 ********************************************************************************/

void
test_ntoh_action_set_queue() {
  struct ofp_action_set_queue dst;

  memset( &dst, 0, sizeof( struct ofp_action_set_queue ) );

  struct ofp_action_set_queue *src = create_action_set_queue();

  ntoh_action_set_queue( &dst, src );

  assert_int_equal( htons( dst.type ), src->type );
  assert_int_equal( htons( dst.len ), src->len );
  assert_int_equal( ( int ) htonl( dst.queue_id) , ( int ) src->queue_id );

  xfree( src );
}


/********************************************************************************
 * ntoh_action_experimenter() test.
 ********************************************************************************/

void
test_ntoh_action_experimenter() {
  struct ofp_action_experimenter_header dst;

  memset( &dst, 0, sizeof( struct ofp_action_experimenter_header ) );

  struct ofp_action_experimenter_header *src = create_action_experimenter();

  ntoh_action_experimenter( &dst, src );

  assert_int_equal( htons( dst.type ), src->type );
  assert_int_equal( htons( dst.len ), src->len );
  assert_int_equal( ( int ) htonl( dst.experimenter ), ( int ) src->experimenter );

  xfree( src );
}


/********************************************************************************
 * ntoh_action_mpls_ttl() test.
 ********************************************************************************/

void
test_ntoh_action_mpls_ttl() {
  struct ofp_action_mpls_ttl dst;

  memset( &dst, 0, sizeof( struct ofp_action_mpls_ttl ) );

  struct ofp_action_mpls_ttl *src = create_action_set_mpls_ttl();

  ntoh_action_mpls_ttl( &dst, src );

  assert_int_equal( htons( dst.type ), src->type );
  assert_int_equal( htons( dst.len ), src->len );
  assert_int_equal( dst.mpls_ttl, src->mpls_ttl );

  xfree( src );
}


/********************************************************************************
 * ntoh_action_push() test.
 ********************************************************************************/

void
test_ntoh_action_push() {
  {
    struct ofp_action_push dst;

    memset( &dst, 0, sizeof( struct ofp_action_push ) );

    struct ofp_action_push *src = create_action_push_vlan();

    ntoh_action_push( &dst, src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );
    assert_int_equal( htons( dst.ethertype ), src->ethertype );

    xfree( src );
  }
  {
    struct ofp_action_push dst;

    memset( &dst, 0, sizeof( struct ofp_action_push ) );

    struct ofp_action_push *src = create_action_push_mpls();

    ntoh_action_push( &dst, src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );
    assert_int_equal( htons( dst.ethertype ), src->ethertype );

    xfree( src );
  }
  {
    struct ofp_action_push dst;

    memset( &dst, 0, sizeof( struct ofp_action_push ) );

    struct ofp_action_push *src = create_action_push_pbb();

    ntoh_action_push( &dst, src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );
    assert_int_equal( htons( dst.ethertype ), src->ethertype );

    xfree( src );
  }
}


/********************************************************************************
 * ntoh_action_pop_mpls() test.
 ********************************************************************************/

void
test_ntoh_action_pop_mpls() {
  struct ofp_action_pop_mpls dst;

  memset( &dst, 0, sizeof( struct ofp_action_pop_mpls ) );

  struct ofp_action_pop_mpls *src = create_action_pop_mpls();

  ntoh_action_pop_mpls( &dst, src );

  assert_int_equal( htons( dst.type ), src->type );
  assert_int_equal( htons( dst.len ), src->len );
  assert_int_equal( htons( dst.ethertype ), src->ethertype );

  xfree( src );
}


/********************************************************************************
 * ntoh_action_group() test.
 ********************************************************************************/

void
test_ntoh_action_group() {
  struct ofp_action_group dst;

  memset( &dst, 0, sizeof( struct ofp_action_group ) );

  struct ofp_action_group *src = create_action_group();

  ntoh_action_group( &dst, src );

  assert_int_equal( htons( dst.type ), src->type );
  assert_int_equal( htons( dst.len ), src->len );
  assert_int_equal( ( int ) htonl( dst.group_id ), ( int ) src->group_id );

  xfree( src );
}


/********************************************************************************
 * ntoh_action_nw_ttl() test.
 ********************************************************************************/

void
test_ntoh_action_nw_ttl() {
  struct ofp_action_nw_ttl dst;

  memset( &dst, 0, sizeof( struct ofp_action_nw_ttl ) );

  struct ofp_action_nw_ttl *src = create_action_set_nw_ttl();

  ntoh_action_nw_ttl( &dst, src );

  assert_int_equal( htons( dst.type ), src->type );
  assert_int_equal( htons( dst.len ), src->len );
  assert_int_equal( dst.nw_ttl, src->nw_ttl );

  xfree( src );
}


/********************************************************************************
 * ntoh_action_header() test.
 ********************************************************************************/

void
test_ntoh_action_header() {
  struct ofp_action_header dst;

  memset( &dst, 0, sizeof( struct ofp_action_header ) );

  struct ofp_action_header *src = create_action_header();

  ntoh_action_header( &dst, src );

  assert_int_equal( htons( dst.type ), src->type );
  assert_int_equal( htons( dst.len ), src->len );

  xfree( src );
}


/********************************************************************************
 * ntoh_action() tests.
 ********************************************************************************/

void
test_ntoh_action() {
  {
    struct ofp_action_output dst;

    memset( &dst, 0, sizeof( struct ofp_action_output ) );

    struct ofp_action_output *src = create_action_output();

    ntoh_action( ( struct ofp_action_header * ) &dst, ( struct ofp_action_header * ) src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );
    assert_int_equal( ( int ) htonl( dst.port ), ( int ) src->port );
    assert_int_equal( htons( dst.max_len ), src->max_len );

    xfree( src );
  }

  {
    struct ofp_action_header dst;

    memset( &dst, 0, sizeof( struct ofp_action_header ) );

    struct ofp_action_header *src = create_action_copy_ttl_out();

    ntoh_action( &dst, src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );

    xfree( src );
  }

  {
    struct ofp_action_header dst;

    memset( &dst, 0, sizeof( struct ofp_action_header ) );

    struct ofp_action_header *src = create_action_copy_ttl_in();

    ntoh_action( &dst, src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );

    xfree( src );
  }

  {
    struct ofp_action_mpls_ttl dst;

    memset( &dst, 0, sizeof( struct ofp_action_mpls_ttl ) );

    struct ofp_action_mpls_ttl *src = create_action_set_mpls_ttl();

    ntoh_action( ( struct ofp_action_header * ) &dst, ( struct ofp_action_header * ) src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );
    assert_int_equal( dst.mpls_ttl, src->mpls_ttl );

    xfree( src );
  }

  {
    struct ofp_action_header dst;

    memset( &dst, 0, sizeof( struct ofp_action_header ) );

    struct ofp_action_header *src = create_action_dec_mpls_ttl();

    ntoh_action( &dst, src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );

    xfree( src );
  }

  {
    struct ofp_action_push dst;

    memset( &dst, 0, sizeof( struct ofp_action_push ) );

    struct ofp_action_push *src = create_action_push_vlan();

    ntoh_action( ( struct ofp_action_header * ) &dst, ( struct ofp_action_header * ) src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );
    assert_int_equal( htons( dst.ethertype ), src->ethertype );

    xfree( src );
  }

  {
    struct ofp_action_header dst;

    memset( &dst, 0, sizeof( struct ofp_action_header ) );

    struct ofp_action_header *src = create_action_pop_vlan();

    ntoh_action( &dst, src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );

    xfree( src );
  }

  {
    struct ofp_action_push dst;

    memset( &dst, 0, sizeof( struct ofp_action_push ) );

    struct ofp_action_push *src = create_action_push_mpls();

    ntoh_action( ( struct ofp_action_header * ) &dst, ( struct ofp_action_header * ) src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );
    assert_int_equal( htons( dst.ethertype ), src->ethertype );

    xfree( src );
  }

  {
    struct ofp_action_pop_mpls dst;

    memset( &dst, 0, sizeof( struct ofp_action_pop_mpls ) );

    struct ofp_action_pop_mpls *src = create_action_pop_mpls();

    ntoh_action( ( struct ofp_action_header * ) &dst, ( struct ofp_action_header * ) src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );
    assert_int_equal( htons( dst.ethertype ), src->ethertype );

    xfree( src );
  }

  {
    struct ofp_action_set_queue dst;

    memset( &dst, 0, sizeof( struct ofp_action_set_queue ) );

    struct ofp_action_set_queue *src = create_action_set_queue();

    ntoh_action( ( struct ofp_action_header * ) &dst, ( struct ofp_action_header * ) src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );
    assert_int_equal( ( int ) htonl( dst.queue_id) , ( int ) src->queue_id );

    xfree( src );
  }

  {
    struct ofp_action_group dst;

    memset( &dst, 0, sizeof( struct ofp_action_group ) );

    struct ofp_action_group *src = create_action_group();

    ntoh_action( ( struct ofp_action_header * ) &dst, ( struct ofp_action_header * ) src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );
    assert_int_equal( ( int ) htonl( dst.group_id ), ( int ) src->group_id );

    xfree( src );
  }

  {
    struct ofp_action_nw_ttl dst;

    memset( &dst, 0, sizeof( struct ofp_action_nw_ttl ) );

    struct ofp_action_nw_ttl *src = create_action_set_nw_ttl();

    ntoh_action( ( struct ofp_action_header * ) &dst, ( struct ofp_action_header * ) src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );
    assert_int_equal( dst.nw_ttl, src->nw_ttl );

    xfree( src );
  }

  {
    struct ofp_action_header dst;

    memset( &dst, 0, sizeof( struct ofp_action_header ) );

    struct ofp_action_header *src = create_action_dec_nw_ttl();

    ntoh_action( &dst, src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );

    xfree( src );
  }

  {
    char buf[256] = {};
    struct ofp_action_set_field *dst = ( struct ofp_action_set_field * ) buf;

    struct ofp_action_set_field *src = create_action_set_field( false );
    struct ofp_action_set_field *expected = create_action_set_field( true );

    ntoh_action_set_field( dst, src );

    assert_memory_equal( dst, expected, expected->len );

    xfree( src );
    xfree( expected );
  }

  {
    struct ofp_action_push dst;

    memset( &dst, 0, sizeof( struct ofp_action_push ) );

    struct ofp_action_push *src = create_action_push_pbb();

    ntoh_action( ( struct ofp_action_header * ) &dst, ( struct ofp_action_header * ) src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );
    assert_int_equal( htons( dst.ethertype ), src->ethertype );

    xfree( src );
  }

  {
    struct ofp_action_header dst;

    memset( &dst, 0, sizeof( struct ofp_action_header ) );

    struct ofp_action_header *src = create_action_pop_pbb();

    ntoh_action( &dst, src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );

    xfree( src );
  }

  {
    struct ofp_action_experimenter_header dst;

    memset( &dst, 0, sizeof( struct ofp_action_experimenter_header ) );

    struct ofp_action_experimenter_header *src = create_action_experimenter();

    ntoh_action( ( struct ofp_action_header * ) &dst, ( struct ofp_action_header * ) src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );
    assert_int_equal( ( int ) htonl( dst.experimenter ), ( int ) src->experimenter );

    xfree( src );
  }
}


void
test_ntoh_action_with_undefined_action_type() {
  struct ofp_action_output dst;

  memset( &dst, 0, sizeof( struct ofp_action_output ) );

  struct ofp_action_output *src = create_action_output();

  src->type = htons( OFPAT_POP_PBB + 1 );
  
  expect_assert_failure( ntoh_action( ( struct ofp_action_header * ) &dst, ( struct ofp_action_header * ) src ) );

  xfree( src );
}


/********************************************************************************
 * hton_action() tests.
 ********************************************************************************/

void
test_hton_action() {
  {
    struct ofp_action_output dst;

    memset( &dst, 0, sizeof( struct ofp_action_output ) );

    struct ofp_action_output *src = create_action_output();
    ntoh_action_output ( src, src );

    hton_action( ( struct ofp_action_header * ) &dst, ( struct ofp_action_header * ) src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );
    assert_int_equal( ( int ) htonl( dst.port ), ( int ) src->port );
    assert_int_equal( htons( dst.max_len ), src->max_len );

    xfree( src );
  }

  {
    struct ofp_action_header dst;

    memset( &dst, 0, sizeof( struct ofp_action_header ) );

    struct ofp_action_header *src = create_action_copy_ttl_out();
    ntoh_action_header ( src, src );

    hton_action( &dst, src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );

    xfree( src );
  }

  {
    struct ofp_action_header dst;

    memset( &dst, 0, sizeof( struct ofp_action_header ) );

    struct ofp_action_header *src = create_action_copy_ttl_in();
    ntoh_action_header ( src, src );

    hton_action( &dst, src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );

    xfree( src );
  }

  {
    struct ofp_action_mpls_ttl dst;

    memset( &dst, 0, sizeof( struct ofp_action_mpls_ttl ) );

    struct ofp_action_mpls_ttl *src = create_action_set_mpls_ttl();
    ntoh_action_mpls_ttl ( src, src );

    hton_action( ( struct ofp_action_header * ) &dst, ( struct ofp_action_header * ) src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );
    assert_int_equal( dst.mpls_ttl, src->mpls_ttl );

    xfree( src );
  }

  {
    struct ofp_action_header dst;

    memset( &dst, 0, sizeof( struct ofp_action_header ) );

    struct ofp_action_header *src = create_action_dec_mpls_ttl();
    ntoh_action_header ( src, src );

    hton_action( &dst, src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );

    xfree( src );
  }

  {
    struct ofp_action_push dst;

    memset( &dst, 0, sizeof( struct ofp_action_push ) );

    struct ofp_action_push *src = create_action_push_vlan();
    ntoh_action_push ( src, src );

    hton_action( ( struct ofp_action_header * ) &dst, ( struct ofp_action_header * ) src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );
    assert_int_equal( htons( dst.ethertype ), src->ethertype );

    xfree( src );
  }

  {
    struct ofp_action_header dst;

    memset( &dst, 0, sizeof( struct ofp_action_header ) );

    struct ofp_action_header *src = create_action_pop_vlan();
    ntoh_action_header ( src, src );

    hton_action( &dst, src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );

    xfree( src );
  }

  {
    struct ofp_action_push dst;

    memset( &dst, 0, sizeof( struct ofp_action_push ) );

    struct ofp_action_push *src = create_action_push_mpls();
    ntoh_action_push ( src, src );

    hton_action( ( struct ofp_action_header * ) &dst, ( struct ofp_action_header * ) src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );
    assert_int_equal( htons( dst.ethertype ), src->ethertype );

    xfree( src );
  }

  {
    struct ofp_action_pop_mpls dst;

    memset( &dst, 0, sizeof( struct ofp_action_pop_mpls ) );

    struct ofp_action_pop_mpls *src = create_action_pop_mpls();
    ntoh_action_pop_mpls ( src, src );

    hton_action( ( struct ofp_action_header * ) &dst, ( struct ofp_action_header * ) src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );
    assert_int_equal( htons( dst.ethertype ), src->ethertype );

    xfree( src );
  }

  {
    struct ofp_action_set_queue dst;

    memset( &dst, 0, sizeof( struct ofp_action_set_queue ) );

    struct ofp_action_set_queue *src = create_action_set_queue();
    ntoh_action_set_queue ( src, src );

    hton_action( ( struct ofp_action_header * ) &dst, ( struct ofp_action_header * ) src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );
    assert_int_equal( ( int ) htonl( dst.queue_id) , ( int ) src->queue_id );

    xfree( src );
  }

  {
    struct ofp_action_group dst;

    memset( &dst, 0, sizeof( struct ofp_action_group ) );

    struct ofp_action_group *src = create_action_group();
    ntoh_action_group ( src, src );

    hton_action( ( struct ofp_action_header * ) &dst, ( struct ofp_action_header * ) src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );
    assert_int_equal( ( int ) htonl( dst.group_id ), ( int ) src->group_id );

    xfree( src );
  }

  {
    struct ofp_action_nw_ttl dst;

    memset( &dst, 0, sizeof( struct ofp_action_nw_ttl ) );

    struct ofp_action_nw_ttl *src = create_action_set_nw_ttl();
    ntoh_action_nw_ttl ( src, src );

    hton_action( ( struct ofp_action_header * ) &dst, ( struct ofp_action_header * ) src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );
    assert_int_equal( dst.nw_ttl, src->nw_ttl );

    xfree( src );
  }

  {
    struct ofp_action_header dst;

    memset( &dst, 0, sizeof( struct ofp_action_header ) );

    struct ofp_action_header *src = create_action_dec_nw_ttl();
    ntoh_action_header ( src, src );

    hton_action( &dst, src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );

    xfree( src );
  }
  {
    char buf[256] = {};
    struct ofp_action_set_field *dst = ( struct ofp_action_set_field * ) buf;

    struct ofp_action_set_field *src = create_action_set_field( true );
    struct ofp_action_set_field *expected = create_action_set_field( false );

    hton_action_set_field( dst, src );

    assert_memory_equal( dst, expected, ntohs( expected->len ) );

    xfree( src );
    xfree( expected );
  }

  {
    struct ofp_action_push dst;

    memset( &dst, 0, sizeof( struct ofp_action_push ) );

    struct ofp_action_push *src = create_action_push_pbb();
    ntoh_action_push ( src, src );

    hton_action( ( struct ofp_action_header * ) &dst, ( struct ofp_action_header * ) src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );
    assert_int_equal( htons( dst.ethertype ), src->ethertype );

    xfree( src );
  }

  {
    struct ofp_action_header dst;

    memset( &dst, 0, sizeof( struct ofp_action_header ) );

    struct ofp_action_header *src = create_action_pop_pbb();
    ntoh_action_header ( src, src );

    hton_action( &dst, src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );

    xfree( src );
  }

  {
    struct ofp_action_experimenter_header dst;

    memset( &dst, 0, sizeof( struct ofp_action_experimenter_header ) );

    struct ofp_action_experimenter_header *src = create_action_experimenter();
    ntoh_action_experimenter ( src, src );

    hton_action( ( struct ofp_action_header * ) &dst, ( struct ofp_action_header * ) src );

    assert_int_equal( htons( dst.type ), src->type );
    assert_int_equal( htons( dst.len ), src->len );
    assert_int_equal( ( int ) htonl( dst.experimenter ), ( int ) src->experimenter );

    xfree( src );
  }
}


void
test_hton_action_with_undefined_action_type() {
  struct ofp_action_output dst;

  memset( &dst, 0, sizeof( struct ofp_action_output ) );

  struct ofp_action_output *src = create_action_output();
  ntoh_action_output( src, src );

  src->type = OFPAT_POP_PBB + 1;
  
  expect_assert_failure( hton_action( ( struct ofp_action_header * ) &dst, ( struct ofp_action_header * ) src ) );

  xfree( src );
}


/********************************************************************************
 * ntoh_flow_stats() tests.
 ********************************************************************************/

void
test_ntoh_flow_stats() {
  openflow_instructions *instructions;
  struct ofp_instruction *inst1, *inst2;
  uint16_t instructions_len;

  create_instruction_testdata();
  inst1 = xcalloc( 1, instruction_testdata_len[0] );
  memcpy( inst1, instruction_testdata[0], instruction_testdata_len[0] );
  inst2 = xcalloc( 1, instruction_testdata_len[1] );
  memcpy( inst2, instruction_testdata[1], instruction_testdata_len[1] );

  instructions = create_instructions();
  instructions->n_instructions = 2;
  append_to_tail( &instructions->list, inst1 );
  append_to_tail( &instructions->list, inst2 );

  create_oxm_match_testdata();

  instructions_len = ( uint16_t ) get_instructions_length( instructions );
  uint16_t offset = ( uint16_t ) ( offsetof( struct ofp_flow_stats, match ) + expected_ofp_match_len );
  uint16_t length = ( uint16_t ) ( offset + instructions_len );
  uint16_t alloc_len = length;

  struct ofp_flow_stats *src = xcalloc( 1, alloc_len );
  struct ofp_flow_stats *dst = xcalloc( 1, alloc_len );

  struct ofp_instruction *expected_inst = xcalloc( 1, instructions_len );
  memcpy( expected_inst, instruction_testdata[0], instruction_testdata_len[0] );
  memcpy( ( char * ) expected_inst + instruction_testdata_len[0], instruction_testdata[1], instruction_testdata_len[1] );

  src->length = htons( length );
  src->table_id = 1;
  src->duration_sec = htonl( 60 );
  src->duration_nsec = htonl( 5000 );
  src->priority = htons( UINT16_MAX );
  src->idle_timeout = htons( 60 );
  src->hard_timeout = htons( 300 );
  src->flags = htons( OFPFF_SEND_FLOW_REM );
  src->cookie = htonll( COOKIE );
  src->packet_count = htonll( PACKET_COUNT );
  src->byte_count= htonll( BYTE_COUNT );
  hton_match( &src->match, expected_ofp_match );

  hton_instruction( ( struct ofp_instruction * ) ( ( char * ) src + offset ), instruction_testdata[0] );
  hton_instruction( ( struct ofp_instruction * ) ( ( char * ) src + offset + instruction_testdata_len[0] ), instruction_testdata[1] );

  ntoh_flow_stats( dst, src );

  assert_int_equal( htons( dst->length ), src->length );
  assert_int_equal( dst->table_id, src->table_id );
  assert_int_equal( ( int ) htonl( dst->duration_sec ), ( int ) src->duration_sec );
  assert_int_equal( ( int ) htonl( dst->duration_nsec ), ( int ) src->duration_nsec );
  assert_int_equal( htons( dst->priority ), src->priority );
  assert_int_equal( htons( dst->idle_timeout ), src->idle_timeout );
  assert_int_equal( htons( dst->hard_timeout ), src->hard_timeout );
  assert_int_equal( htons( dst->flags ), src->flags );
  assert_memory_equal( &dst->cookie, &COOKIE, sizeof( uint64_t ) );
  assert_memory_equal( &dst->packet_count, &PACKET_COUNT, sizeof( uint64_t ) );
  assert_memory_equal( &dst->byte_count, &BYTE_COUNT, sizeof( uint64_t ) );
  assert_memory_equal( &dst->match, expected_ofp_match, expected_ofp_match_len );
  assert_memory_equal( ( ( char * ) dst + offset ), ( ( char * ) expected_inst ), instructions_len );

  delete_instructions( instructions );
  delete_instruction_testdata();
  xfree( expected_inst );
  delete_oxm_match_testdata();
  xfree( src );
  xfree( dst );
}


/********************************************************************************
 * hton_flow_stats() tests.
 ********************************************************************************/
void
test_hton_flow_stats() {
  openflow_instructions *instructions;
  struct ofp_instruction *inst1, *inst2;
  uint16_t instructions_len;

  create_instruction_testdata();
  inst1 = xcalloc( 1, instruction_testdata_len[0] );
  memcpy( inst1, instruction_testdata[0], instruction_testdata_len[0] );
  inst2 = xcalloc( 1, instruction_testdata_len[1] );
  memcpy( inst2, instruction_testdata[1], instruction_testdata_len[1] );

  instructions = create_instructions();
  instructions->n_instructions = 2;
  append_to_tail( &instructions->list, inst1 );
  append_to_tail( &instructions->list, inst2 );

  create_oxm_match_testdata();

  instructions_len = ( uint16_t ) get_instructions_length( instructions );
  uint16_t offset = ( uint16_t ) ( offsetof( struct ofp_flow_stats, match ) + expected_ofp_match_len );
  uint16_t length = ( uint16_t ) ( offset + instructions_len );
  uint16_t alloc_len = length;

  struct ofp_flow_stats *src = xcalloc( 1, alloc_len );
  struct ofp_flow_stats *dst = xcalloc( 1, alloc_len );

  struct ofp_instruction *expected_inst = xcalloc( 1, instructions_len );
  memcpy( expected_inst, instruction_testdata[0], instruction_testdata_len[0] );
  memcpy( ( char * ) expected_inst + instruction_testdata_len[0], instruction_testdata[1], instruction_testdata_len[1] );

  src->length = length;
  src->table_id = 1;
  src->duration_sec = 60;
  src->duration_nsec = 5000;
  src->priority = UINT16_MAX;
  src->idle_timeout = 60;
  src->hard_timeout = 300;
  src->flags = OFPFF_SEND_FLOW_REM;
  src->cookie = COOKIE;
  src->packet_count = PACKET_COUNT;
  src->byte_count= BYTE_COUNT;
  memcpy( &src->match, expected_ofp_match, expected_ofp_match_len );

  memcpy( ( ( char * ) src + offset ), instruction_testdata[0], instruction_testdata_len[0] );
  memcpy( ( ( char * ) src + offset + instruction_testdata_len[0] ), instruction_testdata[1], instruction_testdata_len[1] );

  hton_flow_stats( dst, src );

  struct ofp_match *test_match = xcalloc( 1, expected_ofp_match_len );
  hton_match( test_match, expected_ofp_match );
  struct ofp_instruction *test_inst = xcalloc( 1, instructions_len );
  hton_instruction( test_inst, instruction_testdata[0] );
  hton_instruction( ( struct ofp_instruction * ) ( ( char * ) test_inst + instruction_testdata_len[0] ), instruction_testdata[1] );

  assert_int_equal( dst->length, htons( src->length ) );
  assert_int_equal( dst->table_id, src->table_id );
  assert_int_equal( ( int ) dst->duration_sec, ( int ) htonl( src->duration_sec ) );
  assert_int_equal( ( int ) dst->duration_nsec, ( int ) htonl( src->duration_nsec ) );
  assert_int_equal( dst->priority, htons( src->priority ) );
  assert_int_equal( dst->idle_timeout, htons( src->idle_timeout ) );
  assert_int_equal( dst->hard_timeout, htons( src->hard_timeout ) );
  assert_int_equal( dst->flags, htons( src->flags ) );
  uint64_t cookie_n = htonll( COOKIE );
  uint64_t packet_count_n = htonll( PACKET_COUNT );
  uint64_t byte_count_n = htonll( BYTE_COUNT );
  assert_memory_equal( &dst->cookie, &cookie_n, sizeof( uint64_t ) );
  assert_memory_equal( &dst->packet_count, &packet_count_n, sizeof( uint64_t ) );
  assert_memory_equal( &dst->byte_count, &byte_count_n, sizeof( uint64_t ) );
  assert_memory_equal( &dst->match, test_match, expected_ofp_match_len );
  assert_memory_equal( ( ( char * ) dst + offset ), ( ( char * ) test_inst ), instructions_len );

  xfree( test_match );
  xfree( test_inst );
  delete_instructions( instructions );
  delete_instruction_testdata();
  xfree( expected_inst );
  delete_oxm_match_testdata();
  xfree( src );
  xfree( dst );
}


/********************************************************************************
 * ntoh_aggregate_stats() test.
 ********************************************************************************/

void
test_ntoh_aggregate_stats() {
  struct ofp_aggregate_stats_reply dst;
  struct ofp_aggregate_stats_reply src;

  memset( &src, 0, sizeof( struct ofp_aggregate_stats_reply ) );
  memset( &dst, 0, sizeof( struct ofp_aggregate_stats_reply ) );

  src.packet_count = htonll( PACKET_COUNT );
  src.byte_count = htonll( BYTE_COUNT );
  src.flow_count = htonl( 1000 );

  ntoh_aggregate_stats( &dst, &src );

  assert_memory_equal( &dst.packet_count, &PACKET_COUNT, sizeof( uint64_t ) );
  assert_memory_equal( &dst.byte_count, &BYTE_COUNT, sizeof( uint64_t ) );
  assert_int_equal( ( int ) htonl( dst.flow_count ), ( int ) src.flow_count );
}


/********************************************************************************
 * ntoh_table_stats() test.
 ********************************************************************************/

void
test_ntoh_table_stats() {
  struct ofp_table_stats dst;
  struct ofp_table_stats src;

  memset( &src, 0, sizeof( struct ofp_table_stats ) );
  memset( &dst, 0, sizeof( struct ofp_table_stats ) );

  uint64_t lookup_count = 100000000;
  uint64_t matched_count = 10000000;

  src.table_id = 1;
  src.active_count = htonl( 1234 );
  src.lookup_count = htonll( lookup_count );
  src.matched_count = htonll( matched_count );

  ntoh_table_stats( &dst, &src );

  assert_int_equal( dst.table_id, src.table_id );
  assert_int_equal( ( int ) htonl( dst.active_count ), ( int ) src.active_count );
  assert_memory_equal( &dst.lookup_count, &lookup_count, sizeof( uint64_t ) );
  assert_memory_equal( &dst.matched_count, &matched_count, sizeof( uint64_t ) );
}


/********************************************************************************
 * ntoh_port_stats() test.
 ********************************************************************************/

void
test_ntoh_port_stats() {
  struct ofp_port_stats dst;
  struct ofp_port_stats src;

  memset( &src, 0, sizeof( struct ofp_port_stats ) );
  memset( &dst, 0, sizeof( struct ofp_port_stats ) );

  uint64_t rx_packets = 8000;
  uint64_t tx_packets = 7000;
  uint64_t rx_bytes = 6000;
  uint64_t tx_bytes = 5000;
  uint64_t rx_dropped = 4000;
  uint64_t tx_dropped = 3000;
  uint64_t rx_errors = 2000;
  uint64_t tx_errors = 1000;
  uint64_t rx_frame_err = 900;
  uint64_t rx_over_err = 100;
  uint64_t rx_crc_err = 10;
  uint64_t collisions = 1;
  uint32_t duration_sec = 200;
  uint32_t duration_nsec = 400;

  src.port_no = htonl( 1 );
  src.rx_packets = htonll( rx_packets );
  src.tx_packets = htonll( tx_packets );
  src.rx_bytes = htonll( rx_bytes );
  src.tx_bytes = htonll( tx_bytes );
  src.rx_dropped = htonll( rx_dropped );
  src.tx_dropped = htonll( tx_dropped );
  src.rx_errors = htonll( rx_errors );
  src.tx_errors = htonll( tx_errors );
  src.rx_frame_err = htonll( rx_frame_err );
  src.rx_over_err = htonll( rx_over_err );
  src.rx_crc_err = htonll( rx_crc_err );
  src.collisions = htonll( collisions );
  src.duration_sec = htonl( duration_sec );
  src.duration_nsec = htonl( duration_nsec );

  ntoh_port_stats( &dst, &src );

  assert_int_equal( ( int ) htonl( dst.port_no ), ( int ) src.port_no );
  assert_memory_equal( &dst.rx_packets, &rx_packets, sizeof( uint64_t ) );
  assert_memory_equal( &dst.tx_packets, &tx_packets, sizeof( uint64_t ) );
  assert_memory_equal( &dst.rx_bytes, &rx_bytes, sizeof( uint64_t ) );
  assert_memory_equal( &dst.tx_bytes, &tx_bytes, sizeof( uint64_t ) );
  assert_memory_equal( &dst.rx_dropped, &rx_dropped, sizeof( uint64_t ) );
  assert_memory_equal( &dst.tx_dropped, &tx_dropped, sizeof( uint64_t ) );
  assert_memory_equal( &dst.rx_errors, &rx_errors, sizeof( uint64_t ) );
  assert_memory_equal( &dst.tx_errors, &tx_errors, sizeof( uint64_t ) );
  assert_memory_equal( &dst.rx_frame_err, &rx_frame_err, sizeof( uint64_t ) );
  assert_memory_equal( &dst.rx_over_err, &rx_over_err, sizeof( uint64_t ) );
  assert_memory_equal( &dst.rx_crc_err, &rx_crc_err, sizeof( uint64_t ) );
  assert_memory_equal( &dst.collisions, &collisions, sizeof( uint64_t ) );
  assert_int_equal( ( int ) htonl( dst.duration_sec ), ( int ) src.duration_sec );
  assert_int_equal( ( int ) htonl( dst.duration_nsec ), ( int ) src.duration_nsec );
}


/********************************************************************************
 * ntoh_queue_stats() test.
 ********************************************************************************/

void
test_ntoh_queue_stats() {
  struct ofp_queue_stats dst;
  struct ofp_queue_stats src;

  memset( &src, 0, sizeof( struct ofp_queue_stats ) );
  memset( &dst, 0, sizeof( struct ofp_queue_stats ) );

  uint64_t tx_bytes = 10000000;
  uint64_t tx_packets = 10000;
  uint64_t tx_errors = 1;
  uint32_t duration_sec = 200;
  uint32_t duration_nsec = 400;

  src.port_no = htonl( 1 );
  src.queue_id = htonl( 3 );
  src.tx_bytes = htonll( tx_bytes );
  src.tx_packets = htonll( tx_packets );
  src.tx_errors = htonll( tx_errors );
  src.duration_sec = htonl( duration_sec );
  src.duration_nsec = htonl( duration_nsec );

  ntoh_queue_stats( &dst, &src );

  assert_int_equal( ( int ) htonl( dst.port_no ), ( int ) src.port_no );
  assert_int_equal( ( int ) htonl( dst.queue_id ), ( int ) src.queue_id );
  assert_memory_equal( &dst.tx_bytes, &tx_bytes, sizeof( uint64_t ) );
  assert_memory_equal( &dst.tx_packets, &tx_packets, sizeof( uint64_t ) );
  assert_memory_equal( &dst.tx_errors, &tx_errors, sizeof( uint64_t ) );
  assert_int_equal( ( int ) htonl( dst.duration_sec ), ( int ) src.duration_sec );
  assert_int_equal( ( int ) htonl( dst.duration_nsec ), ( int ) src.duration_nsec );
}


/********************************************************************************
 * ntoh_queue_property() tests.
 ********************************************************************************/

void
test_ntoh_queue_property_with_OFPQT_MIN_RATE() {
  struct ofp_queue_prop_min_rate dst;
  struct ofp_queue_prop_min_rate src;

  memset( &src, 0, sizeof( struct ofp_queue_prop_min_rate ) );
  memset( &dst, 0, sizeof( struct ofp_queue_prop_min_rate ) );

  src.prop_header.property = htons( OFPQT_MIN_RATE );
  src.prop_header.len = htons( 16 );
  src.rate = htons( 500 );

  ntoh_queue_property( ( struct ofp_queue_prop_header * ) &dst, ( struct ofp_queue_prop_header * ) &src );

  assert_int_equal( htons( dst.prop_header.property ), src.prop_header.property );
  assert_int_equal( htons( dst.prop_header.len ), src.prop_header.len );
  assert_int_equal( htons( dst.rate ), src.rate );
}

void
test_ntoh_queue_property_with_OFPQT_MAX_RATE() {
  struct ofp_queue_prop_max_rate dst;
  struct ofp_queue_prop_max_rate src;

  memset( &src, 0, sizeof( struct ofp_queue_prop_max_rate ) );
  memset( &dst, 0, sizeof( struct ofp_queue_prop_max_rate ) );

  src.prop_header.property = htons( OFPQT_MAX_RATE );
  src.prop_header.len = htons( 16 );
  src.rate = htons( 500 );

  ntoh_queue_property( ( struct ofp_queue_prop_header * ) &dst, ( struct ofp_queue_prop_header * ) &src );

  assert_int_equal( htons( dst.prop_header.property ), src.prop_header.property );
  assert_int_equal( htons( dst.prop_header.len ), src.prop_header.len );
  assert_int_equal( htons( dst.rate ), src.rate );
}

void
test_ntoh_queue_property_with_OFPQT_EXPERIMENTER() {
  buffer *body;

  body = alloc_buffer_with_length( 32 );
  append_back_buffer( body, 32 );
  memset( body->data, 'a', body->length );

  uint16_t expected_len = ( uint16_t ) ( sizeof( struct ofp_queue_prop_experimenter ) + body->length );
  struct ofp_queue_prop_experimenter *src;
  struct ofp_queue_prop_experimenter *dst;
  src = xcalloc( 1, expected_len );
  dst = xcalloc( 1, expected_len );
  src->prop_header.property = htons( OFPQT_EXPERIMENTER );
  src->prop_header.len = htons( expected_len );
  src->experimenter = htonl( 1 );
  memcpy(src->data, body->data, body->length);

  ntoh_queue_property( ( struct ofp_queue_prop_header * ) dst, ( struct ofp_queue_prop_header * ) src );

  assert_int_equal( htons( dst->prop_header.property ), src->prop_header.property );
  assert_int_equal( htons( dst->prop_header.len ), src->prop_header.len );
  assert_int_equal( ( int ) htonl( dst->experimenter ), ( int ) src->experimenter );
  assert_memory_equal( dst->data, src->data, body->length );

  xfree( src );
  xfree( dst );
  free_buffer( body );
}


/********************************************************************************
 * hton_queue_property() tests.
 ********************************************************************************/

void
test_hton_queue_property_with_OFPQT_MIN_RATE() {
  struct ofp_queue_prop_min_rate dst;
  struct ofp_queue_prop_min_rate src;

  memset( &src, 0, sizeof( struct ofp_queue_prop_min_rate ) );
  memset( &dst, 0, sizeof( struct ofp_queue_prop_min_rate ) );

  src.prop_header.property = OFPQT_MIN_RATE;
  src.prop_header.len = 16;
  src.rate = 500;

  hton_queue_property( ( struct ofp_queue_prop_header * ) &dst, ( struct ofp_queue_prop_header * ) &src );

  assert_int_equal( dst.prop_header.property, htons( src.prop_header.property ) );
  assert_int_equal( dst.prop_header.len, htons( src.prop_header.len ) );
  assert_int_equal( dst.rate, htons( src.rate ) );
}

void
test_hton_queue_property_with_OFPQT_MAX_RATE() {
  struct ofp_queue_prop_max_rate dst;
  struct ofp_queue_prop_max_rate src;

  memset( &src, 0, sizeof( struct ofp_queue_prop_max_rate ) );
  memset( &dst, 0, sizeof( struct ofp_queue_prop_max_rate ) );

  src.prop_header.property = OFPQT_MAX_RATE;
  src.prop_header.len = 16;
  src.rate = 500;

  hton_queue_property( ( struct ofp_queue_prop_header * ) &dst, ( struct ofp_queue_prop_header * ) &src );

  assert_int_equal( dst.prop_header.property, htons( src.prop_header.property ) );
  assert_int_equal( dst.prop_header.len, htons( src.prop_header.len ) );
  assert_int_equal( dst.rate, htons( src.rate ) );
}

void
test_hton_queue_property_with_OFPQT_EXPERIMENTER() {
  buffer *body;

  body = alloc_buffer_with_length( 32 );
  append_back_buffer( body, 32 );
  memset( body->data, 'a', body->length );

  uint16_t expected_len = ( uint16_t ) ( sizeof( struct ofp_queue_prop_experimenter ) + body->length );
  struct ofp_queue_prop_experimenter *src;
  struct ofp_queue_prop_experimenter *dst;
  src = xcalloc( 1, expected_len );
  dst = xcalloc( 1, expected_len );

  src->prop_header.property = OFPQT_EXPERIMENTER;
  src->prop_header.len = expected_len;
  src->experimenter = 1;
  memcpy(src->data, body->data, body->length);
  
  hton_queue_property( ( struct ofp_queue_prop_header * ) dst, ( struct ofp_queue_prop_header * ) src );

  assert_int_equal( dst->prop_header.property, htons( src->prop_header.property ) );
  assert_int_equal( dst->prop_header.len, htons( src->prop_header.len ) );
  assert_int_equal( ( int ) dst->experimenter, ( int ) htonl( src->experimenter ) );
  assert_memory_equal( dst->data, src->data, body->length );

  xfree( src );
  xfree( dst );
  free_buffer( body );
}

/********************************************************************************
 * ntoh_packet_queue() tests.
 ********************************************************************************/

void
test_ntoh_packet_queue_with_single_OFPQT_MIN_RATE() {
  uint16_t length = ( uint16_t ) ( offsetof( struct ofp_packet_queue, properties ) + sizeof( struct ofp_queue_prop_min_rate ) );

  struct ofp_packet_queue *src = xmalloc( length );
  struct ofp_packet_queue *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->queue_id = htonl( 3 );
  src->port = htonl( 1 );
  src->len = htons( length );
  struct ofp_queue_prop_min_rate *pm_src = ( struct ofp_queue_prop_min_rate * ) src->properties;
  pm_src->prop_header.property = htons( OFPQT_MIN_RATE );
  pm_src->prop_header.len = htons( 16 );
  pm_src->rate = htons( 500 );

  ntoh_packet_queue( dst, src );

  struct ofp_queue_prop_min_rate *pm_dst = ( struct ofp_queue_prop_min_rate * ) dst->properties;

  assert_int_equal( ( int ) htonl( dst->queue_id ), ( int ) src->queue_id );
  assert_int_equal( ( int ) htonl( dst->port ), ( int ) src->port );
  assert_int_equal( htons( dst->len ), src->len );
  assert_int_equal( htons( pm_dst->prop_header.property ), pm_src->prop_header.property );
  assert_int_equal( htons( pm_dst->prop_header.len ), pm_src->prop_header.len );
  assert_int_equal( htons( pm_dst->rate ), pm_src->rate );

  xfree( src );
  xfree( dst );
}

void
test_ntoh_packet_queue_with_single_OFPQT_MAX_RATE() {
  uint16_t length = ( uint16_t ) ( offsetof( struct ofp_packet_queue, properties ) + sizeof( struct ofp_queue_prop_max_rate ) );

  struct ofp_packet_queue *src = xmalloc( length );
  struct ofp_packet_queue *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->queue_id = htonl( 3 );
  src->port = htonl( 1 );
  src->len = htons( length );
  struct ofp_queue_prop_max_rate *pm_src = ( struct ofp_queue_prop_max_rate * ) src->properties;
  pm_src->prop_header.property = htons( OFPQT_MAX_RATE );
  pm_src->prop_header.len = htons( 16 );
  pm_src->rate = htons( 500 );

  ntoh_packet_queue( dst, src );

  struct ofp_queue_prop_max_rate *pm_dst = ( struct ofp_queue_prop_max_rate * ) dst->properties;

  assert_int_equal( ( int ) htonl( dst->queue_id ), ( int ) src->queue_id );
  assert_int_equal( ( int ) htonl( dst->port ), ( int ) src->port );
  assert_int_equal( htons( dst->len ), src->len );
  assert_int_equal( htons( pm_dst->prop_header.property ), pm_src->prop_header.property );
  assert_int_equal( htons( pm_dst->prop_header.len ), pm_src->prop_header.len );
  assert_int_equal( htons( pm_dst->rate ), pm_src->rate );

  xfree( src );
  xfree( dst );
}

void
test_ntoh_packet_queue_with_single_OFPQT_EXPERIMENTER() {
  buffer *body;

  body = alloc_buffer_with_length( 32 );
  append_back_buffer( body, 32 );
  memset( body->data, 'a', body->length );

  uint16_t length = ( uint16_t ) ( offsetof( struct ofp_packet_queue, properties ) + sizeof( struct ofp_queue_prop_experimenter ) + body->length );

  struct ofp_packet_queue *src = xmalloc( length );
  struct ofp_packet_queue *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->queue_id = htonl( 3 );
  src->port = htonl( 1 );
  src->len = htons( length );
  struct ofp_queue_prop_experimenter *pm_src = ( struct ofp_queue_prop_experimenter * ) src->properties;
  pm_src->prop_header.property = htons( OFPQT_EXPERIMENTER );
  pm_src->prop_header.len = htons( ( uint16_t ) ( sizeof( struct ofp_queue_prop_experimenter ) + body->length ) );
  pm_src->experimenter = htonl( 1 );
  memcpy( pm_src->data, body->data, body->length );

  ntoh_packet_queue( dst, src );

  struct ofp_queue_prop_experimenter *pm_dst = ( struct ofp_queue_prop_experimenter * ) dst->properties;

  assert_int_equal( ( int ) htonl( dst->queue_id ), ( int ) src->queue_id );
  assert_int_equal( ( int ) htonl( dst->port ), ( int ) src->port );
  assert_int_equal( htons( dst->len ), src->len );
  assert_int_equal( htons( pm_dst->prop_header.property ), pm_src->prop_header.property );
  assert_int_equal( htons( pm_dst->prop_header.len ), pm_src->prop_header.len );
  assert_int_equal( ( int ) htonl( pm_dst->experimenter ), ( int ) pm_src->experimenter );
  assert_memory_equal( pm_dst->data, pm_src->data, body->length );

  xfree( src );
  xfree( dst );
  free_buffer( body );
}

void
test_ntoh_packet_queue_with_OFPQT_MIN_RATE_and_OFPQT_MAX_RATE() {
  uint16_t length = ( uint16_t ) ( offsetof( struct ofp_packet_queue, properties ) + sizeof( struct ofp_queue_prop_min_rate ) + sizeof( struct ofp_queue_prop_max_rate ) );

  struct ofp_packet_queue *src = xmalloc( length );
  struct ofp_packet_queue *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->queue_id = htonl( 3 );
  src->port = htonl( 1 );
  src->len = htons( length );
  struct ofp_queue_prop_min_rate *pmin_src = ( struct ofp_queue_prop_min_rate * ) src->properties;
  pmin_src->prop_header.property = htons( OFPQT_MIN_RATE );
  pmin_src->prop_header.len = htons( 16 );
  pmin_src->rate = htons( 500 );
  struct ofp_queue_prop_max_rate *pmax_src = ( struct ofp_queue_prop_max_rate * ) ( ( char * ) src->properties + sizeof( struct ofp_queue_prop_min_rate ) );
  pmax_src->prop_header.property = htons( OFPQT_MAX_RATE );
  pmax_src->prop_header.len = htons( 16 );
  pmax_src->rate = htons( 1000 );

  ntoh_packet_queue( dst, src );

  struct ofp_queue_prop_min_rate *pmin_dst = ( struct ofp_queue_prop_min_rate * ) ( ( char * ) dst->properties );
  struct ofp_queue_prop_max_rate *pmax_dst = ( struct ofp_queue_prop_max_rate * ) ( ( char * ) dst->properties + sizeof( struct ofp_queue_prop_min_rate ) );

  assert_int_equal( ( int ) htonl( dst->queue_id ), ( int ) src->queue_id );
  assert_int_equal( ( int ) htonl( dst->port ), ( int ) src->port );
  assert_int_equal( htons( dst->len ), src->len );
  assert_int_equal( htons( pmin_dst->prop_header.property ), pmin_src->prop_header.property );
  assert_int_equal( htons( pmin_dst->prop_header.len ), pmin_src->prop_header.len );
  assert_int_equal( htons( pmin_dst->rate ), pmin_src->rate );
  assert_int_equal( htons( pmax_dst->prop_header.property ), pmax_src->prop_header.property );
  assert_int_equal( htons( pmax_dst->prop_header.len ), pmax_src->prop_header.len );
  assert_int_equal( htons( pmax_dst->rate ), pmax_src->rate );

  xfree( src );
  xfree( dst );
}


/********************************************************************************
 * hton_packet_queue() tests.
 ********************************************************************************/

void
test_hton_packet_queue_with_single_OFPQT_MIN_RATE() {
  uint16_t length = ( uint16_t ) ( offsetof( struct ofp_packet_queue, properties ) + sizeof( struct ofp_queue_prop_min_rate ) );

  struct ofp_packet_queue *src = xmalloc( length );
  struct ofp_packet_queue *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->queue_id = 3;
  src->port = 1;
  src->len = length;
  struct ofp_queue_prop_min_rate *pm_src = ( struct ofp_queue_prop_min_rate * ) src->properties;
  pm_src->prop_header.property = OFPQT_MIN_RATE;
  pm_src->prop_header.len = 16;
  pm_src->rate = 500;

  hton_packet_queue( dst, src );

  struct ofp_queue_prop_min_rate *pm_dst = ( struct ofp_queue_prop_min_rate * ) dst->properties;

  assert_int_equal( ( int ) dst->queue_id, ( int ) htonl( src->queue_id ) );
  assert_int_equal( ( int ) dst->port, ( int ) htonl( src->port ) );
  assert_int_equal( dst->len, htons( src->len ) );
  assert_int_equal( pm_dst->prop_header.property, htons( pm_src->prop_header.property ) );
  assert_int_equal( pm_dst->prop_header.len, htons( pm_src->prop_header.len ) );
  assert_int_equal( pm_dst->rate, htons( pm_src->rate ) );

  xfree( src );
  xfree( dst );
}

void
test_hton_packet_queue_with_single_OFPQT_MAX_RATE() {
  uint16_t length = ( uint16_t ) ( offsetof( struct ofp_packet_queue, properties ) + sizeof( struct ofp_queue_prop_max_rate ) );

  struct ofp_packet_queue *src = xmalloc( length );
  struct ofp_packet_queue *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->queue_id = 3;
  src->port = 1;
  src->len = length;
  struct ofp_queue_prop_max_rate *pm_src = ( struct ofp_queue_prop_max_rate * ) src->properties;
  pm_src->prop_header.property = OFPQT_MAX_RATE;
  pm_src->prop_header.len = 16;
  pm_src->rate = 500;

  hton_packet_queue( dst, src );

  struct ofp_queue_prop_max_rate *pm_dst = ( struct ofp_queue_prop_max_rate * ) dst->properties;

  assert_int_equal( ( int ) dst->queue_id, ( int ) htonl( src->queue_id ) );
  assert_int_equal( ( int ) dst->port, ( int ) htonl( src->port ) );
  assert_int_equal( dst->len, htons( src->len ) );
  assert_int_equal( pm_dst->prop_header.property, htons( pm_src->prop_header.property ) );
  assert_int_equal( pm_dst->prop_header.len, htons( pm_src->prop_header.len ) );
  assert_int_equal( pm_dst->rate, htons( pm_src->rate ) );

  xfree( src );
  xfree( dst );
}

void
test_hton_packet_queue_with_single_OFPQT_EXPERIMENTER() {
  buffer *body;

  body = alloc_buffer_with_length( 32 );
  append_back_buffer( body, 32 );
  memset( body->data, 'a', body->length );

  uint16_t length = ( uint16_t ) ( offsetof( struct ofp_packet_queue, properties ) + sizeof( struct ofp_queue_prop_experimenter ) + body->length );

  struct ofp_packet_queue *src = xmalloc( length );
  struct ofp_packet_queue *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->queue_id = 3;
  src->port = 1;
  src->len = length;
  struct ofp_queue_prop_experimenter *pm_src = ( struct ofp_queue_prop_experimenter * ) src->properties;
  pm_src->prop_header.property = OFPQT_EXPERIMENTER;
  pm_src->prop_header.len = htons( ( uint16_t ) ( sizeof( struct ofp_queue_prop_experimenter ) + body->length ) );
  pm_src->experimenter = 1;
  memcpy( pm_src->data, body->data, body->length );

  hton_packet_queue( dst, src );

  struct ofp_queue_prop_experimenter *pm_dst = ( struct ofp_queue_prop_experimenter * ) dst->properties;

  assert_int_equal( ( int ) dst->queue_id, ( int ) htonl( src->queue_id ) );
  assert_int_equal( ( int ) dst->port, ( int ) htonl( src->port ) );
  assert_int_equal( dst->len, htons( src->len ) );
  assert_int_equal( pm_dst->prop_header.property, htons( pm_src->prop_header.property ) );
  assert_int_equal( pm_dst->prop_header.len, htons( pm_src->prop_header.len ) );
  assert_int_equal( ( int ) pm_dst->experimenter, ( int ) htonl( pm_src->experimenter ) );
  assert_memory_equal( pm_dst->data, pm_src->data, body->length );

  xfree( src );
  xfree( dst );
  free_buffer( body );
}

void
test_hton_packet_queue_with_OFPQT_MIN_RATE_and_OFPQT_MAX_RATE() {
  uint16_t length = ( uint16_t ) ( offsetof( struct ofp_packet_queue, properties ) + sizeof( struct ofp_queue_prop_min_rate ) + sizeof( struct ofp_queue_prop_max_rate ) );

  struct ofp_packet_queue *src = xmalloc( length );
  struct ofp_packet_queue *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->queue_id = 3;
  src->port = 1;
  src->len = length;
  struct ofp_queue_prop_min_rate *pmin_src = ( struct ofp_queue_prop_min_rate * ) src->properties;
  pmin_src->prop_header.property = OFPQT_MIN_RATE;
  pmin_src->prop_header.len = 16;
  pmin_src->rate = 500;
  struct ofp_queue_prop_max_rate *pmax_src = ( struct ofp_queue_prop_max_rate * ) ( ( char * ) src->properties + sizeof( struct ofp_queue_prop_min_rate ) );
  pmax_src->prop_header.property = OFPQT_MAX_RATE;
  pmax_src->prop_header.len = 16;
  pmax_src->rate = 1000;

  hton_packet_queue( dst, src );

  struct ofp_queue_prop_min_rate *pmin_dst = ( struct ofp_queue_prop_min_rate * ) ( ( char * ) dst->properties );
  struct ofp_queue_prop_max_rate *pmax_dst = ( struct ofp_queue_prop_max_rate * ) ( ( char * ) dst->properties + sizeof( struct ofp_queue_prop_min_rate ) );

  assert_int_equal( ( int ) dst->queue_id, ( int ) htonl( src->queue_id ) );
  assert_int_equal( ( int ) dst->port, ( int ) htonl( src->port ) );
  assert_int_equal( dst->len, htons( src->len ) );
  assert_int_equal( pmin_dst->prop_header.property, htons( pmin_src->prop_header.property ) );
  assert_int_equal( pmin_dst->prop_header.len, htons( pmin_src->prop_header.len ) );
  assert_int_equal( pmin_dst->rate, htons( pmin_src->rate ) );
  assert_int_equal( pmax_dst->prop_header.property, htons( pmax_src->prop_header.property ) );
  assert_int_equal( pmax_dst->prop_header.len, htons( pmax_src->prop_header.len ) );
  assert_int_equal( pmax_dst->rate, htons( pmax_src->rate ) );

  xfree( src );
  xfree( dst );
}

/********************************************************************************
 * ntoh_instruction() tests.
 ********************************************************************************/

void
test_ntoh_instruction_OFPIT_GOTO_TABLE() {
  struct ofp_instruction_goto_table dst;
  struct ofp_instruction_goto_table src;

  memset( &src, 0, sizeof( struct ofp_instruction_goto_table ) );
  memset( &dst, 0, sizeof( struct ofp_instruction_goto_table ) );

  src.type = htons( OFPIT_GOTO_TABLE );
  src.len = htons( sizeof( struct ofp_instruction_goto_table ) );
  src.table_id = 1;

  ntoh_instruction( ( struct ofp_instruction * ) &dst, ( struct ofp_instruction * ) &src );

  assert_int_equal( htons ( dst.type ), src.type );
  assert_int_equal( htons ( dst.len ), src.len );
  assert_int_equal( dst.table_id, src.table_id );
}

void
test_ntoh_instruction_OFPIT_WRITE_METADATA() {
  struct ofp_instruction_write_metadata dst;
  struct ofp_instruction_write_metadata src;
  uint64_t metadata = 0x1111222233334444;
  uint64_t metadata_mask = 0x5555666677778888;

  memset( &src, 0, sizeof( struct ofp_instruction_write_metadata ) );
  memset( &dst, 0, sizeof( struct ofp_instruction_write_metadata ) );

  src.type = htons( OFPIT_WRITE_METADATA );
  src.len = htons( sizeof( struct ofp_instruction_write_metadata ) );
  src.metadata = htonll ( metadata );
  src.metadata_mask = htonll ( metadata_mask );

  ntoh_instruction( ( struct ofp_instruction * ) &dst, ( struct ofp_instruction * ) &src );

  assert_int_equal( htons ( dst.type ), src.type );
  assert_int_equal( htons ( dst.len ), src.len );
  assert_memory_equal( &dst.metadata, &metadata, sizeof( uint64_t ) );
  assert_memory_equal( &dst.metadata_mask, &metadata_mask, sizeof( uint64_t ) );
}

void
test_ntoh_instruction_OFPIT_WRITE_ACTIONS() {
  struct ofp_action_header *act1, *act2;
  struct ofp_action_header *expected_act;
  uint16_t expected_act_len = 0;
  uint16_t expected_instruction_len;
  struct ofp_instruction_actions *src, *dst;

  create_action_testdata();
  act1 = xcalloc( 1, action_testdata_len[0] );
  memcpy( act1, action_testdata[0], action_testdata_len[0] );
  act2 = xcalloc( 1, action_testdata_len[1] );
  memcpy( act2, action_testdata[1], action_testdata_len[1] );

  {
    expected_act_len = ( uint16_t ) ( action_testdata_len[0] + action_testdata_len[1] );
    expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_instruction_actions, actions ) + expected_act_len );
    expected_act = xcalloc( 1, expected_act_len );
    memcpy( expected_act, action_testdata[0], action_testdata_len[0] );
    memcpy( ( char * ) expected_act + action_testdata_len[0], action_testdata[1], action_testdata_len[1] );
  }

  src = xcalloc( 1, expected_instruction_len );
  dst = xcalloc( 1, expected_instruction_len );
  memset( src, 0, expected_instruction_len );
  memset( dst, 0, expected_instruction_len );

  src->type = htons( OFPIT_WRITE_ACTIONS );
  src->len = htons( expected_instruction_len );
  hton_action( src->actions, expected_act );
  hton_action( ( struct ofp_action_header * ) ( ( char * ) src->actions + expected_act->len ), ( struct ofp_action_header * ) ( ( char * ) expected_act + expected_act->len ) );

  ntoh_instruction( ( struct ofp_instruction * ) dst, ( struct ofp_instruction * ) src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->len ), src->len );
  assert_memory_equal( dst->actions, expected_act, expected_act_len );

  xfree( expected_act );
  delete_action_testdata();
  xfree ( src );
  xfree ( dst );
  xfree ( act1 );
  xfree ( act2 );
}

void
test_ntoh_instruction_OFPIT_APPLY_ACTIONS() {
  struct ofp_action_header *act1, *act2;
  struct ofp_action_header *expected_act;
  uint16_t expected_act_len = 0;
  uint16_t expected_instruction_len;
  struct ofp_instruction_actions *src, *dst;

  create_action_testdata();
  act1 = xcalloc( 1, action_testdata_len[0] );
  memcpy( act1, action_testdata[0], action_testdata_len[0] );
  act2 = xcalloc( 1, action_testdata_len[1] );
  memcpy( act2, action_testdata[1], action_testdata_len[1] );

  {
    expected_act_len = ( uint16_t ) ( action_testdata_len[0] + action_testdata_len[1] );
    expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_instruction_actions, actions ) + expected_act_len );
    expected_act = xcalloc( 1, expected_act_len );
    memcpy( expected_act, action_testdata[0], action_testdata_len[0] );
    memcpy( ( char * ) expected_act + action_testdata_len[0], action_testdata[1], action_testdata_len[1] );
  }

  src = xcalloc( 1, expected_instruction_len );
  dst = xcalloc( 1, expected_instruction_len );
  memset( src, 0, expected_instruction_len );
  memset( dst, 0, expected_instruction_len );

  src->type = htons( OFPIT_APPLY_ACTIONS );
  src->len = htons( expected_instruction_len );
  hton_action( src->actions, expected_act );
  hton_action( ( struct ofp_action_header * ) ( ( char * ) src->actions + expected_act->len ), ( struct ofp_action_header * ) ( ( char * ) expected_act + expected_act->len ) );

  ntoh_instruction( ( struct ofp_instruction * ) dst, ( struct ofp_instruction * ) src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->len ), src->len );
  assert_memory_equal( dst->actions, expected_act, expected_act_len );

  xfree( expected_act );
  delete_action_testdata();
  xfree ( src );
  xfree ( dst );
  xfree ( act1 );
  xfree ( act2 );
}

void
test_ntoh_instruction_OFPIT_CLEAR_ACTIONS() {
  struct ofp_action_header *act1, *act2;
  struct ofp_action_header *expected_act;
  uint16_t expected_act_len = 0;
  uint16_t expected_instruction_len;
  struct ofp_instruction_actions *src, *dst;

  create_action_testdata();
  act1 = xcalloc( 1, action_testdata_len[0] );
  memcpy( act1, action_testdata[0], action_testdata_len[0] );
  act2 = xcalloc( 1, action_testdata_len[1] );
  memcpy( act2, action_testdata[1], action_testdata_len[1] );

  {
    expected_act_len = ( uint16_t ) ( action_testdata_len[0] + action_testdata_len[1] );
    expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_instruction_actions, actions ) + expected_act_len );
    expected_act = xcalloc( 1, expected_act_len );
    memcpy( expected_act, action_testdata[0], action_testdata_len[0] );
    memcpy( ( char * ) expected_act + action_testdata_len[0], action_testdata[1], action_testdata_len[1] );
  }

  src = xcalloc( 1, expected_instruction_len );
  dst = xcalloc( 1, expected_instruction_len );
  memset( src, 0, expected_instruction_len );
  memset( dst, 0, expected_instruction_len );

  src->type = htons( OFPIT_CLEAR_ACTIONS );
  src->len = htons( expected_instruction_len );
  hton_action( src->actions, expected_act );
  hton_action( ( struct ofp_action_header * ) ( ( char * ) src->actions + expected_act->len ), ( struct ofp_action_header * ) ( ( char * ) expected_act + expected_act->len ) );

  ntoh_instruction( ( struct ofp_instruction * ) dst, ( struct ofp_instruction * ) src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->len ), src->len );
  assert_memory_equal( dst->actions, expected_act, expected_act_len );

  xfree( expected_act );
  delete_action_testdata();
  xfree ( src );
  xfree ( dst );
  xfree ( act1 );
  xfree ( act2 );
}

void
test_ntoh_instruction_OFPIT_METER() {
  struct ofp_instruction_meter dst;
  struct ofp_instruction_meter src;

  memset( &src, 0, sizeof( struct ofp_instruction_meter ) );
  memset( &dst, 0, sizeof( struct ofp_instruction_meter ) );

  src.type = htons( OFPIT_METER );
  src.len = htons( sizeof( struct ofp_instruction_meter ) );
  src.meter_id = htonl ( 1 );

  ntoh_instruction( ( struct ofp_instruction * ) &dst, ( struct ofp_instruction * ) &src );

  assert_int_equal( htons ( dst.type ), src.type );
  assert_int_equal( htons ( dst.len ), src.len );
  assert_int_equal( ( int ) htonl ( dst.meter_id ), ( int ) src.meter_id );
}

void
test_ntoh_instruction_OFPIT_EXPERIMENTER() {
  buffer *body;

  body = alloc_buffer_with_length( 32 );
  append_back_buffer( body, 32 );
  memset( body->data, 'a', body->length );

  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_instruction_experimenter ) + body->length );

  struct ofp_instruction_experimenter *src = xmalloc( length );
  struct ofp_instruction_experimenter *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->type = htons( OFPIT_EXPERIMENTER );
  src->len = htons( length );
  src->experimenter = htonl( 1 );
  uint16_t offset = sizeof( struct ofp_instruction_experimenter );
  memcpy( ( char * ) src + offset, ( char * ) body->data, body->length );

  ntoh_instruction( ( struct ofp_instruction * ) dst, ( struct ofp_instruction * ) src );

  assert_int_equal( htons( dst->type ), src->type );
  assert_int_equal( htons( dst->len ), src->len );
  assert_int_equal( ( int ) htonl( dst->experimenter ), ( int ) src->experimenter );
  assert_memory_equal( ( ( char * ) dst + offset ), ( ( char * ) src + offset ), body->length );

  xfree( src );
  xfree( dst );
  free_buffer( body );
}

void
test_ntoh_instruction_unknown_type() {
  struct ofp_instruction dst;
  struct ofp_instruction src;

  memset( &src, 0, sizeof( struct ofp_instruction ) );
  memset( &dst, 0, sizeof( struct ofp_instruction ) );

  src.type = htons ( OFPIT_EXPERIMENTER - 1 );
  src.len = htons( sizeof( struct ofp_instruction ) );

  expect_assert_failure( ntoh_instruction( ( struct ofp_instruction * ) &dst, ( struct ofp_instruction * ) &src ) );
}


/********************************************************************************
 * hton_instruction() tests.
 ********************************************************************************/

void
test_hton_instruction_OFPIT_GOTO_TABLE() {
  struct ofp_instruction_goto_table dst;
  struct ofp_instruction_goto_table src;

  memset( &src, 0, sizeof( struct ofp_instruction_goto_table ) );
  memset( &dst, 0, sizeof( struct ofp_instruction_goto_table ) );

  src.type = OFPIT_GOTO_TABLE;
  src.len = sizeof( struct ofp_instruction_goto_table );
  src.table_id = 1;

  hton_instruction( ( struct ofp_instruction * ) &dst, ( struct ofp_instruction * ) &src );

  assert_int_equal( dst.type, htons( src.type ) );
  assert_int_equal( dst.len, htons( src.len ) );
  assert_int_equal( dst.table_id, src.table_id );
}

void
test_hton_instruction_OFPIT_WRITE_METADATA() {
  struct ofp_instruction_write_metadata dst;
  struct ofp_instruction_write_metadata src;
  uint64_t metadata = 0x1111222233334444;
  uint64_t metadata_n = htonll( metadata );
  uint64_t metadata_mask = 0x5555666677778888;
  uint64_t metadata_mask_n = htonll( metadata_mask );

  memset( &src, 0, sizeof( struct ofp_instruction_write_metadata ) );
  memset( &dst, 0, sizeof( struct ofp_instruction_write_metadata ) );

  src.type = OFPIT_WRITE_METADATA;
  src.len = sizeof( struct ofp_instruction_write_metadata );
  src.metadata = metadata;
  src.metadata_mask = metadata_mask;

  hton_instruction( ( struct ofp_instruction * ) &dst, ( struct ofp_instruction * ) &src );

  assert_int_equal( dst.type, htons( src.type ) );
  assert_int_equal( dst.len, htons( src.len ) );
  
  assert_memory_equal( &dst.metadata, &metadata_n, sizeof( uint64_t ) );
  assert_memory_equal( &dst.metadata_mask, &metadata_mask_n, sizeof( uint64_t ) );
}

void
test_hton_instruction_OFPIT_WRITE_ACTIONS() {
  struct ofp_action_header *act1, *act2;
  struct ofp_action_header *expected_act;
  uint16_t expected_act_len = 0;
  uint16_t expected_instruction_len;
  struct ofp_instruction_actions *src, *dst;

  create_action_testdata();
  act1 = xcalloc( 1, action_testdata_len[0] );
  memcpy( act1, action_testdata[0], action_testdata_len[0] );
  act2 = xcalloc( 1, action_testdata_len[1] );
  memcpy( act2, action_testdata[1], action_testdata_len[1] );

  {
    expected_act_len = ( uint16_t ) ( action_testdata_len[0] + action_testdata_len[1] );
    expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_instruction_actions, actions ) + expected_act_len );
    expected_act = xcalloc( 1, expected_act_len );
    memcpy( expected_act, action_testdata[0], action_testdata_len[0] );
    memcpy( ( char * ) expected_act + action_testdata_len[0], action_testdata[1], action_testdata_len[1] );
  }

  src = xcalloc( 1, expected_instruction_len );
  dst = xcalloc( 1, expected_instruction_len );
  memset( src, 0, expected_instruction_len );
  memset( dst, 0, expected_instruction_len );

  src->type = htons( OFPIT_WRITE_ACTIONS );
  src->len = htons( expected_instruction_len );
  hton_action( src->actions, expected_act );
  hton_action( ( struct ofp_action_header * ) ( ( char * ) src->actions + expected_act->len ), ( struct ofp_action_header * ) ( ( char * ) expected_act + expected_act->len ) );

  ntoh_instruction_actions( dst, src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->len ), src->len );
  assert_memory_equal( dst->actions, expected_act, expected_act_len );

  xfree( expected_act );
  delete_action_testdata();
  xfree ( src );
  xfree ( dst );
  xfree ( act1 );
  xfree ( act2 );
}

void
test_hton_instruction_OFPIT_APPLY_ACTIONS() {
  struct ofp_action_header *act1, *act2;
  struct ofp_action_header *expected_act;
  uint16_t expected_act_len = 0;
  uint16_t expected_instruction_len;
  struct ofp_instruction_actions *src, *dst;

  create_action_testdata();
  act1 = xcalloc( 1, action_testdata_len[0] );
  memcpy( act1, action_testdata[0], action_testdata_len[0] );
  act2 = xcalloc( 1, action_testdata_len[1] );
  memcpy( act2, action_testdata[1], action_testdata_len[1] );

  {
    expected_act_len = ( uint16_t ) ( action_testdata_len[0] + action_testdata_len[1] );
    expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_instruction_actions, actions ) + expected_act_len );
    expected_act = xcalloc( 1, expected_act_len );
    memcpy( expected_act, action_testdata[0], action_testdata_len[0] );
    memcpy( ( char * ) expected_act + action_testdata_len[0], action_testdata[1], action_testdata_len[1] );
  }

  src = xcalloc( 1, expected_instruction_len );
  dst = xcalloc( 1, expected_instruction_len );
  memset( src, 0, expected_instruction_len );
  memset( dst, 0, expected_instruction_len );

  src->type = htons( OFPIT_APPLY_ACTIONS );
  src->len = htons( expected_instruction_len );
  hton_action( src->actions, expected_act );
  hton_action( ( struct ofp_action_header * ) ( ( char * ) src->actions + expected_act->len ), ( struct ofp_action_header * ) ( ( char * ) expected_act + expected_act->len ) );

  ntoh_instruction_actions( dst, src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->len ), src->len );
  assert_memory_equal( dst->actions, expected_act, expected_act_len );

  xfree( expected_act );
  delete_action_testdata();
  xfree ( src );
  xfree ( dst );
  xfree ( act1 );
  xfree ( act2 );
}

void
test_hton_instruction_OFPIT_CLEAR_ACTIONS() {
  struct ofp_action_header *act1, *act2;
  struct ofp_action_header *expected_act;
  uint16_t expected_act_len = 0;
  uint16_t expected_instruction_len;
  struct ofp_instruction_actions *src, *dst;

  create_action_testdata();
  act1 = xcalloc( 1, action_testdata_len[0] );
  memcpy( act1, action_testdata[0], action_testdata_len[0] );
  act2 = xcalloc( 1, action_testdata_len[1] );
  memcpy( act2, action_testdata[1], action_testdata_len[1] );

  {
    expected_act_len = ( uint16_t ) ( action_testdata_len[0] + action_testdata_len[1] );
    expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_instruction_actions, actions ) + expected_act_len );
    expected_act = xcalloc( 1, expected_act_len );
    memcpy( expected_act, action_testdata[0], action_testdata_len[0] );
    memcpy( ( char * ) expected_act + action_testdata_len[0], action_testdata[1], action_testdata_len[1] );
  }

  src = xcalloc( 1, expected_instruction_len );
  dst = xcalloc( 1, expected_instruction_len );
  memset( src, 0, expected_instruction_len );
  memset( dst, 0, expected_instruction_len );

  src->type = htons( OFPIT_CLEAR_ACTIONS );
  src->len = htons( expected_instruction_len );
  hton_action( src->actions, expected_act );
  hton_action( ( struct ofp_action_header * ) ( ( char * ) src->actions + expected_act->len ), ( struct ofp_action_header * ) ( ( char * ) expected_act + expected_act->len ) );

  ntoh_instruction_actions( dst, src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->len ), src->len );
  assert_memory_equal( dst->actions, expected_act, expected_act_len );

  xfree( expected_act );
  delete_action_testdata();
  xfree ( src );
  xfree ( dst );
  xfree ( act1 );
  xfree ( act2 );
}

void
test_hton_instruction_OFPIT_METER() {
  struct ofp_instruction_meter dst;
  struct ofp_instruction_meter src;

  memset( &src, 0, sizeof( struct ofp_instruction_meter ) );
  memset( &dst, 0, sizeof( struct ofp_instruction_meter ) );

  src.type = OFPIT_METER;
  src.len = sizeof( struct ofp_instruction_meter );
  src.meter_id = 1;

  hton_instruction( ( struct ofp_instruction * ) &dst, ( struct ofp_instruction * ) &src );

  assert_int_equal( dst.type, htons( src.type ) );
  assert_int_equal( dst.len, htons( src.len ) );
  assert_int_equal( ( int ) dst.meter_id, ( int ) htonl( src.meter_id ) );
}

void
test_hton_instruction_OFPIT_EXPERIMENTER() {
  buffer *body;

  body = alloc_buffer_with_length( 32 );
  append_back_buffer( body, 32 );
  memset( body->data, 'a', body->length );

  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_instruction_experimenter ) + body->length );

  struct ofp_instruction_experimenter *src = xmalloc( length );
  struct ofp_instruction_experimenter *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->type = OFPIT_EXPERIMENTER;
  src->len = length;
  src->experimenter = 1;
  uint16_t offset = sizeof( struct ofp_instruction_experimenter );
  memcpy( ( char * ) src + offset, ( char * ) body->data, body->length );

  hton_instruction( ( struct ofp_instruction * ) dst, ( struct ofp_instruction * ) src );

  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->len, htons( src->len ) );
  assert_int_equal( ( int ) dst->experimenter, ( int ) htonl( src->experimenter ) );
  assert_memory_equal( ( ( char * ) dst + offset ), ( ( char * ) src + offset ), body->length );

  xfree( src );
  xfree( dst );
  free_buffer( body );
}

void
test_hton_instruction_unknown_type() {
  struct ofp_instruction dst;
  struct ofp_instruction src;

  memset( &src, 0, sizeof( struct ofp_instruction ) );
  memset( &dst, 0, sizeof( struct ofp_instruction ) );

  src.type = ( OFPIT_EXPERIMENTER - 1 );
  src.len = sizeof( struct ofp_instruction );

  expect_assert_failure( hton_instruction( ( struct ofp_instruction * ) &dst, ( struct ofp_instruction * ) &src ) );
}

/********************************************************************************
 * ntoh_instruction_goto_table() test.
 ********************************************************************************/

void
test_ntoh_instruction_goto_table() {
  struct ofp_instruction_goto_table dst;
  struct ofp_instruction_goto_table src;

  memset( &src, 0, sizeof( struct ofp_instruction_goto_table ) );
  memset( &dst, 0, sizeof( struct ofp_instruction_goto_table ) );

  src.type = htons( OFPIT_GOTO_TABLE );
  src.len = htons( sizeof( struct ofp_instruction_goto_table ) );
  src.table_id = 1;

  ntoh_instruction_goto_table( &dst, &src );

  assert_int_equal( htons ( dst.type ), src.type );
  assert_int_equal( htons ( dst.len ), src.len );
  assert_int_equal( dst.table_id, src.table_id );
}


/********************************************************************************
 * hton_instruction_goto_table() test.
 ********************************************************************************/

void
test_hton_instruction_goto_table() {
  struct ofp_instruction_goto_table dst;
  struct ofp_instruction_goto_table src;

  memset( &src, 0, sizeof( struct ofp_instruction_goto_table ) );
  memset( &dst, 0, sizeof( struct ofp_instruction_goto_table ) );

  src.type = OFPIT_GOTO_TABLE;
  src.len = sizeof( struct ofp_instruction_goto_table );
  src.table_id = 1;

  hton_instruction_goto_table( &dst, &src );

  assert_int_equal( dst.type, htons( src.type ) );
  assert_int_equal( dst.len, htons( src.len ) );
  assert_int_equal( dst.table_id, src.table_id );
}


/********************************************************************************
 * ntoh_instruction_write_metadata() test.
 ********************************************************************************/

void
test_ntoh_instruction_write_metadata() {
  struct ofp_instruction_write_metadata dst;
  struct ofp_instruction_write_metadata src;
  uint64_t metadata = 0x1111222233334444;
  uint64_t metadata_mask = 0x5555666677778888;

  memset( &src, 0, sizeof( struct ofp_instruction_write_metadata ) );
  memset( &dst, 0, sizeof( struct ofp_instruction_write_metadata ) );

  src.type = htons( OFPIT_WRITE_METADATA );
  src.len = htons( sizeof( struct ofp_instruction_write_metadata ) );
  src.metadata = htonll ( metadata );
  src.metadata_mask = htonll ( metadata_mask );

  ntoh_instruction_write_metadata( &dst, &src );

  assert_int_equal( htons ( dst.type ), src.type );
  assert_int_equal( htons ( dst.len ), src.len );
  assert_memory_equal( &dst.metadata, &metadata, sizeof( uint64_t ) );
  assert_memory_equal( &dst.metadata_mask, &metadata_mask, sizeof( uint64_t ) );
}

/********************************************************************************
 * hton_instruction_write_metadata() test.
 ********************************************************************************/

void
test_hton_instruction_write_metadata() {
  struct ofp_instruction_write_metadata dst;
  struct ofp_instruction_write_metadata src;
  uint64_t metadata = 0x1111222233334444;
  uint64_t metadata_n = htonll( metadata );
  uint64_t metadata_mask = 0x5555666677778888;
  uint64_t metadata_mask_n = htonll( metadata_mask );

  memset( &src, 0, sizeof( struct ofp_instruction_write_metadata ) );
  memset( &dst, 0, sizeof( struct ofp_instruction_write_metadata ) );

  src.type = OFPIT_WRITE_METADATA;
  src.len = sizeof( struct ofp_instruction_write_metadata );
  src.metadata = metadata;
  src.metadata_mask = metadata_mask;

  hton_instruction_write_metadata( &dst, &src );

  assert_int_equal( dst.type, htons( src.type ) );
  assert_int_equal( dst.len, htons( src.len ) );
  
  assert_memory_equal( &dst.metadata, &metadata_n, sizeof( uint64_t ) );
  assert_memory_equal( &dst.metadata_mask, &metadata_mask_n, sizeof( uint64_t ) );
}

/********************************************************************************
 * ntoh_instruction_actions() test.
 ********************************************************************************/

void
test_ntoh_instruction_actions() {
  struct ofp_action_header *act1, *act2;
  struct ofp_action_header *expected_act;
  uint16_t expected_act_len = 0;
  uint16_t expected_instruction_len;
  struct ofp_instruction_actions *src, *dst;

  create_action_testdata();
  act1 = xcalloc( 1, action_testdata_len[0] );
  memcpy( act1, action_testdata[0], action_testdata_len[0] );
  act2 = xcalloc( 1, action_testdata_len[1] );
  memcpy( act2, action_testdata[1], action_testdata_len[1] );

  {
    expected_act_len = ( uint16_t ) ( action_testdata_len[0] + action_testdata_len[1] );
    expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_instruction_actions, actions ) + expected_act_len );
    expected_act = xcalloc( 1, expected_act_len );
    memcpy( expected_act, action_testdata[0], action_testdata_len[0] );
    memcpy( ( char * ) expected_act + action_testdata_len[0], action_testdata[1], action_testdata_len[1] );
  }

  src = xcalloc( 1, expected_instruction_len );
  dst = xcalloc( 1, expected_instruction_len );
  memset( src, 0, expected_instruction_len );
  memset( dst, 0, expected_instruction_len );

  src->type = htons( OFPIT_WRITE_ACTIONS );
  src->len = htons( expected_instruction_len );
  hton_action( src->actions, expected_act );
  hton_action( ( struct ofp_action_header * ) ( ( char * ) src->actions + expected_act->len ), ( struct ofp_action_header * ) ( ( char * ) expected_act + expected_act->len ) );

  ntoh_instruction_actions( dst, src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->len ), src->len );
  assert_memory_equal( dst->actions, expected_act, expected_act_len );

  xfree( expected_act );
  delete_action_testdata();
  xfree ( src );
  xfree ( dst );
  xfree ( act1 );
  xfree ( act2 );
}

void
test_ntoh_instruction_actions_no_action() {
  struct ofp_instruction_actions *src, *dst;
  uint16_t len = ( uint16_t ) sizeof(struct ofp_instruction_actions);

  src = xcalloc( 1, len );
  dst = xcalloc( 1, len );
  memset( src, 0, len );
  memset( dst, 0, len );

  src->type = htons( OFPIT_WRITE_ACTIONS );
  src->len = htons( len );
  
  ntoh_instruction_actions( dst, src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->len ), src->len );
  
  xfree ( src );
  xfree ( dst );
}


/********************************************************************************
 * hton_instruction_actions() test.
 ********************************************************************************/

void
test_hton_instruction_actions() {
  struct ofp_action_header *act1, *act2;
  struct ofp_action_header *expected_act;
  uint16_t expected_act_len = 0;
  uint16_t expected_instruction_len;
  struct ofp_instruction_actions *src, *dst;

  create_action_testdata();
  act1 = xcalloc( 1, action_testdata_len[0] );
  memcpy( act1, action_testdata[0], action_testdata_len[0] );
  act2 = xcalloc( 1, action_testdata_len[1] );
  memcpy( act2, action_testdata[1], action_testdata_len[1] );

  {
    expected_act_len = ( uint16_t ) ( action_testdata_len[0] + action_testdata_len[1] );
    expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_instruction_actions, actions ) + expected_act_len );
    expected_act = xcalloc( 1, expected_act_len );
    memcpy( expected_act, action_testdata[0], action_testdata_len[0] );
    memcpy( ( char * ) expected_act + action_testdata_len[0], action_testdata[1], action_testdata_len[1] );
  }

  src = xcalloc( 1, expected_instruction_len );
  dst = xcalloc( 1, expected_instruction_len );
  memset( src, 0, expected_instruction_len );
  memset( dst, 0, expected_instruction_len );

  src->type = OFPIT_WRITE_ACTIONS;
  src->len = expected_instruction_len;
  memcpy( &src->actions, expected_act, expected_act_len );

  hton_instruction_actions( dst, src );

  hton_action( expected_act, expected_act );
  hton_action( ( struct ofp_action_header * ) ( ( char * ) expected_act + ntohs( expected_act->len ) ), ( struct ofp_action_header * ) ( ( char * ) expected_act + ntohs( expected_act->len ) ) );

  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->len, htons( src->len ) );
  assert_memory_equal( dst->actions, expected_act, expected_act_len );

  xfree( expected_act );
  delete_action_testdata();
  xfree ( src );
  xfree ( dst );
  xfree ( act1 );
  xfree ( act2 );
}

void
test_hton_instruction_actions_no_action() {
  struct ofp_instruction_actions *src, *dst;
  uint16_t len = ( uint16_t ) sizeof(struct ofp_instruction_actions);

  src = xcalloc( 1, len );
  dst = xcalloc( 1, len );
  memset( src, 0, len );
  memset( dst, 0, len );

  src->type = OFPIT_WRITE_ACTIONS;
  src->len = len;
  
  hton_instruction_actions( dst, src );

  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->len, htons( src->len ) );
  
  xfree ( src );
  xfree ( dst );
}

/********************************************************************************
 * ntoh_instruction_meter() test.
 ********************************************************************************/

void
test_ntoh_instruction_meter() {
  struct ofp_instruction_meter dst;
  struct ofp_instruction_meter src;

  memset( &src, 0, sizeof( struct ofp_instruction_meter ) );
  memset( &dst, 0, sizeof( struct ofp_instruction_meter ) );

  src.type = htons( OFPIT_METER );
  src.len = htons( sizeof( struct ofp_instruction_meter ) );
  src.meter_id = htonl ( 1 );

  ntoh_instruction_meter( &dst, &src );

  assert_int_equal( htons ( dst.type ), src.type );
  assert_int_equal( htons ( dst.len ), src.len );
  assert_int_equal( ( int ) htonl ( dst.meter_id ), ( int ) src.meter_id );
}

/********************************************************************************
 * hton_instruction_meter() test.
 ********************************************************************************/

void
test_hton_instruction_meter() {
  struct ofp_instruction_meter dst;
  struct ofp_instruction_meter src;

  memset( &src, 0, sizeof( struct ofp_instruction_meter ) );
  memset( &dst, 0, sizeof( struct ofp_instruction_meter ) );

  src.type = OFPIT_METER;
  src.len = sizeof( struct ofp_instruction_meter );
  src.meter_id = 1;

  hton_instruction_meter( &dst, &src );

  assert_int_equal( dst.type, htons( src.type ) );
  assert_int_equal( dst.len, htons( src.len ) );
  assert_int_equal( ( int ) dst.meter_id, ( int ) htonl( src.meter_id ) );
}


/********************************************************************************
 * ntoh_instruction_experimenter() test.
 ********************************************************************************/

void
test_ntoh_instruction_experimenter() {
  buffer *body;

  body = alloc_buffer_with_length( 32 );
  append_back_buffer( body, 32 );
  memset( body->data, 'a', body->length );

  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_instruction_experimenter ) + body->length );

  struct ofp_instruction_experimenter *src = xmalloc( length );
  struct ofp_instruction_experimenter *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->type = htons( OFPIT_EXPERIMENTER );
  src->len = htons( length );
  src->experimenter = htonl( 1 );
  uint16_t offset = sizeof( struct ofp_instruction_experimenter );
  memcpy( ( char * ) src + offset, ( char * ) body->data, body->length );

  ntoh_instruction_experimenter( dst, src );

  assert_int_equal( htons( dst->type ), src->type );
  assert_int_equal( htons( dst->len ), src->len );
  assert_int_equal( ( int ) htonl( dst->experimenter ), ( int ) src->experimenter );
  assert_memory_equal( ( ( char * ) dst + offset ), ( ( char * ) src + offset ), body->length );

  xfree( src );
  xfree( dst );
  free_buffer( body );
}

void
test_ntoh_instruction_experimenter_nodata() {
  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_instruction_experimenter ) );

  struct ofp_instruction_experimenter *src = xmalloc( length );
  struct ofp_instruction_experimenter *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->type = htons( OFPIT_EXPERIMENTER );
  src->len = htons( length );
  src->experimenter = htonl( 1 );

  ntoh_instruction_experimenter( dst, src );

  assert_int_equal( htons( dst->type ), src->type );
  assert_int_equal( htons( dst->len ), src->len );
  assert_int_equal( ( int ) htonl( dst->experimenter ), ( int ) src->experimenter );

  xfree( src );
  xfree( dst );
}

/********************************************************************************
 * hton_instruction_experimenter() test.
 ********************************************************************************/

void
test_hton_instruction_experimenter() {
  buffer *body;

  body = alloc_buffer_with_length( 32 );
  append_back_buffer( body, 32 );
  memset( body->data, 'a', body->length );

  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_instruction_experimenter ) + body->length );

  struct ofp_instruction_experimenter *src = xmalloc( length );
  struct ofp_instruction_experimenter *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->type = OFPIT_EXPERIMENTER;
  src->len = length;
  src->experimenter = 1;
  uint16_t offset = sizeof( struct ofp_instruction_experimenter );
  memcpy( ( char * ) src + offset, ( char * ) body->data, body->length );

  hton_instruction_experimenter( dst, src );

  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->len, htons( src->len ) );
  assert_int_equal( ( int ) dst->experimenter, ( int ) htonl( src->experimenter ) );
  assert_memory_equal( ( ( char * ) dst + offset ), ( ( char * ) src + offset ), body->length );

  xfree( src );
  xfree( dst );
  free_buffer( body );
}

void
test_hton_instruction_experimenter_nodata() {
  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_instruction_experimenter ) );

  struct ofp_instruction_experimenter *src = xmalloc( length );
  struct ofp_instruction_experimenter *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->type = OFPIT_EXPERIMENTER;
  src->len = length;
  src->experimenter = 1;

  hton_instruction_experimenter( dst, src );

  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->len, htons( src->len ) );
  assert_int_equal( ( int ) dst->experimenter, ( int ) htonl( src->experimenter ) );

  xfree( src );
  xfree( dst );
}

/********************************************************************************
 * ntoh_bucket() test.
 ********************************************************************************/

void
test_ntoh_bucket() {
  struct ofp_action_header *act1, *act2;
  struct ofp_action_header *expected_act;
  uint16_t expected_act_len = 0;
  uint16_t expected_instruction_len;
  struct ofp_bucket *src, *dst;

  create_action_testdata();
  act1 = xcalloc( 1, action_testdata_len[0] );
  memcpy( act1, action_testdata[0], action_testdata_len[0] );
  act2 = xcalloc( 1, action_testdata_len[1] );
  memcpy( act2, action_testdata[1], action_testdata_len[1] );

  {
    expected_act_len = ( uint16_t ) ( action_testdata_len[0] + action_testdata_len[1] );
    expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_bucket, actions ) + expected_act_len );
    expected_act = xcalloc( 1, expected_act_len );
    memcpy( expected_act, action_testdata[0], action_testdata_len[0] );
    memcpy( ( char * ) expected_act + action_testdata_len[0], action_testdata[1], action_testdata_len[1] );
  }

  src = xcalloc( 1, expected_instruction_len );
  dst = xcalloc( 1, expected_instruction_len );
  memset( src, 0, expected_instruction_len );
  memset( dst, 0, expected_instruction_len );

  src->len = htons( expected_instruction_len );
  src->weight = htons( 1 );
  src->watch_port = htonl( 10 );
  src->watch_group = htonl( 50 );
  hton_action( src->actions, action_testdata[0] );
  hton_action( ( struct ofp_action_header * ) ( ( char * ) src->actions + action_testdata_len[0] ), action_testdata[1] );

  ntoh_bucket( dst, src );

  assert_int_equal( htons ( dst->len ), src->len );
  assert_int_equal( htons ( dst->weight ), src->weight );
  assert_int_equal( ( int ) htonl ( dst->watch_port ), ( int ) src->watch_port );
  assert_int_equal( ( int ) htonl ( dst->watch_group ), ( int ) src->watch_group );
  assert_memory_equal( dst->actions, expected_act, expected_act_len );

  xfree( expected_act );
  delete_action_testdata();
  xfree ( src );
  xfree ( dst );
  xfree ( act1 );
  xfree ( act2 );
}

void
test_ntoh_bucket_noaction() {
  struct ofp_bucket *src, *dst;

  uint16_t len = sizeof( struct ofp_bucket );

  src = xcalloc( 1, len );
  dst = xcalloc( 1, len );
  memset( src, 0, len );
  memset( dst, 0, len );

  src->len = htons( ( uint16_t ) ( len + PADLEN_TO_64( len ) ) );
  src->weight = htons( 1 );
  src->watch_port = htonl( 10 );
  src->watch_group = htonl( 50 );

  ntoh_bucket( dst, src );

  assert_int_equal( htons ( dst->len ), src->len );
  assert_int_equal( htons ( dst->weight ), src->weight );
  assert_int_equal( ( int ) htonl ( dst->watch_port ), ( int ) src->watch_port );
  assert_int_equal( ( int ) htonl ( dst->watch_group ), ( int ) src->watch_group );

  xfree ( src );
  xfree ( dst );
}


/********************************************************************************
 * hton_bucket() test.
 ********************************************************************************/

void
test_hton_bucket() {
  struct ofp_action_header *act1, *act2;
  struct ofp_action_header *expected_act;
  uint16_t expected_act_len = 0;
  uint16_t expected_instruction_len;
  struct ofp_bucket *src, *dst;

  create_action_testdata();
  act1 = xcalloc( 1, action_testdata_len[0] );
  memcpy( act1, action_testdata[0], action_testdata_len[0] );
  act2 = xcalloc( 1, action_testdata_len[1] );
  memcpy( act2, action_testdata[1], action_testdata_len[1] );

  {
    expected_act_len = ( uint16_t ) ( action_testdata_len[0] + action_testdata_len[1] );
    expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_bucket, actions ) + expected_act_len );
    expected_act = xcalloc( 1, expected_act_len );
    memcpy( expected_act, action_testdata[0], action_testdata_len[0] );
    memcpy( ( char * ) expected_act + action_testdata_len[0], action_testdata[1], action_testdata_len[1] );
  }

  src = xcalloc( 1, expected_instruction_len );
  dst = xcalloc( 1, expected_instruction_len );
  memset( src, 0, expected_instruction_len );
  memset( dst, 0, expected_instruction_len );

  src->len = expected_instruction_len;
  src->weight = 1;
  src->watch_port = 10;
  src->watch_group = 50;
  memcpy( &src->actions, expected_act, expected_act_len );

  hton_bucket( dst, src );

  assert_int_equal( dst->len, htons( src->len ) );
  assert_int_equal( dst->weight, htons( src->weight ) );
  assert_int_equal( ( int ) dst->watch_port, ( int ) htonl( src->watch_port ) );
  assert_int_equal( ( int ) dst->watch_group, ( int ) htonl ( src->watch_group ) );
  hton_action( expected_act, expected_act );
  uint16_t len = ntohs( expected_act->len );
  hton_action( ( struct ofp_action_header * ) ( ( char * ) expected_act + len ), ( struct ofp_action_header * ) ( ( char * ) expected_act + len ) );
  assert_memory_equal( dst->actions, expected_act, expected_act_len );

  xfree( expected_act );
  delete_action_testdata();
  xfree ( src );
  xfree ( dst );
  xfree ( act1 );
  xfree ( act2 );
}

void
test_hton_bucket_noaction() {
  struct ofp_bucket *src, *dst;

  uint16_t len = sizeof( struct ofp_bucket );

  src = xcalloc( 1, len );
  dst = xcalloc( 1, len );
  memset( src, 0, len );
  memset( dst, 0, len );

  src->len = ( uint16_t ) ( len + PADLEN_TO_64( len ) );
  src->weight = 1;
  src->watch_port = 10;
  src->watch_group = 50;

  hton_bucket( dst, src );

  assert_int_equal( dst->len, htons( src->len ) );
  assert_int_equal( dst->weight, htons( src->weight ) );
  assert_int_equal( ( int ) dst->watch_port, ( int ) htonl( src->watch_port ) );
  assert_int_equal( ( int ) dst->watch_group, ( int ) htonl( src->watch_group ) );

  xfree ( src );
  xfree ( dst );
}

/********************************************************************************
 * ntoh_meter_band_drop() test.
 ********************************************************************************/

void
test_ntoh_meter_band_drop() {
  struct ofp_meter_band_drop dst;
  struct ofp_meter_band_drop src;

  memset( &src, 0, sizeof( struct ofp_meter_band_drop ) );
  memset( &dst, 0, sizeof( struct ofp_meter_band_drop ) );

  src.type = htons( OFPMBT_DROP );
  src.len = htons( sizeof( struct ofp_meter_band_drop ) );
  src.rate = htonl( 500 );
  src.burst_size = htonl( 1000 );

  ntoh_meter_band_drop( &dst, &src );

  assert_int_equal( htons( dst.type ), src.type );
  assert_int_equal( htons( dst.len ), src.len );
  assert_int_equal( ( int ) htonl( dst.rate ), ( int ) src.rate );
  assert_int_equal( ( int ) htonl( dst.burst_size ), ( int ) src.burst_size );
}

/********************************************************************************
 * hton_meter_band_drop() test.
 ********************************************************************************/

void
test_hton_meter_band_drop() {
  struct ofp_meter_band_drop dst;
  struct ofp_meter_band_drop src;

  memset( &src, 0, sizeof( struct ofp_meter_band_drop ) );
  memset( &dst, 0, sizeof( struct ofp_meter_band_drop ) );

  src.type = OFPMBT_DROP;
  src.len = sizeof( struct ofp_meter_band_drop );
  src.rate = 500;
  src.burst_size = 1000;

  hton_meter_band_drop( &dst, &src );

  assert_int_equal( dst.type, htons( src.type ) );
  assert_int_equal( dst.len, htons( src.len ) );
  assert_int_equal( ( int ) dst.rate, ( int ) htonl( src.rate ) );
  assert_int_equal( ( int ) dst.burst_size, ( int ) htonl( src.burst_size ) );
}

/********************************************************************************
 * ntoh_meter_band_dscp_remark() test.
 ********************************************************************************/

void
test_ntoh_meter_band_dscp_remark() {
  struct ofp_meter_band_dscp_remark dst;
  struct ofp_meter_band_dscp_remark src;

  memset( &src, 0, sizeof( struct ofp_meter_band_dscp_remark ) );
  memset( &dst, 0, sizeof( struct ofp_meter_band_dscp_remark ) );

  src.type = htons( OFPMBT_DSCP_REMARK );
  src.len = htons( sizeof( struct ofp_meter_band_dscp_remark ) );
  src.rate = htonl( 500 );
  src.burst_size = htonl( 1000 );
  src.prec_level = 10;

  ntoh_meter_band_dscp_remark( &dst, &src );

  assert_int_equal( htons( dst.type ), src.type );
  assert_int_equal( htons( dst.len ), src.len );
  assert_int_equal( ( int ) htonl( dst.rate ), ( int ) src.rate );
  assert_int_equal( ( int ) htonl( dst.burst_size ), ( int ) src.burst_size );
  assert_int_equal( dst.prec_level, src.prec_level );
}

/********************************************************************************
 * hton_meter_band_dscp_remark() test.
 ********************************************************************************/

void
test_hton_meter_band_dscp_remark() {
  struct ofp_meter_band_dscp_remark dst;
  struct ofp_meter_band_dscp_remark src;

  memset( &src, 0, sizeof( struct ofp_meter_band_dscp_remark ) );
  memset( &dst, 0, sizeof( struct ofp_meter_band_dscp_remark ) );

  src.type = OFPMBT_DSCP_REMARK;
  src.len = sizeof( struct ofp_meter_band_dscp_remark );
  src.rate = 500;
  src.burst_size = 1000;
  src.prec_level = 10;

  hton_meter_band_dscp_remark( &dst, &src );

  assert_int_equal( dst.type, htons( src.type ) );
  assert_int_equal( dst.len, htons( src.len ) );
  assert_int_equal( ( int ) dst.rate, ( int ) htonl( src.rate ) );
  assert_int_equal( ( int ) dst.burst_size, ( int ) htonl( src.burst_size ) );
  assert_int_equal( dst.prec_level, src.prec_level );
}


/********************************************************************************
 * ntoh_meter_band_experimenter() test.
 ********************************************************************************/

void
test_ntoh_meter_band_experimenter() {
  buffer *body;

  body = alloc_buffer_with_length( 32 );
  append_back_buffer( body, 32 );
  memset( body->data, 'a', body->length );

  uint16_t offset = sizeof( struct ofp_meter_band_experimenter );
  uint16_t length = ( uint16_t ) ( offset + body->length );

  struct ofp_meter_band_experimenter *src = xmalloc( length );
  struct ofp_meter_band_experimenter *dst = xmalloc( length );
  memset( src, 0, length );
  memset( dst, 0, length );

  src->type = htons( OFPMBT_EXPERIMENTER );
  src->len = htons( length );
  src->rate = htonl( 500 );
  src->burst_size = htonl( 1000 );
  src->experimenter = htonl( 1 );
  memcpy( ( char * ) src + offset, ( char * ) body->data, body->length );

  ntoh_meter_band_experimenter( dst, src );

  assert_int_equal( htons( dst->type ), src->type );
  assert_int_equal( htons( dst->len ), src->len );
  assert_int_equal( ( int ) htonl( dst->rate ), ( int ) src->rate );
  assert_int_equal( ( int ) htonl( dst->burst_size ), ( int ) src->burst_size );
  assert_int_equal( ( int ) htonl( dst->experimenter ), ( int ) src->experimenter );
  assert_memory_equal( ( (char * ) dst + offset ), ( (char * ) src + offset ), body->length );

  xfree( src );
  xfree( dst );
  free_buffer( body );
}

/********************************************************************************
 * hton_meter_band_experimenter() test.
 ********************************************************************************/

void
test_hton_meter_band_experimenter() {
  buffer *body;

  body = alloc_buffer_with_length( 32 );
  append_back_buffer( body, 32 );
  memset( body->data, 'a', body->length );

  uint16_t offset = sizeof( struct ofp_meter_band_experimenter );
  uint16_t length = ( uint16_t ) ( offset + body->length );

  struct ofp_meter_band_experimenter *src = xmalloc( length );
  struct ofp_meter_band_experimenter *dst = xmalloc( length );
  memset( src, 0, length );
  memset( dst, 0, length );

  src->type = OFPMBT_EXPERIMENTER;
  src->len = length;
  src->rate = 500;
  src->burst_size = 1000;
  src->experimenter = 1;
  memcpy( ( char * ) src + offset, ( char * ) body->data, body->length );

  hton_meter_band_experimenter( dst, src );

  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->len, htons( src->len ) );
  assert_int_equal( ( int ) dst->rate, ( int ) htonl( src->rate ) );
  assert_int_equal( ( int ) dst->burst_size, ( int ) htonl( src->burst_size ) );
  assert_int_equal( ( int ) dst->experimenter, ( int ) htonl( src->experimenter ) );
  assert_memory_equal( ( (char * ) dst + offset ), ( (char * ) src + offset ), body->length );

  xfree( src );
  xfree( dst );
  free_buffer( body );
}

/********************************************************************************
 * ntoh_meter_band_header() test.
 ********************************************************************************/

void
test_ntoh_meter_band_header_OFPMBT_DROP() {
  struct ofp_meter_band_drop dst;
  struct ofp_meter_band_drop src;

  memset( &src, 0, sizeof( struct ofp_meter_band_drop ) );
  memset( &dst, 0, sizeof( struct ofp_meter_band_drop ) );

  src.type = htons( OFPMBT_DROP );
  src.len = htons( sizeof( struct ofp_meter_band_drop ) );
  src.rate = htonl( 500 );
  src.burst_size = htonl( 1000 );

  ntoh_meter_band_header( ( struct ofp_meter_band_header* ) &dst, ( struct ofp_meter_band_header* ) &src );

  assert_int_equal( dst.type, htons( src.type ) );
  assert_int_equal( dst.len, htons( src.len ) );
  assert_int_equal( ( int ) dst.rate, ( int ) htonl( src.rate ) );
  assert_int_equal( ( int ) dst.burst_size, ( int ) htonl( src.burst_size ) );
}

void
test_ntoh_meter_band_header_OFPMBT_DSCP_REMARK() {
  struct ofp_meter_band_dscp_remark dst;
  struct ofp_meter_band_dscp_remark src;

  memset( &src, 0, sizeof( struct ofp_meter_band_dscp_remark ) );
  memset( &dst, 0, sizeof( struct ofp_meter_band_dscp_remark ) );

  src.type = htons( OFPMBT_DSCP_REMARK );
  src.len = htons( sizeof( struct ofp_meter_band_dscp_remark ) );
  src.rate = htonl( 500 );
  src.burst_size = htonl( 1000 );

  ntoh_meter_band_header( ( struct ofp_meter_band_header* ) &dst, ( struct ofp_meter_band_header* ) &src );

  assert_int_equal( dst.type, htons( src.type ) );
  assert_int_equal( dst.len, htons( src.len ) );
  assert_int_equal( ( int ) dst.rate, ( int ) htonl( src.rate ) );
  assert_int_equal( ( int ) dst.burst_size, ( int ) htonl( src.burst_size ) );
}

void
test_ntoh_meter_band_header_OFPMBT_EXPERIMENTER() {
  struct ofp_meter_band_experimenter dst;
  struct ofp_meter_band_experimenter src;

  memset( &src, 0, sizeof( struct ofp_meter_band_experimenter ) );
  memset( &dst, 0, sizeof( struct ofp_meter_band_experimenter ) );

  src.type = htons( OFPMBT_EXPERIMENTER );
  src.len = htons( sizeof( struct ofp_meter_band_experimenter ) );
  src.rate = htonl( 500 );
  src.burst_size = htonl( 1000 );

  ntoh_meter_band_header( ( struct ofp_meter_band_header* ) &dst, ( struct ofp_meter_band_header* ) &src );

  assert_int_equal( dst.type, htons( src.type ) );
  assert_int_equal( dst.len, htons( src.len ) );
  assert_int_equal( ( int ) dst.rate, ( int ) htonl( src.rate ) );
  assert_int_equal( ( int ) dst.burst_size, ( int ) htonl( src.burst_size ) );
}

void
test_ntoh_meter_band_header_unknown_type() {
  struct ofp_meter_band_header dst;
  struct ofp_meter_band_header src;

  memset( &src, 0, sizeof( struct ofp_meter_band_header ) );
  memset( &dst, 0, sizeof( struct ofp_meter_band_header ) );

  src.type = htons( OFPMBT_EXPERIMENTER - 1 );
  src.len = htons( sizeof( struct ofp_meter_band_header ) );
  src.rate = htonl( 500 );
  src.burst_size = htonl( 1000 );

  expect_assert_failure( ntoh_meter_band_header( &dst, &src ) );
}

/********************************************************************************
 * hton_meter_band_header() test.
 ********************************************************************************/

void
test_hton_meter_band_header_OFPMBT_DROP() {
  struct ofp_meter_band_drop dst;
  struct ofp_meter_band_drop src;

  memset( &src, 0, sizeof( struct ofp_meter_band_drop ) );
  memset( &dst, 0, sizeof( struct ofp_meter_band_drop ) );

  src.type = OFPMBT_DROP;
  src.len = sizeof( struct ofp_meter_band_drop );
  src.rate = 500;
  src.burst_size = 1000;

  hton_meter_band_header( ( struct ofp_meter_band_header* ) &dst, ( struct ofp_meter_band_header* ) &src );

  assert_int_equal( htons( dst.type ), src.type );
  assert_int_equal( htons( dst.len ), src.len );
  assert_int_equal( ( int ) htonl( dst.rate ), ( int ) src.rate );
  assert_int_equal( ( int ) htonl( dst.burst_size ), ( int ) src.burst_size );
}

void
test_hton_meter_band_header_OFPMBT_DSCP_REMARK() {
  struct ofp_meter_band_dscp_remark dst;
  struct ofp_meter_band_dscp_remark src;

  memset( &src, 0, sizeof( struct ofp_meter_band_dscp_remark ) );
  memset( &dst, 0, sizeof( struct ofp_meter_band_dscp_remark ) );

  src.type = OFPMBT_DSCP_REMARK;
  src.len = sizeof( struct ofp_meter_band_dscp_remark );
  src.rate = 500;
  src.burst_size = 1000;

  hton_meter_band_header( ( struct ofp_meter_band_header* ) &dst, ( struct ofp_meter_band_header* ) &src );

  assert_int_equal( htons( dst.type ), src.type );
  assert_int_equal( htons( dst.len ), src.len );
  assert_int_equal( ( int ) htonl( dst.rate ), ( int ) src.rate );
  assert_int_equal( ( int ) htonl( dst.burst_size ), ( int ) src.burst_size );
}

void
test_hton_meter_band_header_OFPMBT_EXPERIMENTER() {
  struct ofp_meter_band_experimenter dst;
  struct ofp_meter_band_experimenter src;

  memset( &src, 0, sizeof( struct ofp_meter_band_experimenter ) );
  memset( &dst, 0, sizeof( struct ofp_meter_band_experimenter ) );

  src.type = OFPMBT_EXPERIMENTER;
  src.len = sizeof( struct ofp_meter_band_experimenter );
  src.rate = 500;
  src.burst_size = 1000;

  hton_meter_band_header( ( struct ofp_meter_band_header* ) &dst, ( struct ofp_meter_band_header* ) &src );

  assert_int_equal( htons( dst.type ), src.type );
  assert_int_equal( htons( dst.len ), src.len );
  assert_int_equal( ( int ) htonl( dst.rate ), ( int ) src.rate );
  assert_int_equal( ( int ) htonl( dst.burst_size ), ( int ) src.burst_size );
}

void
test_hton_meter_band_header_unknown_type() {
  struct ofp_meter_band_header dst;
  struct ofp_meter_band_header src;

  memset( &src, 0, sizeof( struct ofp_meter_band_header ) );
  memset( &dst, 0, sizeof( struct ofp_meter_band_header ) );

  src.type = ( OFPMBT_EXPERIMENTER - 1 );
  src.len = sizeof( struct ofp_meter_band_header );
  src.rate = 500;
  src.burst_size = 1000;

  expect_assert_failure( ntoh_meter_band_header( &dst, &src ) );
}

/********************************************************************************
 * ntoh_table_feature_prop_instructions() test.
 ********************************************************************************/

void
test_ntoh_table_feature_prop_instructions_OFPTFPT_INSTRUCTIONS() {
  openflow_instructions *instructions;
  struct ofp_instruction *inst1, *inst2;
  uint16_t instructions_len;
  
  create_instruction_testdata();
  inst1 = xcalloc( 1, instruction_testdata_len[0] );
  memcpy( inst1, instruction_testdata[0], instruction_testdata_len[0] );
  inst2 = xcalloc( 1, instruction_testdata_len[1] );
  memcpy( inst2, instruction_testdata[1], instruction_testdata_len[1] );


  instructions = create_instructions();
  instructions->n_instructions = 2;
  append_to_tail( &instructions->list, inst1 );
  append_to_tail( &instructions->list, inst2 );

  instructions_len = ( uint16_t ) get_instructions_length( instructions );
  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_table_feature_prop_instructions ) + instructions_len );
  uint16_t alloc_len = ( uint16_t ) ( length + PADLEN_TO_64( length ) );

  struct ofp_table_feature_prop_instructions *src = xmalloc( alloc_len );
  struct ofp_table_feature_prop_instructions *dst = xmalloc( alloc_len );
  memset( src, 0, alloc_len );
  memset( dst, 0, alloc_len );

  struct ofp_instruction *expected_inst = xcalloc( 1, instructions_len );
  memcpy( expected_inst, instruction_testdata[0], instruction_testdata_len[0] );
  memcpy( ( char * ) expected_inst + instruction_testdata_len[0], instruction_testdata[1], instruction_testdata_len[1] );

  src->type = htons( OFPTFPT_INSTRUCTIONS );
  src->length = htons( length );
  uint16_t offset = sizeof( struct ofp_instruction );
  hton_instruction( ( struct ofp_instruction * ) ( ( char * ) src + offset ), instruction_testdata[0] );
  hton_instruction( ( struct ofp_instruction * ) ( ( char * ) src + offset + instruction_testdata_len[0] ), instruction_testdata[1] );

  ntoh_table_feature_prop_instructions( dst, src );

  assert_int_equal( htons( dst->type ), src->type );
  assert_int_equal( htons( dst->length ), src->length );
  assert_memory_equal( ( ( char * ) dst + offset ), ( ( char * ) expected_inst ), instructions_len );

  delete_instructions( instructions );
  delete_instruction_testdata();
  xfree( expected_inst );
  xfree( src );
  xfree( dst );
}

void
test_ntoh_table_feature_prop_instructions_OFPTFPT_INSTRUCTIONS_MISS() {
  openflow_instructions *instructions;
  struct ofp_instruction *inst1, *inst2;
  uint16_t instructions_len;
  
  create_instruction_testdata();
  inst1 = xcalloc( 1, instruction_testdata_len[0] );
  memcpy( inst1, instruction_testdata[0], instruction_testdata_len[0] );
  inst2 = xcalloc( 1, instruction_testdata_len[1] );
  memcpy( inst2, instruction_testdata[1], instruction_testdata_len[1] );

  instructions = create_instructions();
  instructions->n_instructions = 2;
  append_to_tail( &instructions->list, inst1 );
  append_to_tail( &instructions->list, inst2 );

  instructions_len = ( uint16_t ) get_instructions_length( instructions );
  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_table_feature_prop_instructions ) + instructions_len );
  uint16_t alloc_len = ( uint16_t ) ( length + PADLEN_TO_64( length ) );

  struct ofp_table_feature_prop_instructions *src = xmalloc( alloc_len );
  struct ofp_table_feature_prop_instructions *dst = xmalloc( alloc_len );
  memset( src, 0, alloc_len );
  memset( dst, 0, alloc_len );

  struct ofp_instruction *expected_inst = xcalloc( 1, instructions_len );
  memcpy( expected_inst, instruction_testdata[0], instruction_testdata_len[0] );
  memcpy( ( char * ) expected_inst + instruction_testdata_len[0], instruction_testdata[1], instruction_testdata_len[1] );

  src->type = htons( OFPTFPT_INSTRUCTIONS_MISS );
  src->length = htons( length );
  uint16_t offset = sizeof( struct ofp_instruction );
  hton_instruction( ( struct ofp_instruction * ) ( ( char * ) src + offset ), instruction_testdata[0] );
  hton_instruction( ( struct ofp_instruction * ) ( ( char * ) src + offset + instruction_testdata_len[0] ), instruction_testdata[1] );

  ntoh_table_feature_prop_instructions( dst, src );

  assert_int_equal( htons( dst->type ), src->type );
  assert_int_equal( htons( dst->length ), src->length );
  assert_memory_equal( ( ( char * ) dst + offset ), ( ( char * ) expected_inst ), instructions_len );

  delete_instructions( instructions );
  delete_instruction_testdata();
  xfree( expected_inst );
  xfree( src );
  xfree( dst );
}

/********************************************************************************
 * hton_table_feature_prop_instructions() test.
 ********************************************************************************/

void
test_hton_table_feature_prop_instructions_OFPTFPT_INSTRUCTIONS() {
  openflow_instructions *instructions;
  struct ofp_instruction *inst1, *inst2;
  uint16_t instructions_len;
  
  create_instruction_testdata();
  inst1 = xcalloc( 1, instruction_testdata_len[0] );
  memcpy( inst1, instruction_testdata[0], instruction_testdata_len[0] );
  inst2 = xcalloc( 1, instruction_testdata_len[1] );
  memcpy( inst2, instruction_testdata[1], instruction_testdata_len[1] );

  instructions = create_instructions();
  instructions->n_instructions = 2;
  append_to_tail( &instructions->list, inst1 );
  append_to_tail( &instructions->list, inst2 );

  instructions_len = ( uint16_t ) get_instructions_length( instructions );
  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_table_feature_prop_instructions ) + instructions_len );
  uint16_t alloc_len = ( uint16_t ) ( length + PADLEN_TO_64( length ) );

  struct ofp_table_feature_prop_instructions *src = xmalloc( alloc_len );
  struct ofp_table_feature_prop_instructions *dst = xmalloc( alloc_len );
  memset( src, 0, alloc_len );
  memset( dst, 0, alloc_len );

  struct ofp_instruction *expected_inst = xcalloc( 1, instructions_len );
  memcpy( expected_inst, instruction_testdata[0], instruction_testdata_len[0] );
  memcpy( ( char * ) expected_inst + instruction_testdata_len[0], instruction_testdata[1], instruction_testdata_len[1] );

  src->type = OFPTFPT_INSTRUCTIONS;
  src->length = length;
  memcpy( ( char * ) src + sizeof( struct ofp_table_feature_prop_instructions ), expected_inst, instructions_len );

  hton_table_feature_prop_instructions( dst, src );

  uint16_t offset = sizeof( struct ofp_instruction );
  hton_instruction( ( struct ofp_instruction * ) ( ( char * ) src + offset ), instruction_testdata[0] );
  hton_instruction( ( struct ofp_instruction * ) ( ( char * ) src + offset + instruction_testdata_len[0] ), instruction_testdata[1] );
  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  assert_memory_equal( ( ( char * ) dst + offset ), ( ( char * ) src + offset ), instructions_len );

  delete_instructions( instructions );
  delete_instruction_testdata();
  xfree( expected_inst );
  xfree( src );
  xfree( dst );
}

void
test_hton_table_feature_prop_instructions_OFPTFPT_INSTRUCTIONS_MISS() {
  openflow_instructions *instructions;
  struct ofp_instruction *inst1, *inst2;
  uint16_t instructions_len;
  
  create_instruction_testdata();
  inst1 = xcalloc( 1, instruction_testdata_len[0] );
  memcpy( inst1, instruction_testdata[0], instruction_testdata_len[0] );
  inst2 = xcalloc( 1, instruction_testdata_len[1] );
  memcpy( inst2, instruction_testdata[1], instruction_testdata_len[1] );


  instructions = create_instructions();
  instructions->n_instructions = 2;
  append_to_tail( &instructions->list, inst1 );
  append_to_tail( &instructions->list, inst2 );

  instructions_len = ( uint16_t ) get_instructions_length( instructions );
  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_table_feature_prop_instructions ) + instructions_len );
  uint16_t alloc_len = ( uint16_t ) ( length + PADLEN_TO_64( length ) );

  struct ofp_table_feature_prop_instructions *src = xmalloc( alloc_len );
  struct ofp_table_feature_prop_instructions *dst = xmalloc( alloc_len );
  memset( src, 0, alloc_len );
  memset( dst, 0, alloc_len );

  struct ofp_instruction *expected_inst = xcalloc( 1, instructions_len );
  memcpy( expected_inst, instruction_testdata[0], instruction_testdata_len[0] );
  memcpy( ( char * ) expected_inst + instruction_testdata_len[0], instruction_testdata[1], instruction_testdata_len[1] );

  src->type = OFPTFPT_INSTRUCTIONS_MISS;
  src->length = length;
  memcpy( ( char * ) src + sizeof( struct ofp_table_feature_prop_instructions ), expected_inst, instructions_len );

  hton_table_feature_prop_instructions( dst, src );

  uint16_t offset = sizeof( struct ofp_instruction );
  hton_instruction( ( struct ofp_instruction * ) ( ( char * ) src + offset ), instruction_testdata[0] );
  hton_instruction( ( struct ofp_instruction * ) ( ( char * ) src + offset + instruction_testdata_len[0] ), instruction_testdata[1] );
  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  assert_memory_equal( ( ( char * ) dst + offset ), ( ( char * ) src + offset ), instructions_len );

  delete_instructions( instructions );
  delete_instruction_testdata();
  xfree( expected_inst );
  xfree( src );
  xfree( dst );
}

/********************************************************************************
 * ntoh_table_feature_prop_next_tables() test.
 ********************************************************************************/

void
test_ntoh_table_feature_prop_next_tables_OFPTFPT_NEXT_TABLES() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_next_tables *src, *dst;
  uint16_t expected_table_len;
  uint8_t *expected_table;

  expected_table_len = ( uint16_t ) ( sizeof( uint8_t ) * 3 );
  expected_table = xcalloc( 1, expected_table_len );
  expected_table[0] = 0x12;
  expected_table[1] = 0x34;
  expected_table[2] = 0x56;

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_next_tables, next_table_ids ) + expected_table_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = htons( OFPTFPT_NEXT_TABLES );
  src->length = htons( expected_instruction_len );
  memcpy( ( uint8_t * ) src->next_table_ids, expected_table, expected_table_len );

  ntoh_table_feature_prop_next_tables( dst, src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->length ), src->length );
  assert_memory_equal( dst->next_table_ids, expected_table, expected_table_len );

  xfree( expected_table );
  xfree( src );
  xfree( dst );
}

void
test_ntoh_table_feature_prop_next_tables_OFPTFPT_NEXT_TABLES_MISS() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_next_tables *src, *dst;
  uint16_t expected_table_len;
  uint8_t *expected_table;

  expected_table_len = ( uint16_t ) ( sizeof( uint8_t ) * 3 );
  expected_table = xcalloc( 1, expected_table_len );
  expected_table[0] = 0x12;
  expected_table[1] = 0x34;
  expected_table[2] = 0x56;

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_next_tables, next_table_ids ) + expected_table_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = htons( OFPTFPT_NEXT_TABLES_MISS );
  src->length = htons( expected_instruction_len );
  memcpy( ( uint8_t * ) src->next_table_ids, expected_table, expected_table_len );

  ntoh_table_feature_prop_next_tables( dst, src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->length ), src->length );
  assert_memory_equal( dst->next_table_ids, expected_table, expected_table_len );

  xfree( expected_table );
  xfree( src );
  xfree( dst );
}

/********************************************************************************
 * hton_table_feature_prop_next_tables() test.
 ********************************************************************************/

void
test_hton_table_feature_prop_next_tables_OFPTFPT_NEXT_TABLES() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_next_tables *src, *dst;
  uint16_t expected_table_len;
  uint8_t *expected_table;

  expected_table_len = ( uint16_t ) ( sizeof( uint8_t ) * 3 );
  expected_table = xcalloc( 1, expected_table_len );
  expected_table[0] = 0x12;
  expected_table[1] = 0x34;
  expected_table[2] = 0x56;

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_next_tables, next_table_ids ) + expected_table_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = OFPTFPT_NEXT_TABLES;
  src->length = expected_instruction_len;
  memcpy( ( uint8_t * ) src->next_table_ids, expected_table, expected_table_len );

  hton_table_feature_prop_next_tables( dst, src );

  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  assert_memory_equal( dst->next_table_ids, expected_table, expected_table_len );

  xfree( expected_table );
  xfree( src );
  xfree( dst );
}

void
test_hton_table_feature_prop_next_tables_OFPTFPT_NEXT_TABLES_MISS() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_next_tables *src, *dst;
  uint16_t expected_table_len;
  uint8_t *expected_table;

  expected_table_len = ( uint16_t ) ( sizeof( uint8_t ) * 3 );
  expected_table = xcalloc( 1, expected_table_len );
  expected_table[0] = 0x12;
  expected_table[1] = 0x34;
  expected_table[2] = 0x56;

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_next_tables, next_table_ids ) + expected_table_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = OFPTFPT_NEXT_TABLES_MISS;
  src->length = expected_instruction_len;
  memcpy( ( uint8_t * ) src->next_table_ids, expected_table, expected_table_len );

  hton_table_feature_prop_next_tables( dst, src );

  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  assert_memory_equal( dst->next_table_ids, expected_table, expected_table_len );

  xfree( expected_table );
  xfree( src );
  xfree( dst );
}

/********************************************************************************
 * ntoh_table_feature_prop_actions() test.
 ********************************************************************************/

void
test_ntoh_table_feature_prop_actions() {
  struct ofp_action_header *act1, *act2;
  struct ofp_action_header *expected_act;
  uint16_t expected_act_len = 0;
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_actions *src, *dst;

  create_action_testdata();
  act1 = xcalloc( 1, action_testdata_len[0] );
  memcpy( act1, action_testdata[0], action_testdata_len[0] );
  act2 = xcalloc( 1, action_testdata_len[1] );
  memcpy( act2, action_testdata[1], action_testdata_len[1] );

  {
    expected_act_len = ( uint16_t ) ( action_testdata_len[0] + action_testdata_len[1] );
    expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_actions, action_ids ) + expected_act_len );
    expected_act = xcalloc( 1, expected_act_len );
    memcpy( expected_act, action_testdata[0], action_testdata_len[0] );
    memcpy( ( char * ) expected_act + action_testdata_len[0], action_testdata[1], action_testdata_len[1] );
  }
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );

  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = htons( OFPTFPT_WRITE_ACTIONS );
  src->length = htons( expected_instruction_len );
  hton_action( src->action_ids, action_testdata[0] );
  hton_action( ( struct ofp_action_header * ) ( ( char * ) src->action_ids + action_testdata_len[0] ), action_testdata[1] );

  ntoh_table_feature_prop_actions( dst, src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->length ), src->length );
  assert_memory_equal( dst->action_ids, expected_act, expected_act_len );

  xfree( expected_act );
  delete_action_testdata();
  xfree ( src );
  xfree ( dst );
  xfree ( act1 );
  xfree ( act2 );
}

void
test_ntoh_table_feature_prop_actions_nodata() {
  struct ofp_table_feature_prop_actions *src, *dst;
  uint16_t len = htons( sizeof( struct ofp_table_feature_prop_actions ) );
  uint16_t alloc_len = ( uint16_t ) ( len + PADLEN_TO_64( len ) );

  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = htons( OFPTFPT_WRITE_ACTIONS );
  src->length = len;

  ntoh_table_feature_prop_actions( dst, src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->length ), src->length );

  xfree ( src );
  xfree ( dst );
}

/********************************************************************************
 * hton_table_feature_prop_actions() test.
 ********************************************************************************/

void
test_hton_table_feature_prop_actions() {
  struct ofp_action_header *act1, *act2;
  struct ofp_action_header *expected_act;
  uint16_t expected_act_len = 0;
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_actions *src, *dst;

  create_action_testdata();
  act1 = xcalloc( 1, action_testdata_len[0] );
  memcpy( act1, action_testdata[0], action_testdata_len[0] );
  act2 = xcalloc( 1, action_testdata_len[1] );
  memcpy( act2, action_testdata[1], action_testdata_len[1] );

  {
    expected_act_len = ( uint16_t ) ( action_testdata_len[0] + action_testdata_len[1] );
    expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_actions, action_ids ) + expected_act_len );
    expected_act = xcalloc( 1, expected_act_len );
    memcpy( expected_act, action_testdata[0], action_testdata_len[0] );
    memcpy( ( char * ) expected_act + action_testdata_len[0], action_testdata[1], action_testdata_len[1] );
  }
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );

  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = OFPTFPT_WRITE_ACTIONS;
  src->length = expected_instruction_len;
  memcpy( &src->action_ids, expected_act, expected_act_len );

  hton_table_feature_prop_actions( dst, src );

  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  hton_action( expected_act, expected_act );
  uint16_t len = ntohs( expected_act->len );
  hton_action( ( struct ofp_action_header * ) ( ( char * ) expected_act + len ), ( struct ofp_action_header * ) ( ( char * ) expected_act + len ) );
  assert_memory_equal( dst->action_ids, expected_act, expected_act_len );

  xfree( expected_act );
  delete_action_testdata();
  xfree ( src );
  xfree ( dst );
  xfree ( act1 );
  xfree ( act2 );
}

void
test_hton_table_feature_prop_actions_nodata() {
  struct ofp_table_feature_prop_actions *src, *dst;

  uint16_t len = ( uint16_t ) sizeof( struct ofp_table_feature_prop_actions );
  uint16_t alloc_len = ( uint16_t ) ( len + PADLEN_TO_64( len ) );

  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = OFPTFPT_WRITE_ACTIONS;
  src->length = alloc_len;

  hton_table_feature_prop_actions( dst, src );

  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );

  xfree ( src );
  xfree ( dst );
}

/********************************************************************************
 * ntoh_table_feature_prop_oxm() test.
 ********************************************************************************/

void
test_ntoh_table_feature_prop_oxm() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_oxm *src, *dst;
  uint16_t expected_oxm_len;
  uint32_t *expected_oxm;

  expected_oxm_len = ( uint16_t ) ( sizeof( uint32_t ) * 3 );
  expected_oxm = xcalloc( 1, expected_oxm_len );
  expected_oxm[0] = htonl( 0x1234 );
  expected_oxm[1] = htonl( 0x5678 );
  expected_oxm[2] = htonl( 0x9ABC );

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_oxm, oxm_ids ) + expected_oxm_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = htons( OFPTFPT_MATCH );
  src->length = htons( expected_instruction_len );
  memcpy( ( uint32_t * ) src->oxm_ids, expected_oxm, expected_oxm_len );

  ntoh_table_feature_prop_oxm( dst, src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->length ), src->length );
  assert_int_equal( ( int ) htonl ( dst->oxm_ids[0] ), ( int ) expected_oxm[0] );
  assert_int_equal( ( int ) htonl ( dst->oxm_ids[1] ), ( int ) expected_oxm[1] );
  assert_int_equal( ( int ) htonl ( dst->oxm_ids[2] ), ( int ) expected_oxm[2] );
  uint32_t *expected_oxm_n = xcalloc( 1, expected_oxm_len );
  expected_oxm_n[0] = ntohl( expected_oxm[0] );
  expected_oxm_n[1] = ntohl( expected_oxm[1] );
  expected_oxm_n[2] = ntohl( expected_oxm[2] );
  assert_memory_equal( dst->oxm_ids, expected_oxm_n, expected_oxm_len );

  xfree( expected_oxm );
  xfree( expected_oxm_n );
  xfree( src );
  xfree( dst );
}

void
test_ntoh_table_feature_prop_oxm_nodata() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_oxm *src, *dst;
  uint16_t expected_oxm_len = 0;

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_oxm, oxm_ids ) + expected_oxm_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = htons( OFPTFPT_MATCH );
  src->length = htons( expected_instruction_len );

  ntoh_table_feature_prop_oxm( dst, src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->length ), src->length );

  xfree( src );
  xfree( dst );
}

/********************************************************************************
 * hton_table_feature_prop_oxm() test.
 ********************************************************************************/

void
test_hton_table_feature_prop_oxm() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_oxm *src, *dst;
  uint16_t expected_oxm_len;
  uint32_t *expected_oxm;

  expected_oxm_len = ( uint16_t ) ( sizeof( uint32_t ) * 3 );
  expected_oxm = xcalloc( 1, expected_oxm_len );
  expected_oxm[0] = 0x1234;
  expected_oxm[1] = 0x5678;
  expected_oxm[2] = 0x9ABC;

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_oxm, oxm_ids ) + expected_oxm_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = OFPTFPT_MATCH;
  src->length = expected_instruction_len;
  memcpy( ( uint32_t * ) src->oxm_ids, expected_oxm, expected_oxm_len );

  hton_table_feature_prop_oxm( dst, src );

  assert_int_equal( dst->type, htons ( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  assert_int_equal( ( int ) dst->oxm_ids[0], ( int ) htonl( expected_oxm[0] ) );
  assert_int_equal( ( int ) dst->oxm_ids[1], ( int ) htonl( expected_oxm[1] ) );
  assert_int_equal( ( int ) dst->oxm_ids[2], ( int ) htonl( expected_oxm[2] ) );
  uint32_t *expected_oxm_n = xcalloc( 1, expected_oxm_len );
  expected_oxm_n[0] = htonl( expected_oxm[0] );
  expected_oxm_n[1] = htonl( expected_oxm[1] );
  expected_oxm_n[2] = htonl( expected_oxm[2] );
  assert_memory_equal( dst->oxm_ids, expected_oxm_n, expected_oxm_len );

  xfree( expected_oxm );
  xfree( expected_oxm_n );
  xfree( src );
  xfree( dst );
}

void
test_hton_table_feature_prop_oxm_nodata() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_oxm *src, *dst;
  uint16_t expected_oxm_len = 0;

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_oxm, oxm_ids ) + expected_oxm_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = OFPTFPT_MATCH;
  src->length = expected_instruction_len;

  hton_table_feature_prop_oxm( dst, src );

  assert_int_equal( dst->type, htons ( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  xfree( src );
  xfree( dst );
}

/********************************************************************************
 * ntoh_table_feature_prop_experimenter() test.
 ********************************************************************************/

void
test_ntoh_table_feature_prop_experimenter() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_experimenter *src, *dst;
  uint16_t expected_experimenter_data_len = ( uint16_t ) ( sizeof( uint32_t ) * 3 );
  uint32_t expected_experimenter_data[] = { 0x1234, 0x5678, 0x9ABC };
  
  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_experimenter, experimenter_data ) + expected_experimenter_data_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = htons( OFPTFPT_EXPERIMENTER );
  src->length = htons( expected_instruction_len );
  src->experimenter = htonl( 1 );
  memcpy( ( uint32_t * ) src->experimenter_data, expected_experimenter_data, expected_experimenter_data_len );

  ntoh_table_feature_prop_experimenter( dst, src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->length ), src->length );
  assert_int_equal( ( int ) htonl ( dst->experimenter ), ( int ) src->experimenter );
  assert_memory_equal( dst->experimenter_data, expected_experimenter_data, expected_experimenter_data_len );

  xfree( src );
  xfree( dst );
}

void
test_ntoh_table_feature_prop_experimenter_nodata() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_experimenter *src, *dst;
  uint16_t expected_experimenter_data_len = 0;
  
  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_experimenter, experimenter_data ) + expected_experimenter_data_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = htons( OFPTFPT_EXPERIMENTER );
  src->length = htons( expected_instruction_len );
  src->experimenter = htonl( 1 );

  ntoh_table_feature_prop_experimenter( dst, src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->length ), src->length );
  assert_int_equal( ( int ) htonl ( dst->experimenter ), ( int ) src->experimenter );

  xfree( src );
  xfree( dst );
}

/********************************************************************************
 * hton_table_feature_prop_experimenter() test.
 ********************************************************************************/

void
test_hton_table_feature_prop_experimenter() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_experimenter *src, *dst;
  uint16_t expected_experimenter_data_len = ( uint16_t ) ( sizeof( uint32_t ) * 3 );
  uint32_t expected_experimenter_data[] = { 0x1234, 0x5678, 0x9ABC };
  
  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_experimenter, experimenter_data ) + expected_experimenter_data_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = OFPTFPT_EXPERIMENTER;
  src->length = expected_instruction_len;
  src->experimenter = htonl( 1 );
  memcpy( ( uint32_t * ) src->experimenter_data, expected_experimenter_data, expected_experimenter_data_len );

  hton_table_feature_prop_experimenter( dst, src );

  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  assert_int_equal( ( int ) dst->experimenter, ( int ) htonl( src->experimenter ) );
  assert_memory_equal( dst->experimenter_data, expected_experimenter_data, expected_experimenter_data_len );

  xfree( src );
  xfree( dst );
}

void
test_hton_table_feature_prop_experimenter_nodata() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_experimenter *src, *dst;
  uint16_t expected_experimenter_data_len = 0;
  
  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_experimenter, experimenter_data ) + expected_experimenter_data_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = OFPTFPT_EXPERIMENTER;
  src->length = expected_instruction_len;
  src->experimenter = htonl( 1 );

  hton_table_feature_prop_experimenter( dst, src );

  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  assert_int_equal( ( int ) dst->experimenter, ( int ) htonl( src->experimenter ) );

  xfree( src );
  xfree( dst );
}


/********************************************************************************
 * ntoh_table_feature_prop_header() test.
 ********************************************************************************/

void
test_ntoh_table_feature_prop_header_OFPTFPT_INSTRUCTIONS() {
  openflow_instructions *instructions;
  struct ofp_instruction *inst1, *inst2;
  uint16_t instructions_len;
  
  create_instruction_testdata();
  inst1 = xcalloc( 1, instruction_testdata_len[0] );
  memcpy( inst1, instruction_testdata[0], instruction_testdata_len[0] );
  inst2 = xcalloc( 1, instruction_testdata_len[1] );
  memcpy( inst2, instruction_testdata[1], instruction_testdata_len[1] );


  instructions = create_instructions();
  instructions->n_instructions = 2;
  append_to_tail( &instructions->list, inst1 );
  append_to_tail( &instructions->list, inst2 );

  instructions_len = ( uint16_t ) get_instructions_length( instructions );
  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_table_feature_prop_instructions ) + instructions_len );
  uint16_t alloc_len = ( uint16_t ) ( length + PADLEN_TO_64( length ) );

  struct ofp_table_feature_prop_instructions *src = xmalloc( alloc_len );
  struct ofp_table_feature_prop_instructions *dst = xmalloc( alloc_len );
  memset( src, 0, alloc_len );
  memset( dst, 0, alloc_len );

  struct ofp_instruction *expected_inst = xcalloc( 1, instructions_len );
  memcpy( expected_inst, instruction_testdata[0], instruction_testdata_len[0] );
  memcpy( ( char * ) expected_inst + instruction_testdata_len[0], instruction_testdata[1], instruction_testdata_len[1] );

  src->type = htons( OFPTFPT_INSTRUCTIONS );
  src->length = htons( length );
  uint16_t offset = sizeof( struct ofp_instruction );
  hton_instruction( ( struct ofp_instruction * ) ( ( char * ) src + offset ), instruction_testdata[0] );
  hton_instruction( ( struct ofp_instruction * ) ( ( char * ) src + offset + instruction_testdata_len[0] ), instruction_testdata[1] );

  ntoh_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( htons( dst->type ), src->type );
  assert_int_equal( htons( dst->length ), src->length );
  assert_memory_equal( ( ( char * ) dst + offset ), ( ( char * ) expected_inst ), instructions_len );

  delete_instructions( instructions );
  delete_instruction_testdata();
  xfree( expected_inst );
  xfree( src );
  xfree( dst );
}

void
test_ntoh_table_feature_prop_header_OFPTFPT_INSTRUCTIONS_MISS() {
  openflow_instructions *instructions;
  struct ofp_instruction *inst1, *inst2;
  uint16_t instructions_len;
  
  create_instruction_testdata();
  inst1 = xcalloc( 1, instruction_testdata_len[0] );
  memcpy( inst1, instruction_testdata[0], instruction_testdata_len[0] );
  inst2 = xcalloc( 1, instruction_testdata_len[1] );
  memcpy( inst2, instruction_testdata[1], instruction_testdata_len[1] );

  instructions = create_instructions();
  instructions->n_instructions = 2;
  append_to_tail( &instructions->list, inst1 );
  append_to_tail( &instructions->list, inst2 );

  instructions_len = ( uint16_t ) get_instructions_length( instructions );
  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_table_feature_prop_instructions ) + instructions_len );
  uint16_t alloc_len = ( uint16_t ) ( length + PADLEN_TO_64( length ) );

  struct ofp_table_feature_prop_instructions *src = xmalloc( alloc_len );
  struct ofp_table_feature_prop_instructions *dst = xmalloc( alloc_len );
  memset( src, 0, alloc_len );
  memset( dst, 0, alloc_len );

  struct ofp_instruction *expected_inst = xcalloc( 1, instructions_len );
  memcpy( expected_inst, instruction_testdata[0], instruction_testdata_len[0] );
  memcpy( ( char * ) expected_inst + instruction_testdata_len[0], instruction_testdata[1], instruction_testdata_len[1] );

  src->type = htons( OFPTFPT_INSTRUCTIONS_MISS );
  src->length = htons( length );
  uint16_t offset = sizeof( struct ofp_instruction );
  hton_instruction( ( struct ofp_instruction * ) ( ( char * ) src + offset ), instruction_testdata[0] );
  hton_instruction( ( struct ofp_instruction * ) ( ( char * ) src + offset + instruction_testdata_len[0] ), instruction_testdata[1] );

  ntoh_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( htons( dst->type ), src->type );
  assert_int_equal( htons( dst->length ), src->length );
  assert_memory_equal( ( ( char * ) dst + offset ), ( ( char * ) expected_inst ), instructions_len );

  delete_instructions( instructions );
  delete_instruction_testdata();
  xfree( expected_inst );
  xfree( src );
  xfree( dst );
}

void
test_ntoh_table_feature_prop_header_OFPTFPT_NEXT_TABLES() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_next_tables *src, *dst;
  uint16_t expected_table_len;
  uint8_t *expected_table;

  expected_table_len = ( uint16_t ) ( sizeof( uint8_t ) * 3 );
  expected_table = xcalloc( 1, expected_table_len );
  expected_table[0] = 0x12;
  expected_table[1] = 0x34;
  expected_table[2] = 0x56;

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_next_tables, next_table_ids ) + expected_table_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = htons( OFPTFPT_NEXT_TABLES );
  src->length = htons( expected_instruction_len );
  memcpy( ( uint8_t * ) src->next_table_ids, expected_table, expected_table_len );

  ntoh_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->length ), src->length );
  assert_memory_equal( dst->next_table_ids, expected_table, expected_table_len );

  xfree( expected_table );
  xfree( src );
  xfree( dst );
}

void
test_ntoh_table_feature_prop_header_OFPTFPT_NEXT_TABLES_MISS() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_next_tables *src, *dst;
  uint16_t expected_table_len;
  uint8_t *expected_table;

  expected_table_len = ( uint16_t ) ( sizeof( uint8_t ) * 3 );
  expected_table = xcalloc( 1, expected_table_len );
  expected_table[0] = 0x12;
  expected_table[1] = 0x34;
  expected_table[2] = 0x56;

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_next_tables, next_table_ids ) + expected_table_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = htons( OFPTFPT_NEXT_TABLES_MISS );
  src->length = htons( expected_instruction_len );
  memcpy( ( uint8_t * ) src->next_table_ids, expected_table, expected_table_len );

  ntoh_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->length ), src->length );
  assert_memory_equal( dst->next_table_ids, expected_table, expected_table_len );

  xfree( expected_table );
  xfree( src );
  xfree( dst );
}

void
test_ntoh_table_feature_prop_header_OFPTFPT_WRITE_ACTIONS() {
  struct ofp_action_header *act1, *act2;
  struct ofp_action_header *expected_act;
  uint16_t expected_act_len = 0;
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_actions *src, *dst;

  create_action_testdata();
  act1 = xcalloc( 1, action_testdata_len[0] );
  memcpy( act1, action_testdata[0], action_testdata_len[0] );
  act2 = xcalloc( 1, action_testdata_len[1] );
  memcpy( act2, action_testdata[1], action_testdata_len[1] );

  {
    expected_act_len = ( uint16_t ) ( action_testdata_len[0] + action_testdata_len[1] );
    expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_actions, action_ids ) + expected_act_len );
    expected_act = xcalloc( 1, expected_act_len );
    memcpy( expected_act, action_testdata[0], action_testdata_len[0] );
    memcpy( ( char * ) expected_act + action_testdata_len[0], action_testdata[1], action_testdata_len[1] );
  }
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );

  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = htons( OFPTFPT_WRITE_ACTIONS );
  src->length = htons( expected_instruction_len );
  hton_action( src->action_ids, action_testdata[0] );
  hton_action( ( struct ofp_action_header * ) ( ( char * ) src->action_ids + action_testdata_len[0] ), action_testdata[1] );

  ntoh_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->length ), src->length );
  assert_memory_equal( dst->action_ids, expected_act, expected_act_len );

  xfree( expected_act );
  delete_action_testdata();
  xfree ( src );
  xfree ( dst );
  xfree ( act1 );
  xfree ( act2 );
}

void
test_ntoh_table_feature_prop_header_OFPTFPT_WRITE_ACTIONS_MISS() {
  struct ofp_action_header *act1, *act2;
  struct ofp_action_header *expected_act;
  uint16_t expected_act_len = 0;
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_actions *src, *dst;

  create_action_testdata();
  act1 = xcalloc( 1, action_testdata_len[0] );
  memcpy( act1, action_testdata[0], action_testdata_len[0] );
  act2 = xcalloc( 1, action_testdata_len[1] );
  memcpy( act2, action_testdata[1], action_testdata_len[1] );

  {
    expected_act_len = ( uint16_t ) ( action_testdata_len[0] + action_testdata_len[1] );
    expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_actions, action_ids ) + expected_act_len );
    expected_act = xcalloc( 1, expected_act_len );
    memcpy( expected_act, action_testdata[0], action_testdata_len[0] );
    memcpy( ( char * ) expected_act + action_testdata_len[0], action_testdata[1], action_testdata_len[1] );
  }
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );

  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = htons( OFPTFPT_WRITE_ACTIONS_MISS );
  src->length = htons( expected_instruction_len );
  hton_action( src->action_ids, action_testdata[0] );
  hton_action( ( struct ofp_action_header * ) ( ( char * ) src->action_ids + action_testdata_len[0] ), action_testdata[1] );

  ntoh_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->length ), src->length );
  assert_memory_equal( dst->action_ids, expected_act, expected_act_len );

  xfree( expected_act );
  delete_action_testdata();
  xfree ( src );
  xfree ( dst );
  xfree ( act1 );
  xfree ( act2 );
}

void
test_ntoh_table_feature_prop_header_OFPTFPT_APPLY_ACTIONS() {
  struct ofp_action_header *act1, *act2;
  struct ofp_action_header *expected_act;
  uint16_t expected_act_len = 0;
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_actions *src, *dst;

  create_action_testdata();
  act1 = xcalloc( 1, action_testdata_len[0] );
  memcpy( act1, action_testdata[0], action_testdata_len[0] );
  act2 = xcalloc( 1, action_testdata_len[1] );
  memcpy( act2, action_testdata[1], action_testdata_len[1] );

  {
    expected_act_len = ( uint16_t ) ( action_testdata_len[0] + action_testdata_len[1] );
    expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_actions, action_ids ) + expected_act_len );
    expected_act = xcalloc( 1, expected_act_len );
    memcpy( expected_act, action_testdata[0], action_testdata_len[0] );
    memcpy( ( char * ) expected_act + action_testdata_len[0], action_testdata[1], action_testdata_len[1] );
  }
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );

  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = htons( OFPTFPT_APPLY_ACTIONS );
  src->length = htons( expected_instruction_len );
  hton_action( src->action_ids, action_testdata[0] );
  hton_action( ( struct ofp_action_header * ) ( ( char * ) src->action_ids + action_testdata_len[0] ), action_testdata[1] );

  ntoh_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->length ), src->length );
  assert_memory_equal( dst->action_ids, expected_act, expected_act_len );

  xfree( expected_act );
  delete_action_testdata();
  xfree ( src );
  xfree ( dst );
  xfree ( act1 );
  xfree ( act2 );
}

void
test_ntoh_table_feature_prop_header_OFPTFPT_APPLY_ACTIONS_MISS() {
  struct ofp_action_header *act1, *act2;
  struct ofp_action_header *expected_act;
  uint16_t expected_act_len = 0;
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_actions *src, *dst;

  create_action_testdata();
  act1 = xcalloc( 1, action_testdata_len[0] );
  memcpy( act1, action_testdata[0], action_testdata_len[0] );
  act2 = xcalloc( 1, action_testdata_len[1] );
  memcpy( act2, action_testdata[1], action_testdata_len[1] );

  {
    expected_act_len = ( uint16_t ) ( action_testdata_len[0] + action_testdata_len[1] );
    expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_actions, action_ids ) + expected_act_len );
    expected_act = xcalloc( 1, expected_act_len );
    memcpy( expected_act, action_testdata[0], action_testdata_len[0] );
    memcpy( ( char * ) expected_act + action_testdata_len[0], action_testdata[1], action_testdata_len[1] );
  }
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );

  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = htons( OFPTFPT_APPLY_ACTIONS_MISS );
  src->length = htons( expected_instruction_len );
  hton_action( src->action_ids, action_testdata[0] );
  hton_action( ( struct ofp_action_header * ) ( ( char * ) src->action_ids + action_testdata_len[0] ), action_testdata[1] );

  ntoh_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->length ), src->length );
  assert_memory_equal( dst->action_ids, expected_act, expected_act_len );

  xfree( expected_act );
  delete_action_testdata();
  xfree ( src );
  xfree ( dst );
  xfree ( act1 );
  xfree ( act2 );
}

void
test_ntoh_table_feature_prop_header_OFPTFPT_MATCH() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_oxm *src, *dst;
  uint16_t expected_oxm_len;
  uint32_t *expected_oxm;

  expected_oxm_len = ( uint16_t ) ( sizeof( uint32_t ) * 3 );
  expected_oxm = xcalloc( 1, expected_oxm_len );
  expected_oxm[0] = htonl( 0x1234 );
  expected_oxm[1] = htonl( 0x5678 );
  expected_oxm[2] = htonl( 0x9ABC );

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_oxm, oxm_ids ) + expected_oxm_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = htons( OFPTFPT_MATCH );
  src->length = htons( expected_instruction_len );
  memcpy( ( uint32_t * ) src->oxm_ids, expected_oxm, expected_oxm_len );

  ntoh_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->length ), src->length );
  assert_int_equal( ( int ) htonl ( dst->oxm_ids[0] ), ( int ) expected_oxm[0] );
  assert_int_equal( ( int ) htonl ( dst->oxm_ids[1] ), ( int ) expected_oxm[1] );
  assert_int_equal( ( int ) htonl ( dst->oxm_ids[2] ), ( int ) expected_oxm[2] );
  uint32_t *expected_oxm_n = xcalloc( 1, expected_oxm_len );
  expected_oxm_n[0] = ntohl( expected_oxm[0] );
  expected_oxm_n[1] = ntohl( expected_oxm[1] );
  expected_oxm_n[2] = ntohl( expected_oxm[2] );
  assert_memory_equal( dst->oxm_ids, expected_oxm_n, expected_oxm_len );

  xfree( expected_oxm );
  xfree( expected_oxm_n );
  xfree( src );
  xfree( dst );
}

void
test_ntoh_table_feature_prop_header_OFPTFPT_WILDCARDS() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_oxm *src, *dst;
  uint16_t expected_oxm_len;
  uint32_t *expected_oxm;

  expected_oxm_len = ( uint16_t ) ( sizeof( uint32_t ) * 3 );
  expected_oxm = xcalloc( 1, expected_oxm_len );
  expected_oxm[0] = htonl( 0x1234 );
  expected_oxm[1] = htonl( 0x5678 );
  expected_oxm[2] = htonl( 0x9ABC );

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_oxm, oxm_ids ) + expected_oxm_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = htons( OFPTFPT_WILDCARDS );
  src->length = htons( expected_instruction_len );
  memcpy( ( uint32_t * ) src->oxm_ids, expected_oxm, expected_oxm_len );

  ntoh_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->length ), src->length );
  assert_int_equal( ( int ) htonl ( dst->oxm_ids[0] ), ( int ) expected_oxm[0] );
  assert_int_equal( ( int ) htonl ( dst->oxm_ids[1] ), ( int ) expected_oxm[1] );
  assert_int_equal( ( int ) htonl ( dst->oxm_ids[2] ), ( int ) expected_oxm[2] );
  uint32_t *expected_oxm_n = xcalloc( 1, expected_oxm_len );
  expected_oxm_n[0] = ntohl( expected_oxm[0] );
  expected_oxm_n[1] = ntohl( expected_oxm[1] );
  expected_oxm_n[2] = ntohl( expected_oxm[2] );
  assert_memory_equal( dst->oxm_ids, expected_oxm_n, expected_oxm_len );

  xfree( expected_oxm );
  xfree( expected_oxm_n );
  xfree( src );
  xfree( dst );
}

void
test_ntoh_table_feature_prop_header_OFPTFPT_WRITE_SETFIELD() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_oxm *src, *dst;
  uint16_t expected_oxm_len;
  uint32_t *expected_oxm;

  expected_oxm_len = ( uint16_t ) ( sizeof( uint32_t ) * 3 );
  expected_oxm = xcalloc( 1, expected_oxm_len );
  expected_oxm[0] = htonl( 0x1234 );
  expected_oxm[1] = htonl( 0x5678 );
  expected_oxm[2] = htonl( 0x9ABC );

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_oxm, oxm_ids ) + expected_oxm_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = htons( OFPTFPT_WRITE_SETFIELD );
  src->length = htons( expected_instruction_len );
  memcpy( ( uint32_t * ) src->oxm_ids, expected_oxm, expected_oxm_len );

  ntoh_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->length ), src->length );
  assert_int_equal( ( int ) htonl ( dst->oxm_ids[0] ), ( int ) expected_oxm[0] );
  assert_int_equal( ( int ) htonl ( dst->oxm_ids[1] ), ( int ) expected_oxm[1] );
  assert_int_equal( ( int ) htonl ( dst->oxm_ids[2] ), ( int ) expected_oxm[2] );
  uint32_t *expected_oxm_n = xcalloc( 1, expected_oxm_len );
  expected_oxm_n[0] = ntohl( expected_oxm[0] );
  expected_oxm_n[1] = ntohl( expected_oxm[1] );
  expected_oxm_n[2] = ntohl( expected_oxm[2] );
  assert_memory_equal( dst->oxm_ids, expected_oxm_n, expected_oxm_len );

  xfree( expected_oxm );
  xfree( expected_oxm_n );
  xfree( src );
  xfree( dst );
}

void
test_ntoh_table_feature_prop_header_OFPTFPT_WRITE_SETFIELD_MISS() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_oxm *src, *dst;
  uint16_t expected_oxm_len;
  uint32_t *expected_oxm;

  expected_oxm_len = ( uint16_t ) ( sizeof( uint32_t ) * 3 );
  expected_oxm = xcalloc( 1, expected_oxm_len );
  expected_oxm[0] = htonl( 0x1234 );
  expected_oxm[1] = htonl( 0x5678 );
  expected_oxm[2] = htonl( 0x9ABC );

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_oxm, oxm_ids ) + expected_oxm_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = htons( OFPTFPT_WRITE_SETFIELD_MISS );
  src->length = htons( expected_instruction_len );
  memcpy( ( uint32_t * ) src->oxm_ids, expected_oxm, expected_oxm_len );

  ntoh_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->length ), src->length );
  assert_int_equal( ( int ) htonl ( dst->oxm_ids[0] ), ( int ) expected_oxm[0] );
  assert_int_equal( ( int ) htonl ( dst->oxm_ids[1] ), ( int ) expected_oxm[1] );
  assert_int_equal( ( int ) htonl ( dst->oxm_ids[2] ), ( int ) expected_oxm[2] );
  uint32_t *expected_oxm_n = xcalloc( 1, expected_oxm_len );
  expected_oxm_n[0] = ntohl( expected_oxm[0] );
  expected_oxm_n[1] = ntohl( expected_oxm[1] );
  expected_oxm_n[2] = ntohl( expected_oxm[2] );
  assert_memory_equal( dst->oxm_ids, expected_oxm_n, expected_oxm_len );

  xfree( expected_oxm );
  xfree( expected_oxm_n );
  xfree( src );
  xfree( dst );
}

void
test_ntoh_table_feature_prop_header_OFPTFPT_APPLY_SETFIELD() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_oxm *src, *dst;
  uint16_t expected_oxm_len;
  uint32_t *expected_oxm;

  expected_oxm_len = ( uint16_t ) ( sizeof( uint32_t ) * 3 );
  expected_oxm = xcalloc( 1, expected_oxm_len );
  expected_oxm[0] = htonl( 0x1234 );
  expected_oxm[1] = htonl( 0x5678 );
  expected_oxm[2] = htonl( 0x9ABC );

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_oxm, oxm_ids ) + expected_oxm_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = htons( OFPTFPT_APPLY_SETFIELD );
  src->length = htons( expected_instruction_len );
  memcpy( ( uint32_t * ) src->oxm_ids, expected_oxm, expected_oxm_len );

  ntoh_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->length ), src->length );
  assert_int_equal( ( int ) htonl ( dst->oxm_ids[0] ), ( int ) expected_oxm[0] );
  assert_int_equal( ( int ) htonl ( dst->oxm_ids[1] ), ( int ) expected_oxm[1] );
  assert_int_equal( ( int ) htonl ( dst->oxm_ids[2] ), ( int ) expected_oxm[2] );
  uint32_t *expected_oxm_n = xcalloc( 1, expected_oxm_len );
  expected_oxm_n[0] = ntohl( expected_oxm[0] );
  expected_oxm_n[1] = ntohl( expected_oxm[1] );
  expected_oxm_n[2] = ntohl( expected_oxm[2] );
  assert_memory_equal( dst->oxm_ids, expected_oxm_n, expected_oxm_len );

  xfree( expected_oxm );
  xfree( expected_oxm_n );
  xfree( src );
  xfree( dst );
}

void
test_ntoh_table_feature_prop_header_OFPTFPT_APPLY_SETFIELD_MISS() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_oxm *src, *dst;
  uint16_t expected_oxm_len;
  uint32_t *expected_oxm;

  expected_oxm_len = ( uint16_t ) ( sizeof( uint32_t ) * 3 );
  expected_oxm = xcalloc( 1, expected_oxm_len );
  expected_oxm[0] = htonl( 0x1234 );
  expected_oxm[1] = htonl( 0x5678 );
  expected_oxm[2] = htonl( 0x9ABC );

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_oxm, oxm_ids ) + expected_oxm_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = htons( OFPTFPT_APPLY_SETFIELD_MISS );
  src->length = htons( expected_instruction_len );
  memcpy( ( uint32_t * ) src->oxm_ids, expected_oxm, expected_oxm_len );

  ntoh_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->length ), src->length );
  assert_int_equal( ( int ) htonl ( dst->oxm_ids[0] ), ( int ) expected_oxm[0] );
  assert_int_equal( ( int ) htonl ( dst->oxm_ids[1] ), ( int ) expected_oxm[1] );
  assert_int_equal( ( int ) htonl ( dst->oxm_ids[2] ), ( int ) expected_oxm[2] );
  uint32_t *expected_oxm_n = xcalloc( 1, expected_oxm_len );
  expected_oxm_n[0] = ntohl( expected_oxm[0] );
  expected_oxm_n[1] = ntohl( expected_oxm[1] );
  expected_oxm_n[2] = ntohl( expected_oxm[2] );
  assert_memory_equal( dst->oxm_ids, expected_oxm_n, expected_oxm_len );

  xfree( expected_oxm );
  xfree( expected_oxm_n );
  xfree( src );
  xfree( dst );
}

void
test_ntoh_table_feature_prop_header_OFPTFPT_EXPERIMENTER() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_experimenter *src, *dst;
  uint16_t expected_experimenter_data_len = ( uint16_t ) ( sizeof( uint32_t ) * 3 );
  uint32_t expected_experimenter_data[] = { 0x1234, 0x5678, 0x9ABC };
  
  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_experimenter, experimenter_data ) + expected_experimenter_data_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = htons( OFPTFPT_EXPERIMENTER );
  src->length = htons( expected_instruction_len );
  src->experimenter = htonl( 1 );
  memcpy( ( uint32_t * ) src->experimenter_data, expected_experimenter_data, expected_experimenter_data_len );

  ntoh_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->length ), src->length );
  assert_int_equal( ( int ) htonl ( dst->experimenter ), ( int ) src->experimenter );
  assert_memory_equal( dst->experimenter_data, expected_experimenter_data, expected_experimenter_data_len );

  xfree( src );
  xfree( dst );
}

void
test_ntoh_table_feature_prop_header_OFPTFPT_EXPERIMENTER_MISS() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_experimenter *src, *dst;
  uint16_t expected_experimenter_data_len = ( uint16_t ) ( sizeof( uint32_t ) * 3 );
  uint32_t expected_experimenter_data[] = { 0x1234, 0x5678, 0x9ABC };
  
  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_experimenter, experimenter_data ) + expected_experimenter_data_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = htons( OFPTFPT_EXPERIMENTER_MISS );
  src->length = htons( expected_instruction_len );
  src->experimenter = htonl( 1 );
  memcpy( ( uint32_t * ) src->experimenter_data, expected_experimenter_data, expected_experimenter_data_len );

  ntoh_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( htons ( dst->type ), src->type );
  assert_int_equal( htons ( dst->length ), src->length );
  assert_int_equal( ( int ) htonl ( dst->experimenter ), ( int ) src->experimenter );
  assert_memory_equal( dst->experimenter_data, expected_experimenter_data, expected_experimenter_data_len );

  xfree( src );
  xfree( dst );
}

void
test_ntoh_table_feature_prop_header_unknown_type() {
  struct ofp_table_feature_prop_header dst;
  struct ofp_table_feature_prop_header src;
  memset( &src, 0, sizeof( struct ofp_table_feature_prop_header ) );
  memset( &dst, 0, sizeof( struct ofp_table_feature_prop_header ) );

  src.type = htons ( OFPTFPT_EXPERIMENTER - 1 );
  src.length = htons( sizeof( struct ofp_table_feature_prop_header ) );

  expect_assert_failure( ntoh_table_feature_prop_header( &dst, &src ) );
}

/********************************************************************************
 * hton_table_feature_prop_header() test.
 ********************************************************************************/

void
test_hton_table_feature_prop_header_OFPTFPT_INSTRUCTIONS() {
  openflow_instructions *instructions;
  struct ofp_instruction *inst1, *inst2;
  uint16_t instructions_len;
  
  create_instruction_testdata();
  inst1 = xcalloc( 1, instruction_testdata_len[0] );
  memcpy( inst1, instruction_testdata[0], instruction_testdata_len[0] );
  inst2 = xcalloc( 1, instruction_testdata_len[1] );
  memcpy( inst2, instruction_testdata[1], instruction_testdata_len[1] );

  instructions = create_instructions();
  instructions->n_instructions = 2;
  append_to_tail( &instructions->list, inst1 );
  append_to_tail( &instructions->list, inst2 );

  instructions_len = ( uint16_t ) get_instructions_length( instructions );
  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_table_feature_prop_instructions ) + instructions_len );
  uint16_t alloc_len = ( uint16_t ) ( length + PADLEN_TO_64( length ) );

  struct ofp_table_feature_prop_instructions *src = xmalloc( alloc_len );
  struct ofp_table_feature_prop_instructions *dst = xmalloc( alloc_len );
  memset( src, 0, alloc_len );
  memset( dst, 0, alloc_len );

  struct ofp_instruction *expected_inst = xcalloc( 1, instructions_len );
  memcpy( expected_inst, instruction_testdata[0], instruction_testdata_len[0] );
  memcpy( ( char * ) expected_inst + instruction_testdata_len[0], instruction_testdata[1], instruction_testdata_len[1] );

  src->type = OFPTFPT_INSTRUCTIONS;
  src->length = length;
  memcpy( ( char * ) src + sizeof( struct ofp_table_feature_prop_instructions ), expected_inst, instructions_len );

  hton_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  uint16_t offset = sizeof( struct ofp_instruction );
  hton_instruction( ( struct ofp_instruction * ) ( ( char * ) src + offset ), instruction_testdata[0] );
  hton_instruction( ( struct ofp_instruction * ) ( ( char * ) src + offset + instruction_testdata_len[0] ), instruction_testdata[1] );
  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  assert_memory_equal( ( ( char * ) dst + offset ), ( ( char * ) src + offset ), instructions_len );

  delete_instructions( instructions );
  delete_instruction_testdata();
  xfree( expected_inst );
  xfree( src );
  xfree( dst );
}

void
test_hton_table_feature_prop_header_OFPTFPT_INSTRUCTIONS_MISS() {
  openflow_instructions *instructions;
  struct ofp_instruction *inst1, *inst2;
  uint16_t instructions_len;
  
  create_instruction_testdata();
  inst1 = xcalloc( 1, instruction_testdata_len[0] );
  memcpy( inst1, instruction_testdata[0], instruction_testdata_len[0] );
  inst2 = xcalloc( 1, instruction_testdata_len[1] );
  memcpy( inst2, instruction_testdata[1], instruction_testdata_len[1] );

  instructions = create_instructions();
  instructions->n_instructions = 2;
  append_to_tail( &instructions->list, inst1 );
  append_to_tail( &instructions->list, inst2 );

  instructions_len = ( uint16_t ) get_instructions_length( instructions );
  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_table_feature_prop_instructions ) + instructions_len );
  uint16_t alloc_len = ( uint16_t ) ( length + PADLEN_TO_64( length ) );

  struct ofp_table_feature_prop_instructions *src = xmalloc( alloc_len );
  struct ofp_table_feature_prop_instructions *dst = xmalloc( alloc_len );
  memset( src, 0, alloc_len );
  memset( dst, 0, alloc_len );

  struct ofp_instruction *expected_inst = xcalloc( 1, instructions_len );
  memcpy( expected_inst, instruction_testdata[0], instruction_testdata_len[0] );
  memcpy( ( char * ) expected_inst + instruction_testdata_len[0], instruction_testdata[1], instruction_testdata_len[1] );

  src->type = OFPTFPT_INSTRUCTIONS_MISS;
  src->length = length;
  memcpy( ( char * ) src + sizeof( struct ofp_table_feature_prop_instructions ), expected_inst, instructions_len );

  hton_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  uint16_t offset = sizeof( struct ofp_instruction );
  hton_instruction( ( struct ofp_instruction * ) ( ( char * ) src + offset ), instruction_testdata[0] );
  hton_instruction( ( struct ofp_instruction * ) ( ( char * ) src + offset + instruction_testdata_len[0] ), instruction_testdata[1] );
  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  assert_memory_equal( ( ( char * ) dst + offset ), ( ( char * ) src + offset ), instructions_len );

  delete_instructions( instructions );
  delete_instruction_testdata();
  xfree( expected_inst );
  xfree( src );
  xfree( dst );
}

void
test_hton_table_feature_prop_header_OFPTFPT_NEXT_TABLES() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_next_tables *src, *dst;
  uint16_t expected_table_len;
  uint8_t *expected_table;

  expected_table_len = ( uint16_t ) ( sizeof( uint8_t ) * 3 );
  expected_table = xcalloc( 1, expected_table_len );
  expected_table[0] = 0x12;
  expected_table[1] = 0x34;
  expected_table[2] = 0x56;

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_next_tables, next_table_ids ) + expected_table_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = OFPTFPT_NEXT_TABLES;
  src->length = expected_instruction_len;
  memcpy( ( uint8_t * ) src->next_table_ids, expected_table, expected_table_len );

  hton_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  assert_memory_equal( dst->next_table_ids, expected_table, expected_table_len );

  xfree( expected_table );
  xfree( src );
  xfree( dst );
}

void
test_hton_table_feature_prop_header_OFPTFPT_NEXT_TABLES_MISS() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_next_tables *src, *dst;
  uint16_t expected_table_len;
  uint8_t *expected_table;

  expected_table_len = ( uint16_t ) ( sizeof( uint8_t ) * 3 );
  expected_table = xcalloc( 1, expected_table_len );
  expected_table[0] = 0x12;
  expected_table[1] = 0x34;
  expected_table[2] = 0x56;

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_next_tables, next_table_ids ) + expected_table_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = OFPTFPT_NEXT_TABLES_MISS;
  src->length = expected_instruction_len;
  memcpy( ( uint8_t * ) src->next_table_ids, expected_table, expected_table_len );

  hton_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  assert_memory_equal( dst->next_table_ids, expected_table, expected_table_len );

  xfree( expected_table );
  xfree( src );
  xfree( dst );
}

void
test_hton_table_feature_prop_header_OFPTFPT_WRITE_ACTIONS() {
  struct ofp_action_header *act1, *act2;
  struct ofp_action_header *expected_act;
  uint16_t expected_act_len = 0;
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_actions *src, *dst;

  create_action_testdata();
  act1 = xcalloc( 1, action_testdata_len[0] );
  memcpy( act1, action_testdata[0], action_testdata_len[0] );
  act2 = xcalloc( 1, action_testdata_len[1] );
  memcpy( act2, action_testdata[1], action_testdata_len[1] );

  {
    expected_act_len = ( uint16_t ) ( action_testdata_len[0] + action_testdata_len[1] );
    expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_actions, action_ids ) + expected_act_len );
    expected_act = xcalloc( 1, expected_act_len );
    memcpy( expected_act, action_testdata[0], action_testdata_len[0] );
    memcpy( ( char * ) expected_act + action_testdata_len[0], action_testdata[1], action_testdata_len[1] );
  }
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );

  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = OFPTFPT_WRITE_ACTIONS;
  src->length = expected_instruction_len;
  memcpy( &src->action_ids, expected_act, expected_act_len );

  hton_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  hton_action( expected_act, expected_act );
  uint16_t len = ntohs( expected_act->len );
  hton_action( ( struct ofp_action_header * ) ( ( char * ) expected_act + len ), ( struct ofp_action_header * ) ( ( char * ) expected_act + len ) );
  assert_memory_equal( dst->action_ids, expected_act, expected_act_len );

  xfree( expected_act );
  delete_action_testdata();
  xfree ( src );
  xfree ( dst );
  xfree ( act1 );
  xfree ( act2 );
}

void
test_hton_table_feature_prop_header_OFPTFPT_WRITE_ACTIONS_MISS() {
  struct ofp_action_header *act1, *act2;
  struct ofp_action_header *expected_act;
  uint16_t expected_act_len = 0;
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_actions *src, *dst;

  create_action_testdata();
  act1 = xcalloc( 1, action_testdata_len[0] );
  memcpy( act1, action_testdata[0], action_testdata_len[0] );
  act2 = xcalloc( 1, action_testdata_len[1] );
  memcpy( act2, action_testdata[1], action_testdata_len[1] );

  {
    expected_act_len = ( uint16_t ) ( action_testdata_len[0] + action_testdata_len[1] );
    expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_actions, action_ids ) + expected_act_len );
    expected_act = xcalloc( 1, expected_act_len );
    memcpy( expected_act, action_testdata[0], action_testdata_len[0] );
    memcpy( ( char * ) expected_act + action_testdata_len[0], action_testdata[1], action_testdata_len[1] );
  }
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );

  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = OFPTFPT_WRITE_ACTIONS_MISS;
  src->length = expected_instruction_len;
  memcpy( &src->action_ids, expected_act, expected_act_len );

  hton_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  hton_action( expected_act, expected_act );
  uint16_t len = ntohs( expected_act->len );
  hton_action( ( struct ofp_action_header * ) ( ( char * ) expected_act + len ), ( struct ofp_action_header * ) ( ( char * ) expected_act + len ) );
  assert_memory_equal( dst->action_ids, expected_act, expected_act_len );

  xfree( expected_act );
  delete_action_testdata();
  xfree ( src );
  xfree ( dst );
  xfree ( act1 );
  xfree ( act2 );
}

void
test_hton_table_feature_prop_header_OFPTFPT_APPLY_ACTIONS() {
  struct ofp_action_header *act1, *act2;
  struct ofp_action_header *expected_act;
  uint16_t expected_act_len = 0;
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_actions *src, *dst;

  create_action_testdata();
  act1 = xcalloc( 1, action_testdata_len[0] );
  memcpy( act1, action_testdata[0], action_testdata_len[0] );
  act2 = xcalloc( 1, action_testdata_len[1] );
  memcpy( act2, action_testdata[1], action_testdata_len[1] );

  {
    expected_act_len = ( uint16_t ) ( action_testdata_len[0] + action_testdata_len[1] );
    expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_actions, action_ids ) + expected_act_len );
    expected_act = xcalloc( 1, expected_act_len );
    memcpy( expected_act, action_testdata[0], action_testdata_len[0] );
    memcpy( ( char * ) expected_act + action_testdata_len[0], action_testdata[1], action_testdata_len[1] );
  }
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );

  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = OFPTFPT_APPLY_ACTIONS;
  src->length = expected_instruction_len;
  memcpy( &src->action_ids, expected_act, expected_act_len );

  hton_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  hton_action( expected_act, expected_act );
  uint16_t len = ntohs( expected_act->len );
  hton_action( ( struct ofp_action_header * ) ( ( char * ) expected_act + len ), ( struct ofp_action_header * ) ( ( char * ) expected_act + len ) );
  assert_memory_equal( dst->action_ids, expected_act, expected_act_len );

  xfree( expected_act );
  delete_action_testdata();
  xfree ( src );
  xfree ( dst );
  xfree ( act1 );
  xfree ( act2 );
}

void
test_hton_table_feature_prop_header_OFPTFPT_APPLY_ACTIONS_MISS() {
  struct ofp_action_header *act1, *act2;
  struct ofp_action_header *expected_act;
  uint16_t expected_act_len = 0;
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_actions *src, *dst;

  create_action_testdata();
  act1 = xcalloc( 1, action_testdata_len[0] );
  memcpy( act1, action_testdata[0], action_testdata_len[0] );
  act2 = xcalloc( 1, action_testdata_len[1] );
  memcpy( act2, action_testdata[1], action_testdata_len[1] );

  {
    expected_act_len = ( uint16_t ) ( action_testdata_len[0] + action_testdata_len[1] );
    expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_actions, action_ids ) + expected_act_len );
    expected_act = xcalloc( 1, expected_act_len );
    memcpy( expected_act, action_testdata[0], action_testdata_len[0] );
    memcpy( ( char * ) expected_act + action_testdata_len[0], action_testdata[1], action_testdata_len[1] );
  }
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );

  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = OFPTFPT_APPLY_ACTIONS_MISS;
  src->length = expected_instruction_len;
  memcpy( &src->action_ids, expected_act, expected_act_len );

  hton_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  hton_action( expected_act, expected_act );
  uint16_t len = ntohs( expected_act->len );
  hton_action( ( struct ofp_action_header * ) ( ( char * ) expected_act + len ), ( struct ofp_action_header * ) ( ( char * ) expected_act + len ) );
  assert_memory_equal( dst->action_ids, expected_act, expected_act_len );

  xfree( expected_act );
  delete_action_testdata();
  xfree ( src );
  xfree ( dst );
  xfree ( act1 );
  xfree ( act2 );
}

void
test_hton_table_feature_prop_header_OFPTFPT_MATCH() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_oxm *src, *dst;
  uint16_t expected_oxm_len;
  uint32_t *expected_oxm;

  expected_oxm_len = ( uint16_t ) ( sizeof( uint32_t ) * 3 );
  expected_oxm = xcalloc( 1, expected_oxm_len );
  expected_oxm[0] = 0x1234;
  expected_oxm[1] = 0x5678;
  expected_oxm[2] = 0x9ABC;

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_oxm, oxm_ids ) + expected_oxm_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = OFPTFPT_MATCH;
  src->length = expected_instruction_len;
  memcpy( ( uint32_t * ) src->oxm_ids, expected_oxm, expected_oxm_len );

  hton_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( dst->type, htons ( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  assert_int_equal( ( int ) dst->oxm_ids[0], ( int ) htonl( expected_oxm[0] ) );
  assert_int_equal( ( int ) dst->oxm_ids[1], ( int ) htonl( expected_oxm[1] ) );
  assert_int_equal( ( int ) dst->oxm_ids[2], ( int ) htonl( expected_oxm[2] ) );
  uint32_t *expected_oxm_n = xcalloc( 1, expected_oxm_len );
  expected_oxm_n[0] = htonl( expected_oxm[0] );
  expected_oxm_n[1] = htonl( expected_oxm[1] );
  expected_oxm_n[2] = htonl( expected_oxm[2] );
  assert_memory_equal( dst->oxm_ids, expected_oxm_n, expected_oxm_len );

  xfree( expected_oxm );
  xfree( expected_oxm_n );
  xfree( src );
  xfree( dst );
}

void
test_hton_table_feature_prop_header_OFPTFPT_WILDCARDS() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_oxm *src, *dst;
  uint16_t expected_oxm_len;
  uint32_t *expected_oxm;

  expected_oxm_len = ( uint16_t ) ( sizeof( uint32_t ) * 3 );
  expected_oxm = xcalloc( 1, expected_oxm_len );
  expected_oxm[0] = 0x1234;
  expected_oxm[1] = 0x5678;
  expected_oxm[2] = 0x9ABC;

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_oxm, oxm_ids ) + expected_oxm_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = OFPTFPT_WILDCARDS;
  src->length = expected_instruction_len;
  memcpy( ( uint32_t * ) src->oxm_ids, expected_oxm, expected_oxm_len );

  hton_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( dst->type, htons ( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  assert_int_equal( ( int ) dst->oxm_ids[0], ( int ) htonl( expected_oxm[0] ) );
  assert_int_equal( ( int ) dst->oxm_ids[1], ( int ) htonl( expected_oxm[1] ) );
  assert_int_equal( ( int ) dst->oxm_ids[2], ( int ) htonl( expected_oxm[2] ) );
  uint32_t *expected_oxm_n = xcalloc( 1, expected_oxm_len );
  expected_oxm_n[0] = htonl( expected_oxm[0] );
  expected_oxm_n[1] = htonl( expected_oxm[1] );
  expected_oxm_n[2] = htonl( expected_oxm[2] );
  assert_memory_equal( dst->oxm_ids, expected_oxm_n, expected_oxm_len );

  xfree( expected_oxm );
  xfree( expected_oxm_n );
  xfree( src );
  xfree( dst );
}

void
test_hton_table_feature_prop_header_OFPTFPT_WRITE_SETFIELD() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_oxm *src, *dst;
  uint16_t expected_oxm_len;
  uint32_t *expected_oxm;

  expected_oxm_len = ( uint16_t ) ( sizeof( uint32_t ) * 3 );
  expected_oxm = xcalloc( 1, expected_oxm_len );
  expected_oxm[0] = 0x1234;
  expected_oxm[1] = 0x5678;
  expected_oxm[2] = 0x9ABC;

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_oxm, oxm_ids ) + expected_oxm_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = OFPTFPT_WRITE_SETFIELD;
  src->length = expected_instruction_len;
  memcpy( ( uint32_t * ) src->oxm_ids, expected_oxm, expected_oxm_len );

  hton_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( dst->type, htons ( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  assert_int_equal( ( int ) dst->oxm_ids[0], ( int ) htonl( expected_oxm[0] ) );
  assert_int_equal( ( int ) dst->oxm_ids[1], ( int ) htonl( expected_oxm[1] ) );
  assert_int_equal( ( int ) dst->oxm_ids[2], ( int ) htonl( expected_oxm[2] ) );
  uint32_t *expected_oxm_n = xcalloc( 1, expected_oxm_len );
  expected_oxm_n[0] = htonl( expected_oxm[0] );
  expected_oxm_n[1] = htonl( expected_oxm[1] );
  expected_oxm_n[2] = htonl( expected_oxm[2] );
  assert_memory_equal( dst->oxm_ids, expected_oxm_n, expected_oxm_len );

  xfree( expected_oxm );
  xfree( expected_oxm_n );
  xfree( src );
  xfree( dst );
}

void
test_hton_table_feature_prop_header_OFPTFPT_WRITE_SETFIELD_MISS() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_oxm *src, *dst;
  uint16_t expected_oxm_len;
  uint32_t *expected_oxm;

  expected_oxm_len = ( uint16_t ) ( sizeof( uint32_t ) * 3 );
  expected_oxm = xcalloc( 1, expected_oxm_len );
  expected_oxm[0] = 0x1234;
  expected_oxm[1] = 0x5678;
  expected_oxm[2] = 0x9ABC;

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_oxm, oxm_ids ) + expected_oxm_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = OFPTFPT_WRITE_SETFIELD_MISS;
  src->length = expected_instruction_len;
  memcpy( ( uint32_t * ) src->oxm_ids, expected_oxm, expected_oxm_len );

  hton_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( dst->type, htons ( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  assert_int_equal( ( int ) dst->oxm_ids[0], ( int ) htonl( expected_oxm[0] ) );
  assert_int_equal( ( int ) dst->oxm_ids[1], ( int ) htonl( expected_oxm[1] ) );
  assert_int_equal( ( int ) dst->oxm_ids[2], ( int ) htonl( expected_oxm[2] ) );
  uint32_t *expected_oxm_n = xcalloc( 1, expected_oxm_len );
  expected_oxm_n[0] = htonl( expected_oxm[0] );
  expected_oxm_n[1] = htonl( expected_oxm[1] );
  expected_oxm_n[2] = htonl( expected_oxm[2] );
  assert_memory_equal( dst->oxm_ids, expected_oxm_n, expected_oxm_len );

  xfree( expected_oxm );
  xfree( expected_oxm_n );
  xfree( src );
  xfree( dst );
}

void
test_hton_table_feature_prop_header_OFPTFPT_APPLY_SETFIELD() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_oxm *src, *dst;
  uint16_t expected_oxm_len;
  uint32_t *expected_oxm;

  expected_oxm_len = ( uint16_t ) ( sizeof( uint32_t ) * 3 );
  expected_oxm = xcalloc( 1, expected_oxm_len );
  expected_oxm[0] = 0x1234;
  expected_oxm[1] = 0x5678;
  expected_oxm[2] = 0x9ABC;

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_oxm, oxm_ids ) + expected_oxm_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = OFPTFPT_APPLY_SETFIELD;
  src->length = expected_instruction_len;
  memcpy( ( uint32_t * ) src->oxm_ids, expected_oxm, expected_oxm_len );

  hton_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( dst->type, htons ( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  assert_int_equal( ( int ) dst->oxm_ids[0], ( int ) htonl( expected_oxm[0] ) );
  assert_int_equal( ( int ) dst->oxm_ids[1], ( int ) htonl( expected_oxm[1] ) );
  assert_int_equal( ( int ) dst->oxm_ids[2], ( int ) htonl( expected_oxm[2] ) );
  uint32_t *expected_oxm_n = xcalloc( 1, expected_oxm_len );
  expected_oxm_n[0] = htonl( expected_oxm[0] );
  expected_oxm_n[1] = htonl( expected_oxm[1] );
  expected_oxm_n[2] = htonl( expected_oxm[2] );
  assert_memory_equal( dst->oxm_ids, expected_oxm_n, expected_oxm_len );

  xfree( expected_oxm );
  xfree( expected_oxm_n );
  xfree( src );
  xfree( dst );
}

void
test_hton_table_feature_prop_header_OFPTFPT_APPLY_SETFIELD_MISS() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_oxm *src, *dst;
  uint16_t expected_oxm_len;
  uint32_t *expected_oxm;

  expected_oxm_len = ( uint16_t ) ( sizeof( uint32_t ) * 3 );
  expected_oxm = xcalloc( 1, expected_oxm_len );
  expected_oxm[0] = 0x1234;
  expected_oxm[1] = 0x5678;
  expected_oxm[2] = 0x9ABC;

  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_oxm, oxm_ids ) + expected_oxm_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = OFPTFPT_APPLY_SETFIELD_MISS;
  src->length = expected_instruction_len;
  memcpy( ( uint32_t * ) src->oxm_ids, expected_oxm, expected_oxm_len );

  hton_table_feature_prop_header( (struct ofp_table_feature_prop_header *) dst, (struct ofp_table_feature_prop_header *) src );

  assert_int_equal( dst->type, htons ( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  assert_int_equal( ( int ) dst->oxm_ids[0], ( int ) htonl( expected_oxm[0] ) );
  assert_int_equal( ( int ) dst->oxm_ids[1], ( int ) htonl( expected_oxm[1] ) );
  assert_int_equal( ( int ) dst->oxm_ids[2], ( int ) htonl( expected_oxm[2] ) );
  uint32_t *expected_oxm_n = xcalloc( 1, expected_oxm_len );
  expected_oxm_n[0] = htonl( expected_oxm[0] );
  expected_oxm_n[1] = htonl( expected_oxm[1] );
  expected_oxm_n[2] = htonl( expected_oxm[2] );
  assert_memory_equal( dst->oxm_ids, expected_oxm_n, expected_oxm_len );

  xfree( expected_oxm );
  xfree( expected_oxm_n );
  xfree( src );
  xfree( dst );
}

void
test_hton_table_feature_prop_header_OFPTFPT_EXPERIMENTER() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_experimenter *src, *dst;
  uint16_t expected_experimenter_data_len = ( uint16_t ) ( sizeof( uint32_t ) * 3 );
  uint32_t expected_experimenter_data[] = { 0x1234, 0x5678, 0x9ABC };
  
  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_experimenter, experimenter_data ) + expected_experimenter_data_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = OFPTFPT_EXPERIMENTER;
  src->length = expected_instruction_len;
  src->experimenter = htonl( 1 );
  memcpy( ( uint32_t * ) src->experimenter_data, expected_experimenter_data, expected_experimenter_data_len );

  hton_table_feature_prop_experimenter( dst, src );

  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  assert_int_equal( ( int ) dst->experimenter, ( int ) htonl( src->experimenter ) );
  assert_memory_equal( dst->experimenter_data, expected_experimenter_data, expected_experimenter_data_len );

  xfree( src );
  xfree( dst );
}

void
test_hton_table_feature_prop_header_OFPTFPT_EXPERIMENTER_MISS() {
  uint16_t expected_instruction_len;
  struct ofp_table_feature_prop_experimenter *src, *dst;
  uint16_t expected_experimenter_data_len = ( uint16_t ) ( sizeof( uint32_t ) * 3 );
  uint32_t expected_experimenter_data[] = { 0x1234, 0x5678, 0x9ABC };
  
  expected_instruction_len = ( uint16_t ) ( offsetof( struct ofp_table_feature_prop_experimenter, experimenter_data ) + expected_experimenter_data_len );
  uint16_t alloc_len = ( uint16_t ) ( expected_instruction_len + PADLEN_TO_64( expected_instruction_len ) );
  src = xcalloc( 1, alloc_len );
  dst = xcalloc( 1, alloc_len );

  src->type = OFPTFPT_EXPERIMENTER_MISS;
  src->length = expected_instruction_len;
  src->experimenter = htonl( 1 );
  memcpy( ( uint32_t * ) src->experimenter_data, expected_experimenter_data, expected_experimenter_data_len );

  hton_table_feature_prop_experimenter( dst, src );

  assert_int_equal( dst->type, htons( src->type ) );
  assert_int_equal( dst->length, htons( src->length ) );
  assert_int_equal( ( int ) dst->experimenter, ( int ) htonl( src->experimenter ) );
  assert_memory_equal( dst->experimenter_data, expected_experimenter_data, expected_experimenter_data_len );

  xfree( src );
  xfree( dst );
}

void
test_hton_table_feature_prop_header_unknown_type() {
  struct ofp_table_feature_prop_header dst;
  struct ofp_table_feature_prop_header src;
  memset( &src, 0, sizeof( struct ofp_table_feature_prop_header ) );
  memset( &dst, 0, sizeof( struct ofp_table_feature_prop_header ) );

  src.type = ( OFPTFPT_EXPERIMENTER - 1 );
  src.length = sizeof( struct ofp_table_feature_prop_header );

  expect_assert_failure( hton_table_feature_prop_header( &dst, &src ) );
}

/********************************************************************************
 * ntoh_table_features() test.
 ********************************************************************************/

void
test_ntoh_table_features() {
  uint64_t METADATA_MATCH = 50;
  uint64_t METADATA_WRITE = 100;

  openflow_instructions *instructions;
  struct ofp_instruction *inst1, *inst2;
  uint16_t instructions_len;
  
  create_instruction_testdata();
  inst1 = xcalloc( 1, instruction_testdata_len[0] );
  memcpy( inst1, instruction_testdata[0], instruction_testdata_len[0] );
  inst2 = xcalloc( 1, instruction_testdata_len[1] );
  memcpy( inst2, instruction_testdata[1], instruction_testdata_len[1] );

  instructions = create_instructions();
  instructions->n_instructions = 2;
  append_to_tail( &instructions->list, inst1 );
  append_to_tail( &instructions->list, inst2 );

  instructions_len = ( uint16_t ) get_instructions_length( instructions );
  uint16_t tfp_header_len = ( uint16_t ) sizeof( struct ofp_table_feature_prop_header );
  uint16_t feature_prop_len = ( uint16_t ) ( tfp_header_len + instructions_len );
  uint16_t feature_prop_total_len = ( uint16_t ) ( feature_prop_len + PADLEN_TO_64( feature_prop_len ) );
  uint16_t length = ( uint16_t ) ( sizeof ( struct ofp_table_features ) + feature_prop_total_len );
  uint16_t alloc_len = length;
  uint16_t offset = sizeof( struct ofp_table_features );

  struct ofp_table_features *src = xcalloc( 1, alloc_len );
  struct ofp_table_features *dst = xcalloc( 1, alloc_len );

  struct ofp_instruction *expected_inst = xcalloc( 1, instructions_len );
  memcpy( expected_inst, instruction_testdata[0], instruction_testdata_len[0] );
  memcpy( ( char * ) expected_inst + instruction_testdata_len[0], instruction_testdata[1], instruction_testdata_len[1] );

  src->length = htons( length );
  src->table_id = 1;
  memcpy( src->name, "TableFetName", OFP_MAX_TABLE_NAME_LEN);
  src->metadata_match = htonll( METADATA_MATCH );
  src->metadata_write = htonll( METADATA_WRITE );
  src->config = htonl( 500 );
  src->max_entries = htonl( 1000 );
  struct ofp_table_feature_prop_header *properties = ( struct ofp_table_feature_prop_header * ) ( src + 1 );
  properties->type = ntohs( OFPTFPT_INSTRUCTIONS );
  properties->length = ntohs( feature_prop_len );
  struct ofp_instruction *p_inst = ( struct ofp_instruction * ) ( properties + 1 );
  hton_instruction( p_inst, instruction_testdata[0] );
  hton_instruction( ( struct ofp_instruction * ) ( ( char * ) p_inst + instruction_testdata_len[0] ), instruction_testdata[1] );

  ntoh_table_features( dst, src );

  assert_int_equal( htons( dst->length ), src->length );
  assert_int_equal( dst->table_id, src->table_id );
  assert_memory_equal( dst->name, src->name, OFP_MAX_TABLE_NAME_LEN );
  assert_memory_equal( &dst->metadata_match, &METADATA_MATCH, sizeof( uint64_t ) );
  assert_memory_equal( &dst->metadata_write, &METADATA_WRITE, sizeof( uint64_t ) );
  assert_int_equal( ( int ) htonl( dst->config ), ( int ) src->config );
  assert_int_equal( ( int ) htonl( dst->max_entries ), ( int ) src->max_entries );
  assert_memory_equal( ( ( char * ) dst + offset + tfp_header_len ), ( ( char * ) expected_inst ), instructions_len );

  delete_instructions( instructions );
  delete_instruction_testdata();
  xfree( expected_inst );
  xfree( src );
  xfree( dst );
}

/********************************************************************************
 * hton_table_features() test.
 ********************************************************************************/

void
test_hton_table_features() {
  uint64_t METADATA_MATCH = 50;
  uint64_t METADATA_WRITE = 100;

  openflow_instructions *instructions;
  struct ofp_instruction *inst1, *inst2;
  uint16_t instructions_len;
  
  create_instruction_testdata();
  inst1 = xcalloc( 1, instruction_testdata_len[0] );
  memcpy( inst1, instruction_testdata[0], instruction_testdata_len[0] );
  inst2 = xcalloc( 1, instruction_testdata_len[1] );
  memcpy( inst2, instruction_testdata[1], instruction_testdata_len[1] );

  instructions = create_instructions();
  instructions->n_instructions = 2;
  append_to_tail( &instructions->list, inst1 );
  append_to_tail( &instructions->list, inst2 );

  instructions_len = ( uint16_t ) get_instructions_length( instructions );
  uint16_t tfp_header_len = ( uint16_t ) sizeof( struct ofp_table_feature_prop_header );
  uint16_t feature_prop_len = ( uint16_t ) ( tfp_header_len + instructions_len );
  uint16_t feature_prop_total_len = ( uint16_t ) ( feature_prop_len + PADLEN_TO_64( feature_prop_len ) );
  uint16_t length = ( uint16_t ) ( sizeof ( struct ofp_table_features ) + feature_prop_total_len );
  uint16_t alloc_len = length;
  uint16_t offset = sizeof( struct ofp_table_features );

  struct ofp_table_features *src = xcalloc( 1, alloc_len );
  struct ofp_table_features *dst = xcalloc( 1, alloc_len );

  struct ofp_instruction *expected_inst = xcalloc( 1, instructions_len );
  memcpy( expected_inst, instruction_testdata[0], instruction_testdata_len[0] );
  memcpy( ( char * ) expected_inst + instruction_testdata_len[0], instruction_testdata[1], instruction_testdata_len[1] );

  src->length = length;
  src->table_id = 1;
  memcpy( src->name, "TableFetName", OFP_MAX_TABLE_NAME_LEN);
  src->metadata_match = METADATA_MATCH;
  src->metadata_write = METADATA_WRITE;
  src->config = 500;
  src->max_entries = 1000;
  struct ofp_table_feature_prop_header *properties = ( struct ofp_table_feature_prop_header * ) ( src + 1 );
  properties->type = OFPTFPT_INSTRUCTIONS;
  properties->length = feature_prop_len;
  struct ofp_instruction *p_inst = ( struct ofp_instruction * ) ( properties + 1 );
  memcpy( p_inst, instruction_testdata[0], instruction_testdata_len[0] );
  memcpy( ( struct ofp_instruction * ) ( ( char * ) p_inst + instruction_testdata_len[0] ), instruction_testdata[1], instruction_testdata_len[1] );

  hton_table_features( dst, src );

  assert_int_equal( dst->length, htons ( src->length ));
  assert_int_equal( dst->table_id, src->table_id );
  assert_memory_equal( dst->name, src->name, OFP_MAX_TABLE_NAME_LEN );
  METADATA_MATCH = htonll( METADATA_MATCH );
  METADATA_WRITE = htonll( METADATA_WRITE );
  assert_memory_equal( &dst->metadata_match, &METADATA_MATCH, sizeof( uint64_t ) );
  assert_memory_equal( &dst->metadata_write, &METADATA_WRITE, sizeof( uint64_t ) );
  assert_int_equal( ( int ) dst->config, ( int ) htonl( src->config ) );
  assert_int_equal( ( int ) dst->max_entries, ( int ) htonl ( src->max_entries ) );
  hton_instruction( expected_inst, expected_inst );
  p_inst = ( struct ofp_instruction * ) ( ( char * ) expected_inst + instruction_testdata_len[0] );
  hton_instruction( p_inst, p_inst );
  assert_memory_equal( ( ( char * ) dst + offset + tfp_header_len ), ( ( char * ) expected_inst ), instructions_len );

  delete_instructions( instructions );
  delete_instruction_testdata();
  xfree( expected_inst );
  xfree( src );
  xfree( dst );
}

/********************************************************************************
 * ntoh_bucket_counter() test.
 ********************************************************************************/

void
test_ntoh_bucket_counter() {
  struct ofp_bucket_counter dst;
  struct ofp_bucket_counter src;
  uint64_t packet_count = 0x1111222233334444;
  uint64_t byte_count = 0x5555666677778888;

  memset( &src, 0, sizeof( struct ofp_bucket_counter ) );
  memset( &dst, 0, sizeof( struct ofp_bucket_counter ) );

  src.packet_count = htonll ( packet_count );
  src.byte_count = htonll ( byte_count );

  ntoh_bucket_counter( &dst, &src );

  assert_memory_equal( &dst.packet_count, &packet_count, sizeof( uint64_t ) );
  assert_memory_equal( &dst.byte_count, &byte_count, sizeof( uint64_t ) );
}

void
test_hton_bucket_counter() {
  struct ofp_bucket_counter dst;
  struct ofp_bucket_counter src;
  uint64_t packet_count = 0x1111222233334444;
  uint64_t packet_count_n = htonll( packet_count );
  uint64_t byte_count = 0x5555666677778888;
  uint64_t byte_count_n = htonll( byte_count );

  memset( &src, 0, sizeof( struct ofp_bucket_counter ) );
  memset( &dst, 0, sizeof( struct ofp_bucket_counter ) );

  src.packet_count = packet_count;
  src.byte_count = byte_count;

  hton_bucket_counter( &dst, &src );

  assert_memory_equal( &dst.packet_count, &packet_count_n, sizeof( uint64_t ) );
  assert_memory_equal( &dst.byte_count, &byte_count_n, sizeof( uint64_t ) );
}

/********************************************************************************
 * ntoh_group_stats() test.
 ********************************************************************************/

void
test_ntoh_group_stats() {
  struct ofp_bucket_counter *cnt1, *cnt2;
  uint16_t cnt1_len, cnt2_len;

  cnt1_len = sizeof( struct ofp_bucket_counter );
  cnt2_len = sizeof( struct ofp_bucket_counter );

  cnt1 = xcalloc( 1, cnt1_len );
  cnt1->packet_count = 0x1133224455776688;
  cnt1->byte_count = 0x1144223355886677;

  cnt2 = xcalloc( 1, cnt2_len );
  cnt2->packet_count = 0x1113311155776688;
  cnt2->byte_count = 0x1112211155886677;

  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_group_stats ) + cnt1_len + cnt2_len );
  uint64_t packet_count = 0x1111222233334444;
  uint64_t byte_count = 0x5555666677778888;

  struct ofp_group_stats *src = xmalloc( length );
  struct ofp_group_stats *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->length = htons( length );
  src->group_id = htonl( 10 );
  src->ref_count = htonl( 100 );
  src->packet_count = htonll ( packet_count );
  src->byte_count = htonll ( byte_count );
  src->duration_sec = htonl( 200 );
  src->duration_nsec = htonl( 400 );
  src->bucket_stats[0].packet_count = htonll( cnt1->packet_count );
  src->bucket_stats[0].byte_count = htonll( cnt1->byte_count );
  src->bucket_stats[1].packet_count = htonll( cnt2->packet_count );
  src->bucket_stats[1].byte_count = htonll( cnt2->byte_count );

  ntoh_group_stats( dst, src );

  assert_int_equal( htons( dst->length ), src->length );
  assert_int_equal( ( int ) htonl( dst->group_id ), ( int ) src->group_id );
  assert_int_equal( ( int ) htonl( dst->ref_count ), ( int ) src->ref_count );
  assert_memory_equal( &dst->packet_count, &packet_count, sizeof( uint64_t ) );
  assert_memory_equal( &dst->byte_count, &byte_count, sizeof( uint64_t ) );
  assert_int_equal( ( int ) htonl( dst->duration_sec ), ( int ) src->duration_sec );
  assert_int_equal( ( int ) htonl( dst->duration_nsec ), ( int ) src->duration_nsec );
  assert_memory_equal( &dst->bucket_stats[0], cnt1, cnt1_len );
  assert_memory_equal( &dst->bucket_stats[1], cnt2, cnt2_len );

  xfree( src );
  xfree( dst );
  xfree( cnt1 );
  xfree( cnt2 );
}

void
test_ntoh_group_stats_nodata() {
  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_group_stats ) );
  uint64_t packet_count = 0x1111222233334444;
  uint64_t byte_count = 0x5555666677778888;

  struct ofp_group_stats *src = xmalloc( length );
  struct ofp_group_stats *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->length = htons( length );
  src->group_id = htonl( 10 );
  src->ref_count = htonl( 100 );
  src->packet_count = htonll ( packet_count );
  src->byte_count = htonll ( byte_count );
  src->duration_sec = htonl( 200 );
  src->duration_nsec = htonl( 400 );

  ntoh_group_stats( dst, src );

  assert_int_equal( htons( dst->length ), src->length );
  assert_int_equal( ( int ) htonl( dst->group_id ), ( int ) src->group_id );
  assert_int_equal( ( int ) htonl( dst->ref_count ), ( int ) src->ref_count );
  assert_memory_equal( &dst->packet_count, &packet_count, sizeof( uint64_t ) );
  assert_memory_equal( &dst->byte_count, &byte_count, sizeof( uint64_t ) );
  assert_int_equal( ( int ) htonl( dst->duration_sec ), ( int ) src->duration_sec );
  assert_int_equal( ( int ) htonl( dst->duration_nsec ), ( int ) src->duration_nsec );

  xfree( src );
  xfree( dst );
}


/********************************************************************************
 * hton_group_stats() test.
 ********************************************************************************/

void
test_hton_group_stats() {
  struct ofp_bucket_counter *cnt1, *cnt2;
  uint16_t cnt1_len, cnt2_len;

  cnt1_len = sizeof( struct ofp_bucket_counter );
  cnt2_len = sizeof( struct ofp_bucket_counter );

  cnt1 = xcalloc( 1, cnt1_len );
  cnt1->packet_count = 0x1133224455776688;
  cnt1->byte_count = 0x1144223355886677;

  cnt2 = xcalloc( 1, cnt2_len );
  cnt2->packet_count = 0x1113311155776688;
  cnt2->byte_count = 0x1112211155886677;

  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_group_stats ) + cnt1_len + cnt2_len );
  uint64_t packet_count = 0x1111222233334444;
  uint64_t byte_count = 0x5555666677778888;

  struct ofp_group_stats *src = xmalloc( length );
  struct ofp_group_stats *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->length = length;
  src->group_id = 10;
  src->ref_count = 100;
  src->packet_count = packet_count;
  src->byte_count = byte_count;
  src->duration_sec = 200;
  src->duration_nsec = 400;
  src->bucket_stats[0].packet_count = cnt1->packet_count;
  src->bucket_stats[0].byte_count = cnt1->byte_count;
  src->bucket_stats[1].packet_count = cnt2->packet_count;
  src->bucket_stats[1].byte_count = cnt2->byte_count;

  hton_group_stats( dst, src );

  assert_int_equal( dst->length, ntohs( src->length ) );
  assert_int_equal( ( int ) dst->group_id, ( int ) ntohl( src->group_id ) );
  assert_int_equal( ( int ) dst->ref_count, ( int ) ntohl( src->ref_count ) );
  packet_count = htonll( packet_count );
  assert_memory_equal( &dst->packet_count, &packet_count, sizeof( uint64_t ) );
  byte_count = htonll( byte_count );
  assert_memory_equal( &dst->byte_count, &byte_count, sizeof( uint64_t ) );
  assert_int_equal( ( int ) dst->duration_sec, ( int ) htonl( src->duration_sec ) );
  assert_int_equal( ( int ) dst->duration_nsec, ( int ) htonl( src->duration_nsec ) );
  cnt1->packet_count = htonll( cnt1->packet_count );
  cnt1->byte_count = htonll( cnt1->byte_count );
  assert_memory_equal( &dst->bucket_stats[0], cnt1, cnt1_len );
  cnt2->packet_count = htonll( cnt2->packet_count );
  cnt2->byte_count = htonll( cnt2->byte_count );
  assert_memory_equal( &dst->bucket_stats[1], cnt2, cnt2_len );

  xfree( src );
  xfree( dst );
  xfree( cnt1 );
  xfree( cnt2 );
}

void
test_hton_group_stats_nodata() {
  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_group_stats ) );
  uint64_t packet_count = 0x1111222233334444;
  uint64_t packet_count_n = htonll( packet_count );
  uint64_t byte_count = 0x5555666677778888;
  uint64_t byte_count_n = htonll( byte_count );

  struct ofp_group_stats *src = xmalloc( length );
  struct ofp_group_stats *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->length = length;
  src->group_id = 10;
  src->ref_count = 100;
  src->packet_count = packet_count;
  src->byte_count = byte_count;
  src->duration_sec = 200;
  src->duration_nsec = 400;

  hton_group_stats( dst, src );

  assert_int_equal( dst->length, htons( src->length ) );
  assert_int_equal( ( int ) dst->group_id, ( int ) htonl( src->group_id ) );
  assert_int_equal( ( int ) dst->ref_count, ( int ) htonl( src->ref_count ) );
  assert_memory_equal( &dst->packet_count, &packet_count_n, sizeof( uint64_t ) );
  assert_memory_equal( &dst->byte_count, &byte_count_n, sizeof( uint64_t ) );
  assert_int_equal( ( int ) dst->duration_sec, ( int ) htonl( src->duration_sec ) );
  assert_int_equal( ( int ) dst->duration_nsec, ( int ) htonl( src->duration_nsec ) );

  xfree( src );
  xfree( dst );
}

/********************************************************************************
 * ntoh_group_desc_stats() test.
 ********************************************************************************/

void
test_ntoh_group_desc_stats() {
  uint16_t grpdsc_len;
  struct ofp_group_desc_stats *dsc1;

  create_bucket_testdata();

  grpdsc_len = ( uint16_t ) ( offsetof( struct ofp_group_desc_stats, buckets ) + bucket_testdata_len[0] );
  dsc1 = xcalloc( 1, grpdsc_len );
  dsc1->length = grpdsc_len;
  dsc1->type = OFPGT_SELECT;
  dsc1->group_id = 0x11223344;
  memcpy( dsc1->buckets, bucket_testdata[0], bucket_testdata_len[0] );

  uint16_t length = grpdsc_len;

  struct ofp_group_desc_stats *src = xmalloc( length );
  struct ofp_group_desc_stats *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->length = htons( dsc1->length );
  src->type = dsc1->type;
  src->group_id = htonl( dsc1->group_id );
  hton_bucket( src->buckets, dsc1->buckets );

  ntoh_group_desc_stats( dst, src );

  assert_int_equal( htons( dst->length ), src->length );
  assert_int_equal( dst->type, src->type );
  assert_int_equal( ( int ) htonl( dst->group_id ), ( int ) src->group_id );
  assert_memory_equal( dst->buckets, dsc1->buckets, bucket_testdata_len[0] );

  delete_bucket_testdata();
  xfree( dsc1 );
  xfree( src );
  xfree( dst );
}

void
test_ntoh_group_desc_stats_nodata() {
  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_group_desc_stats ) );

  struct ofp_group_desc_stats *src = xmalloc( length );
  struct ofp_group_desc_stats *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->length = htons( length );
  src->type = OFPGT_SELECT;
  src->group_id = htonl( 1 );

  ntoh_group_desc_stats( dst, src );

  assert_int_equal( htons( dst->length ), src->length );
  assert_int_equal( dst->type, src->type );
  assert_int_equal( ( int ) htonl( dst->group_id ), ( int ) src->group_id );

  xfree( src );
  xfree( dst );
}

/********************************************************************************
 * hton_group_desc_stats() test.
 ********************************************************************************/

void
test_hton_group_desc_stats() {
  uint16_t grpdsc_len;
  struct ofp_group_desc_stats *dsc1;

  create_bucket_testdata();

  grpdsc_len = ( uint16_t ) ( offsetof( struct ofp_group_desc_stats, buckets ) + bucket_testdata_len[0] );
  dsc1 = xcalloc( 1, grpdsc_len );
  dsc1->length = grpdsc_len;
  dsc1->type = OFPGT_SELECT;
  dsc1->group_id = 0x11223344;
  memcpy( dsc1->buckets, bucket_testdata[0], bucket_testdata_len[0] );

  uint16_t length = grpdsc_len;

  struct ofp_group_desc_stats *src = xmalloc( length );
  struct ofp_group_desc_stats *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->length = dsc1->length;
  src->type = dsc1->type;
  src->group_id = dsc1->group_id;
  memcpy( src->buckets, dsc1->buckets, bucket_testdata_len[0] );

  dsc1->length = htons( dsc1->length );
  dsc1->group_id = htonl( dsc1->group_id );
  hton_bucket( dsc1->buckets, dsc1->buckets );

  hton_group_desc_stats( dst, src );

  assert_int_equal( dst->length, htons( src->length ) );
  assert_int_equal( dst->type, src->type );
  assert_int_equal( ( int ) dst->group_id, ( int ) htonl( src->group_id ) );
  assert_memory_equal( dst->buckets, dsc1->buckets, bucket_testdata_len[0] );

  delete_bucket_testdata();
  xfree( dsc1 );
  xfree( src );
  xfree( dst );
}

void
test_hton_group_desc_stats_nodata() {
  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_group_desc_stats ) );

  struct ofp_group_desc_stats *src = xmalloc( length );
  struct ofp_group_desc_stats *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->length = length;
  src->type = OFPGT_SELECT;
  src->group_id = 1;

  hton_group_desc_stats( dst, src );

  assert_int_equal( dst->length, htons( src->length ) );
  assert_int_equal( dst->type, src->type );
  assert_int_equal( ( int ) dst->group_id, ( int ) htonl( src->group_id ) );

  xfree( src );
  xfree( dst );
}

/********************************************************************************
 * ntoh_group_features_stats() test.
 ********************************************************************************/

void
test_ntoh_group_features_stats() {
  struct ofp_group_features dst;
  struct ofp_group_features src;

  memset( &src, 0, sizeof( struct ofp_group_features ) );
  memset( &dst, 0, sizeof( struct ofp_group_features ) );

  src.types = htonl( OFPGT_ALL );
  src.capabilities = htonl( OFPGFC_SELECT_WEIGHT );
  src.max_groups[ 0 ] = htonl ( OFPMF_KBPS );
  src.max_groups[ 1 ] = htonl ( OFPMF_PKTPS );
  src.actions[ 0 ] = htonl( OFPAT_OUTPUT );
  src.actions[ 1 ] = htonl( OFPAT_COPY_TTL_OUT );

  ntoh_group_features_stats( &dst, &src );

  assert_int_equal( ( int ) htonl ( dst.types ), ( int ) src.types );
  assert_int_equal( ( int ) htonl ( dst.capabilities ), ( int ) src.capabilities );
  assert_int_equal( ( int ) htonl ( dst.max_groups[ 0 ] ), ( int ) src.max_groups[ 0 ] );
  assert_int_equal( ( int ) htonl ( dst.max_groups[ 1 ] ), ( int ) src.max_groups[ 1 ] );
  assert_int_equal( ( int ) htonl ( dst.actions[ 0 ] ), ( int ) src.actions[ 0 ] );
  assert_int_equal( ( int ) htonl ( dst.actions[ 1 ] ), ( int ) src.actions[ 1 ] );
}

/********************************************************************************
 * hton_group_features_stats() test.
 ********************************************************************************/

void
test_hton_group_features_stats() {
  struct ofp_group_features dst;
  struct ofp_group_features src;

  memset( &src, 0, sizeof( struct ofp_group_features ) );
  memset( &dst, 0, sizeof( struct ofp_group_features ) );

  src.types = OFPGT_ALL;
  src.capabilities = OFPGFC_SELECT_WEIGHT;
  src.max_groups[ 0 ] = OFPMF_KBPS;
  src.max_groups[ 1 ] = OFPMF_PKTPS;
  src.actions[ 0 ] = OFPAT_OUTPUT;
  src.actions[ 1 ] = OFPAT_COPY_TTL_OUT;

  hton_group_features_stats( &dst, &src );

  assert_int_equal( ( int ) dst.types, ( int ) htonl ( src.types ) );
  assert_int_equal( ( int ) dst.capabilities, ( int ) htonl ( src.capabilities ) );
  assert_int_equal( ( int ) dst.max_groups[ 0 ], ( int ) htonl ( src.max_groups[ 0 ] ) );
  assert_int_equal( ( int ) dst.max_groups[ 1 ], ( int ) htonl ( src.max_groups[ 1 ] ) );
  assert_int_equal( ( int ) dst.actions[ 0 ], ( int ) htonl ( src.actions[ 0 ] ) );
  assert_int_equal( ( int ) dst.actions[ 1 ], ( int ) htonl ( src.actions[ 1 ] ) );
}

/********************************************************************************
 * ntoh_meter_band_stats() test.
 ********************************************************************************/

void
test_ntoh_meter_band_stats() {
  struct ofp_meter_band_stats dst;
  struct ofp_meter_band_stats src;
  uint64_t packet_band_count = 0x1111222233334444;
  uint64_t byte_band_count = 0x5555666677778888;

  memset( &src, 0, sizeof( struct ofp_meter_band_stats ) );
  memset( &dst, 0, sizeof( struct ofp_meter_band_stats ) );

  src.packet_band_count = htonll ( packet_band_count );
  src.byte_band_count = htonll ( byte_band_count );

  ntoh_meter_band_stats( &dst, &src );

  assert_memory_equal( &dst.packet_band_count, &packet_band_count, sizeof( uint64_t ) );
  assert_memory_equal( &dst.byte_band_count, &byte_band_count, sizeof( uint64_t ) );
}

/********************************************************************************
 * hton_meter_band_stats() test.
 ********************************************************************************/

void
test_hton_meter_band_stats() {
  struct ofp_meter_band_stats dst;
  struct ofp_meter_band_stats src;
  uint64_t packet_band_count = 0x1111222233334444;
  uint64_t packet_band_count_n = htonll( packet_band_count );
  uint64_t byte_band_count = 0x5555666677778888;
  uint64_t byte_band_count_n = htonll( byte_band_count );

  memset( &src, 0, sizeof( struct ofp_meter_band_stats ) );
  memset( &dst, 0, sizeof( struct ofp_meter_band_stats ) );

  src.packet_band_count = packet_band_count;
  src.byte_band_count = byte_band_count;

  hton_meter_band_stats( &dst, &src );

  assert_memory_equal( &dst.packet_band_count, &packet_band_count_n, sizeof( uint64_t ) );
  assert_memory_equal( &dst.byte_band_count, &byte_band_count_n, sizeof( uint64_t ) );
}

/********************************************************************************
 * ntoh_meter_stats() test.
 ********************************************************************************/

void
test_ntoh_meter_stats() {
  struct ofp_meter_band_stats *expected_opt;
  uint16_t expected_opt_len = 0;
  uint16_t expected_total_len;
  struct ofp_meter_stats *src, *dst;
  uint64_t packet_in_count = 0x1111222233334444;
  uint64_t byte_in_count = 0x5555666677778888;

  create_meter_band_stats_testdata();

  {
    expected_opt_len = ( uint16_t ) ( meter_band_stats_testdata_len[0] + meter_band_stats_testdata_len[1] );
    expected_total_len = ( uint16_t ) ( offsetof( struct ofp_meter_stats, band_stats ) + expected_opt_len );
    expected_opt = xcalloc( 1, expected_opt_len );
    memcpy( expected_opt, meter_band_stats_testdata[0], meter_band_stats_testdata_len[0] );
    memcpy( ( char * ) expected_opt + meter_band_stats_testdata_len[0], meter_band_stats_testdata[1], meter_band_stats_testdata_len[1] );
  }

  src = xcalloc( 1, expected_total_len );
  dst = xcalloc( 1, expected_total_len );
  memset( src, 0, expected_total_len );
  memset( dst, 0, expected_total_len );

  src->meter_id = htonl( 10 );
  src->len = htons( expected_total_len );
  src->flow_count = htonl( 100 );
  src->packet_in_count = htonll ( packet_in_count );
  src->byte_in_count = htonll ( byte_in_count );
  src->duration_sec = htonl( 200 );
  src->duration_nsec = htonl( 400 );
  hton_meter_band_stats( src->band_stats, meter_band_stats_testdata[0] );
  hton_meter_band_stats( ( struct ofp_meter_band_stats * ) ( ( char * ) src->band_stats + meter_band_stats_testdata_len[0] ), meter_band_stats_testdata[1] );

  ntoh_meter_stats( dst, src );

  assert_int_equal( ( int ) htonl( dst->meter_id ), ( int ) src->meter_id );
  assert_int_equal( htons( dst->len ), src->len );
  assert_int_equal( ( int ) htonl( dst->flow_count ), ( int ) src->flow_count );
  assert_memory_equal( &dst->packet_in_count, &packet_in_count, sizeof( uint64_t ) );
  assert_memory_equal( &dst->byte_in_count, &byte_in_count, sizeof( uint64_t ) );
  assert_int_equal( ( int ) htonl( dst->duration_sec ), ( int ) src->duration_sec );
  assert_int_equal( ( int ) htonl( dst->duration_nsec ), ( int ) src->duration_nsec );
  assert_memory_equal( dst->band_stats, expected_opt, expected_opt_len );

  xfree( expected_opt );
  delete_meter_band_stats_testdata();
  xfree ( src );
  xfree ( dst );
}

void
test_ntoh_meter_stats_nodata() {
  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_meter_stats ) );
  uint64_t packet_in_count = 0x1111222233334444;
  uint64_t byte_in_count = 0x5555666677778888;

  struct ofp_meter_stats *src = xmalloc( length );
  struct ofp_meter_stats *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->meter_id = htonl( 10 );
  src->len = htons( length );
  src->flow_count = htonl( 100 );
  src->packet_in_count = htonll ( packet_in_count );
  src->byte_in_count = htonll ( byte_in_count );
  src->duration_sec = htonl( 200 );
  src->duration_nsec = htonl( 400 );

  ntoh_meter_stats( dst, src );

  assert_int_equal( ( int ) htonl( dst->meter_id ), ( int ) src->meter_id );
  assert_int_equal( htons( dst->len ), src->len );
  assert_int_equal( ( int ) htonl( dst->flow_count ), ( int ) src->flow_count );
  assert_memory_equal( &dst->packet_in_count, &packet_in_count, sizeof( uint64_t ) );
  assert_memory_equal( &dst->byte_in_count, &byte_in_count, sizeof( uint64_t ) );
  assert_int_equal( ( int ) htonl( dst->duration_sec ), ( int ) src->duration_sec );
  assert_int_equal( ( int ) htonl( dst->duration_nsec ), ( int ) src->duration_nsec );

  xfree( src );
  xfree( dst );
}

/********************************************************************************
 * hton_meter_stats() test.
 ********************************************************************************/

void
test_hton_meter_stats() {
  struct ofp_meter_band_stats *expected_opt;
  uint16_t expected_opt_len = 0;
  uint16_t expected_total_len;
  struct ofp_meter_stats *src, *dst;
  uint64_t packet_in_count = 0x1111222233334444;
  uint64_t packet_in_count_n = htonll( packet_in_count );
  uint64_t byte_in_count = 0x5555666677778888;
  uint64_t byte_in_count_n = htonll( byte_in_count );

  create_meter_band_stats_testdata();

  {
    expected_opt_len = ( uint16_t ) ( meter_band_stats_testdata_len[0] + meter_band_stats_testdata_len[1] );
    expected_total_len = ( uint16_t ) ( offsetof( struct ofp_meter_stats, band_stats ) + expected_opt_len );
    expected_opt = xcalloc( 1, expected_opt_len );
    memcpy( expected_opt, meter_band_stats_testdata[0], meter_band_stats_testdata_len[0] );
    memcpy( ( char * ) expected_opt + meter_band_stats_testdata_len[0], meter_band_stats_testdata[1], meter_band_stats_testdata_len[1] );
  }

  src = xcalloc( 1, expected_total_len );
  dst = xcalloc( 1, expected_total_len );
  memset( src, 0, expected_total_len );
  memset( dst, 0, expected_total_len );

  src->meter_id = 10;
  src->len = expected_total_len;
  src->flow_count = 100;
  src->packet_in_count = packet_in_count;
  src->byte_in_count = byte_in_count;
  src->duration_sec = 200;
  src->duration_nsec = 400;
  memcpy( &src->band_stats, expected_opt, expected_opt_len );

  hton_meter_stats( dst, src );

  hton_meter_band_stats( expected_opt, expected_opt );
  hton_meter_band_stats( ( struct ofp_meter_band_stats * ) ( ( char * ) expected_opt + sizeof( struct ofp_meter_band_stats ) ), ( struct ofp_meter_band_stats * ) ( ( char * ) expected_opt + sizeof( struct ofp_meter_band_stats ) ) );

  assert_int_equal( ( int ) dst->meter_id, ( int ) htonl( src->meter_id ) );
  assert_int_equal( dst->len, htons( src->len ) );
  assert_int_equal( ( int ) dst->flow_count, ( int ) htonl( src->flow_count ) );
  assert_memory_equal( &dst->packet_in_count, &packet_in_count_n, sizeof( uint64_t ) );
  assert_memory_equal( &dst->byte_in_count, &byte_in_count_n, sizeof( uint64_t ) );
  assert_int_equal( ( int ) dst->duration_sec, ( int ) htonl( src->duration_sec ) );
  assert_int_equal( ( int ) dst->duration_nsec, ( int ) htonl( src->duration_nsec ) );
  assert_memory_equal( dst->band_stats, expected_opt, expected_opt_len );

  xfree( expected_opt );
  delete_meter_band_stats_testdata();
  xfree ( src );
  xfree ( dst );
}

void
test_hton_meter_stats_nodata() {
  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_meter_stats ) );
  uint64_t packet_in_count = 0x1111222233334444;
  uint64_t packet_in_count_n = htonll( packet_in_count );
  uint64_t byte_in_count = 0x5555666677778888;
  uint64_t byte_in_count_n = htonll( byte_in_count );

  struct ofp_meter_stats *src = xmalloc( length );
  struct ofp_meter_stats *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->meter_id = 10;
  src->len = length;
  src->flow_count = 100;
  src->packet_in_count = packet_in_count;
  src->byte_in_count = byte_in_count;
  src->duration_sec = 200;
  src->duration_nsec = 400;

  hton_meter_stats( dst, src );

  assert_int_equal( ( int ) dst->meter_id, ( int ) htonl( src->meter_id ) );
  assert_int_equal( dst->len, htons( src->len ) );
  assert_int_equal( ( int ) dst->flow_count, ( int ) htonl( src->flow_count ) );
  assert_memory_equal( &dst->packet_in_count, &packet_in_count_n, sizeof( uint64_t ) );
  assert_memory_equal( &dst->byte_in_count, &byte_in_count_n, sizeof( uint64_t ) );
  assert_int_equal( ( int ) dst->duration_sec, ( int ) htonl( src->duration_sec ) );
  assert_int_equal( ( int ) dst->duration_nsec, ( int ) htonl( src->duration_nsec ) );

  xfree( src );
  xfree( dst );
}

/********************************************************************************
 * ntoh_meter_config() test.
 ********************************************************************************/

void
test_ntoh_meter_config() {
  struct ofp_meter_band_header *expected_opt;
  uint16_t expected_opt_len = 0;
  uint16_t expected_total_len;
  struct ofp_meter_config *src, *dst;

  create_meter_band_header_testdata();

  {
    expected_opt_len = ( uint16_t ) ( meter_band_header_testdata_len[0] + meter_band_header_testdata_len[1] );
    expected_total_len = ( uint16_t ) ( offsetof( struct ofp_meter_config, bands ) + expected_opt_len );
    expected_opt = xcalloc( 1, expected_opt_len );
    memcpy( expected_opt, meter_band_header_testdata[0], meter_band_header_testdata_len[0] );
    memcpy( ( char * ) expected_opt + meter_band_header_testdata_len[0], meter_band_header_testdata[1], meter_band_header_testdata_len[1] );
  }

  src = xcalloc( 1, expected_total_len );
  dst = xcalloc( 1, expected_total_len );
  memset( src, 0, expected_total_len );
  memset( dst, 0, expected_total_len );

  src->length = htons( expected_total_len );
  src->flags = htons( OFPMC_MODIFY );
  src->meter_id = htonl( 100 );
  hton_meter_band_header( src->bands, meter_band_header_testdata[0] );
  hton_meter_band_header( ( struct ofp_meter_band_header * ) ( ( char * ) src->bands + meter_band_header_testdata_len[0] ), meter_band_header_testdata[1] );

  ntoh_meter_config( dst, src );

  assert_int_equal( htons ( dst->length ), src->length );
  assert_int_equal( htons ( dst->flags ), src->flags );
  assert_int_equal( ( int ) htonl ( dst->meter_id ), ( int ) src->meter_id );
  assert_memory_equal( dst->bands, expected_opt, expected_opt_len );

  xfree( expected_opt );
  delete_meter_band_header_testdata();
  xfree ( src );
  xfree ( dst );
}

void
test_ntoh_meter_config_nodata() {
  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_meter_config ) );

  struct ofp_meter_config *src = xmalloc( length );
  struct ofp_meter_config *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->length = htons( length );
  src->flags = htons( OFPMC_MODIFY );
  src->meter_id = htonl( 1 );

  ntoh_meter_config( dst, src );

  assert_int_equal( htons( dst->length ), src->length );
  assert_int_equal( htons( dst->flags ), src->flags );
  assert_int_equal( ( int ) htonl( dst->meter_id ), ( int ) src->meter_id );

  xfree( src );
  xfree( dst );
}

/********************************************************************************
 * hton_meter_config() test.
 ********************************************************************************/

void
test_hton_meter_config() {
  struct ofp_meter_band_header *expected_opt;
  uint16_t expected_opt_len = 0;
  uint16_t expected_total_len;
  struct ofp_meter_config *src, *dst;

  create_meter_band_header_testdata();

  {
    expected_opt_len = ( uint16_t ) ( meter_band_header_testdata_len[0] + meter_band_header_testdata_len[1] );
    expected_total_len = ( uint16_t ) ( offsetof( struct ofp_meter_config, bands ) + expected_opt_len );
    expected_opt = xcalloc( 1, expected_opt_len );
    memcpy( expected_opt, meter_band_header_testdata[0], meter_band_header_testdata_len[0] );
    memcpy( ( char * ) expected_opt + meter_band_header_testdata_len[0], meter_band_header_testdata[1], meter_band_header_testdata_len[1] );
  }

  src = xcalloc( 1, expected_total_len );
  dst = xcalloc( 1, expected_total_len );
  memset( src, 0, expected_total_len );
  memset( dst, 0, expected_total_len );

  src->length = expected_total_len;
  src->flags = OFPMC_MODIFY;
  src->meter_id = 100;
  memcpy( &src->bands, expected_opt, expected_opt_len );

  hton_meter_config( dst, src );

  hton_meter_band_header( expected_opt, expected_opt );
  hton_meter_band_header( ( struct ofp_meter_band_header * ) ( ( char * ) expected_opt + ntohs( expected_opt->len ) ), ( struct ofp_meter_band_header * ) ( ( char * ) expected_opt + ntohs( expected_opt->len ) ) );

  assert_int_equal( dst->length, htons ( src->length ) );
  assert_int_equal( dst->flags, htons ( src->flags ) );
  assert_int_equal( ( int ) dst->meter_id, ( int ) htonl ( src->meter_id ) );
  assert_memory_equal( dst->bands, expected_opt, expected_opt_len );

  xfree( expected_opt );
  delete_meter_band_header_testdata();
  xfree ( src );
  xfree ( dst );
}


void
test_hton_meter_config_nodata() {
  uint16_t length = ( uint16_t ) ( sizeof( struct ofp_meter_config ) );

  struct ofp_meter_config *src = xmalloc( length );
  struct ofp_meter_config *dst = xmalloc( length );

  memset( src, 0, length );
  memset( dst, 0, length );

  src->length = length;
  src->flags = OFPMC_MODIFY;
  src->meter_id = 1;

  hton_meter_config( dst, src );

  assert_int_equal( dst->length, htons( src->length ) );
  assert_int_equal( dst->flags, htons( src->flags ) );
  assert_int_equal( ( int ) dst->meter_id, ( int ) htonl( src->meter_id ) );

  xfree( src );
  xfree( dst );
}

/********************************************************************************
 * ntoh_meter_features() test.
 ********************************************************************************/

void
test_ntoh_meter_features() {
  struct ofp_meter_features dst;
  struct ofp_meter_features src;

  memset( &src, 0, sizeof( struct ofp_meter_features ) );
  memset( &dst, 0, sizeof( struct ofp_meter_features ) );

  src.max_meter = htonl( 1000 );
  src.band_types = htonl( OFPMBT_DROP );
  src.capabilities = htonl ( OFPMF_KBPS );
  src.max_bands = 100;
  src.max_color = 10;

  ntoh_meter_features( &dst, &src );

  assert_int_equal( ( int ) htonl ( dst.max_meter ), ( int ) src.max_meter );
  assert_int_equal( ( int ) htonl ( dst.band_types ), ( int ) src.band_types );
  assert_int_equal( ( int ) htonl ( dst.capabilities ), ( int ) src.capabilities );
  assert_int_equal( dst.max_bands, src.max_bands );
  assert_int_equal( dst.max_color, src.max_color );
}

/********************************************************************************
 * hton_meter_features() test.
 ********************************************************************************/

void
test_hton_meter_features() {
  struct ofp_meter_features dst;
  struct ofp_meter_features src;

  memset( &src, 0, sizeof( struct ofp_meter_features ) );
  memset( &dst, 0, sizeof( struct ofp_meter_features ) );

  src.max_meter = 1000;
  src.band_types = OFPMBT_DROP;
  src.capabilities = OFPMF_KBPS;
  src.max_bands = 100;
  src.max_color = 10;

  ntoh_meter_features( &dst, &src );

  assert_int_equal( ( int ) dst.max_meter, ( int ) htonl( src.max_meter ) );
  assert_int_equal( ( int ) dst.band_types, ( int ) htonl( src.band_types ) );
  assert_int_equal( ( int ) dst.capabilities, ( int ) htonl( src.capabilities ) );
  assert_int_equal( dst.max_bands, src.max_bands );
  assert_int_equal( dst.max_color, src.max_color );
}



/********************************************************************************
 * Run tests.
 ********************************************************************************/

int
main() {
  // FIXME: mockanize in setup()
  die = mock_die;

  const UnitTest tests[] = {
    unit_test( test_ntoh_port ),
    unit_test( test_ntoh_action_output ),
    unit_test( test_ntoh_action_set_field ),
    unit_test( test_hton_action_set_field ),
    unit_test( test_ntoh_action_set_queue ),
    unit_test( test_ntoh_action_experimenter ),
    unit_test( test_ntoh_action_mpls_ttl ),
    unit_test( test_ntoh_action_push ),
    unit_test( test_ntoh_action_pop_mpls ),
    unit_test( test_ntoh_action_group ),
    unit_test( test_ntoh_action_nw_ttl ),
    unit_test( test_ntoh_action_header ),
    unit_test( test_ntoh_action ),
    unit_test( test_ntoh_action_with_undefined_action_type ),
    unit_test( test_hton_action ),
    unit_test( test_hton_action_with_undefined_action_type ),
    unit_test( test_ntoh_flow_stats ),
    unit_test( test_hton_flow_stats ),
    unit_test( test_ntoh_aggregate_stats ),
    unit_test( test_ntoh_table_stats ),
    unit_test( test_ntoh_port_stats ),
    unit_test( test_ntoh_queue_stats ),
    unit_test( test_ntoh_queue_property_with_OFPQT_MIN_RATE ),
    unit_test( test_ntoh_queue_property_with_OFPQT_MAX_RATE ),
    unit_test( test_ntoh_queue_property_with_OFPQT_EXPERIMENTER ),
    unit_test( test_hton_queue_property_with_OFPQT_MIN_RATE ),
    unit_test( test_hton_queue_property_with_OFPQT_MAX_RATE ),
    unit_test( test_hton_queue_property_with_OFPQT_EXPERIMENTER ),
    unit_test( test_ntoh_packet_queue_with_single_OFPQT_MIN_RATE ),
    unit_test( test_ntoh_packet_queue_with_single_OFPQT_MAX_RATE ),
    unit_test( test_ntoh_packet_queue_with_single_OFPQT_EXPERIMENTER ),
    unit_test( test_ntoh_packet_queue_with_OFPQT_MIN_RATE_and_OFPQT_MAX_RATE ),
    unit_test( test_hton_packet_queue_with_single_OFPQT_MIN_RATE ),
    unit_test( test_hton_packet_queue_with_single_OFPQT_MAX_RATE ),
    unit_test( test_hton_packet_queue_with_OFPQT_MIN_RATE_and_OFPQT_MAX_RATE ),
    unit_test( test_ntoh_instruction_OFPIT_GOTO_TABLE ),
    unit_test( test_ntoh_instruction_OFPIT_WRITE_METADATA ),
    unit_test( test_ntoh_instruction_OFPIT_WRITE_ACTIONS ),
    unit_test( test_ntoh_instruction_OFPIT_APPLY_ACTIONS ),
    unit_test( test_ntoh_instruction_OFPIT_CLEAR_ACTIONS ),
    unit_test( test_ntoh_instruction_OFPIT_METER ),
    unit_test( test_ntoh_instruction_OFPIT_EXPERIMENTER ),
    unit_test( test_ntoh_instruction_unknown_type ),
    unit_test( test_hton_instruction_OFPIT_GOTO_TABLE ),
    unit_test( test_hton_instruction_OFPIT_WRITE_METADATA ),
    unit_test( test_hton_instruction_OFPIT_WRITE_ACTIONS ),
    unit_test( test_hton_instruction_OFPIT_APPLY_ACTIONS ),
    unit_test( test_hton_instruction_OFPIT_CLEAR_ACTIONS ),
    unit_test( test_hton_instruction_OFPIT_METER ),
    unit_test( test_hton_instruction_OFPIT_EXPERIMENTER ),
    unit_test( test_hton_instruction_unknown_type ),
    unit_test( test_ntoh_instruction_goto_table ),
    unit_test( test_hton_instruction_goto_table ),
    unit_test( test_ntoh_instruction_write_metadata ),
    unit_test( test_hton_instruction_write_metadata ),
    unit_test( test_ntoh_instruction_actions ),
    unit_test( test_ntoh_instruction_actions_no_action ),
    unit_test( test_hton_instruction_actions ),
    unit_test( test_hton_instruction_actions_no_action ),
    unit_test( test_ntoh_instruction_meter ),
    unit_test( test_hton_instruction_meter ),
    unit_test( test_ntoh_instruction_experimenter ),
    unit_test( test_ntoh_instruction_experimenter_nodata ),
    unit_test( test_hton_instruction_experimenter ),
    unit_test( test_hton_instruction_experimenter_nodata ),
    unit_test( test_ntoh_bucket ),
    unit_test( test_ntoh_bucket_noaction ),
    unit_test( test_hton_bucket ),
    unit_test( test_hton_bucket_noaction ),
    unit_test( test_ntoh_meter_band_drop ),
    unit_test( test_hton_meter_band_drop ),
    unit_test( test_ntoh_meter_band_dscp_remark ),
    unit_test( test_hton_meter_band_dscp_remark ),
    unit_test( test_ntoh_meter_band_experimenter ),
    unit_test( test_hton_meter_band_experimenter ),
    unit_test( test_ntoh_meter_band_header_OFPMBT_DROP ),
    unit_test( test_ntoh_meter_band_header_OFPMBT_DSCP_REMARK ),
    unit_test( test_ntoh_meter_band_header_OFPMBT_EXPERIMENTER ),
    unit_test( test_ntoh_meter_band_header_unknown_type ),
    unit_test( test_hton_meter_band_header_OFPMBT_DROP ),
    unit_test( test_hton_meter_band_header_OFPMBT_DSCP_REMARK ),
    unit_test( test_hton_meter_band_header_OFPMBT_EXPERIMENTER ),
    unit_test( test_hton_meter_band_header_unknown_type ),
    unit_test( test_ntoh_table_feature_prop_instructions_OFPTFPT_INSTRUCTIONS ),
    unit_test( test_ntoh_table_feature_prop_instructions_OFPTFPT_INSTRUCTIONS_MISS ),
    unit_test( test_hton_table_feature_prop_instructions_OFPTFPT_INSTRUCTIONS ),
    unit_test( test_hton_table_feature_prop_instructions_OFPTFPT_INSTRUCTIONS_MISS ),
    unit_test( test_ntoh_table_feature_prop_next_tables_OFPTFPT_NEXT_TABLES ),
    unit_test( test_ntoh_table_feature_prop_next_tables_OFPTFPT_NEXT_TABLES_MISS ),
    unit_test( test_hton_table_feature_prop_next_tables_OFPTFPT_NEXT_TABLES ),
    unit_test( test_hton_table_feature_prop_next_tables_OFPTFPT_NEXT_TABLES_MISS ),
    unit_test( test_ntoh_table_feature_prop_actions ),
    unit_test( test_ntoh_table_feature_prop_actions_nodata ),
    unit_test( test_hton_table_feature_prop_actions ),
    unit_test( test_hton_table_feature_prop_actions_nodata ),
    unit_test( test_ntoh_table_feature_prop_oxm ),
    unit_test( test_ntoh_table_feature_prop_oxm_nodata ),
    unit_test( test_hton_table_feature_prop_oxm ),
    unit_test( test_hton_table_feature_prop_oxm_nodata ),
    unit_test( test_ntoh_table_feature_prop_experimenter ),
    unit_test( test_ntoh_table_feature_prop_experimenter_nodata ),
    unit_test( test_hton_table_feature_prop_experimenter ),
    unit_test( test_hton_table_feature_prop_experimenter_nodata ),
    unit_test( test_ntoh_table_feature_prop_header_OFPTFPT_INSTRUCTIONS ),
    unit_test( test_ntoh_table_feature_prop_header_OFPTFPT_INSTRUCTIONS_MISS ),
    unit_test( test_ntoh_table_feature_prop_header_OFPTFPT_NEXT_TABLES ),
    unit_test( test_ntoh_table_feature_prop_header_OFPTFPT_NEXT_TABLES_MISS ),
    unit_test( test_ntoh_table_feature_prop_header_OFPTFPT_WRITE_ACTIONS ),
    unit_test( test_ntoh_table_feature_prop_header_OFPTFPT_WRITE_ACTIONS_MISS ),
    unit_test( test_ntoh_table_feature_prop_header_OFPTFPT_APPLY_ACTIONS ),
    unit_test( test_ntoh_table_feature_prop_header_OFPTFPT_APPLY_ACTIONS_MISS ),
    unit_test( test_ntoh_table_feature_prop_header_OFPTFPT_MATCH ),
    unit_test( test_ntoh_table_feature_prop_header_OFPTFPT_WILDCARDS ),
    unit_test( test_ntoh_table_feature_prop_header_OFPTFPT_WRITE_SETFIELD ),
    unit_test( test_ntoh_table_feature_prop_header_OFPTFPT_WRITE_SETFIELD_MISS ),
    unit_test( test_ntoh_table_feature_prop_header_OFPTFPT_APPLY_SETFIELD ),
    unit_test( test_ntoh_table_feature_prop_header_OFPTFPT_APPLY_SETFIELD_MISS ),
    unit_test( test_ntoh_table_feature_prop_header_OFPTFPT_EXPERIMENTER ),
    unit_test( test_ntoh_table_feature_prop_header_OFPTFPT_EXPERIMENTER_MISS ),
    unit_test( test_ntoh_table_feature_prop_header_unknown_type ),
    unit_test( test_hton_table_feature_prop_header_OFPTFPT_INSTRUCTIONS ),
    unit_test( test_hton_table_feature_prop_header_OFPTFPT_INSTRUCTIONS_MISS ),
    unit_test( test_hton_table_feature_prop_header_OFPTFPT_NEXT_TABLES ),
    unit_test( test_hton_table_feature_prop_header_OFPTFPT_NEXT_TABLES_MISS ),
    unit_test( test_hton_table_feature_prop_header_OFPTFPT_WRITE_ACTIONS ),
    unit_test( test_hton_table_feature_prop_header_OFPTFPT_WRITE_ACTIONS_MISS ),
    unit_test( test_hton_table_feature_prop_header_OFPTFPT_APPLY_ACTIONS ),
    unit_test( test_hton_table_feature_prop_header_OFPTFPT_APPLY_ACTIONS_MISS ),
    unit_test( test_hton_table_feature_prop_header_OFPTFPT_MATCH ),
    unit_test( test_hton_table_feature_prop_header_OFPTFPT_WILDCARDS ),
    unit_test( test_hton_table_feature_prop_header_OFPTFPT_WRITE_SETFIELD ),
    unit_test( test_hton_table_feature_prop_header_OFPTFPT_WRITE_SETFIELD_MISS ),
    unit_test( test_hton_table_feature_prop_header_OFPTFPT_APPLY_SETFIELD ),
    unit_test( test_hton_table_feature_prop_header_OFPTFPT_APPLY_SETFIELD_MISS ),
    unit_test( test_hton_table_feature_prop_header_OFPTFPT_EXPERIMENTER ),
    unit_test( test_hton_table_feature_prop_header_OFPTFPT_EXPERIMENTER_MISS ),
    unit_test( test_hton_table_feature_prop_header_unknown_type ),
    unit_test( test_ntoh_table_features ),
    unit_test( test_hton_table_features ),
    unit_test( test_ntoh_bucket_counter ),
    unit_test( test_hton_bucket_counter ),
    unit_test( test_ntoh_group_stats ),
    unit_test( test_ntoh_group_stats_nodata ),
    unit_test( test_hton_group_stats ),
    unit_test( test_hton_group_stats_nodata ),
    unit_test( test_ntoh_group_desc_stats ),
    unit_test( test_ntoh_group_desc_stats_nodata ),
    unit_test( test_hton_group_desc_stats ),
    unit_test( test_hton_group_desc_stats_nodata ),
    unit_test( test_ntoh_group_features_stats ),
    unit_test( test_hton_group_features_stats ),
    unit_test( test_ntoh_meter_band_stats ),
    unit_test( test_hton_meter_band_stats ),
    unit_test( test_ntoh_meter_stats ),
    unit_test( test_ntoh_meter_stats_nodata ),
    unit_test( test_hton_meter_stats ),
    unit_test( test_hton_meter_stats_nodata ),
    unit_test( test_ntoh_meter_config ),
    unit_test( test_ntoh_meter_config_nodata ),
    unit_test( test_hton_meter_config ),
    unit_test( test_hton_meter_config_nodata ),
    unit_test( test_ntoh_meter_features ),
    unit_test( test_hton_meter_features ),
    
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
