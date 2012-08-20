/*
 * Sample OpenFlow event dumper.
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


#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include "trema.h"
#include "checks.h"

//#define DEBUG
#ifdef DEBUG
#define dump(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define dump info
#endif

void
usage() {
  printf(
          "OpenFlow Event Dumper.\n"
          "Usage: %s [OPTION]...\n"
          "\n"
          "  -n, --name=SERVICE_NAME     service name\n"
          "  -d, --daemonize             run in the background\n"
          "  -l, --logging_level=LEVEL   set logging level\n"
          "  -h, --help                  display this help and exit\n"
          , get_executable_name()
        );
}


static void
dump_match( const oxm_matches *match ) {
  char match_string[ MATCH_STRING_LENGTH ];
  memset( match_string, '\0', MATCH_STRING_LENGTH );
  match_to_string( match, match_string, sizeof( match_string ) );
  dump( " match: %s", match_string );
}

static void
dump_ofp_port( const struct ofp_port *ofp_port ) {
  dump( " port_no: %#x", ofp_port->port_no );
  dump( " hw_addr: %02x:%02x:%02x:%02x:%02x:%02x",
        ofp_port->hw_addr[ 0 ], ofp_port->hw_addr[ 1 ], ofp_port->hw_addr[ 2 ],
        ofp_port->hw_addr[ 3 ], ofp_port->hw_addr[ 4 ], ofp_port->hw_addr[ 5 ] );
  dump( " name: %s", ofp_port->name );
  dump( " config: %#x", ofp_port->config );
  dump( " state: %#x", ofp_port->state );
  dump( " curr: %#x", ofp_port->curr );
  dump( " advertised: %#x", ofp_port->advertised );
  dump( " supported: %#x", ofp_port->supported );
  dump( " peer: %#x", ofp_port->peer );
  dump( " curr_speed: %#x", ofp_port->curr_speed );
  dump( " max_speed: %#x", ofp_port->max_speed );
}


static void
dump_packet_queue( const struct ofp_packet_queue *packet_queue ) {
  uint16_t properties_length;
  struct ofp_queue_prop_header *prop_header, *properties_head;
  struct ofp_queue_prop_min_rate *prop_min_rate;
  struct ofp_queue_prop_max_rate *prop_max_rate;
  struct ofp_queue_prop_experimenter *prop_experimenter;

  dump( "queue_id: %#x", packet_queue->queue_id );
  dump( " len: %#x", packet_queue->len );
  dump( " properties:" );

  properties_length =
    ( uint16_t ) ( packet_queue->len -
                   offsetof( struct ofp_packet_queue, properties ) );

  properties_head = ( struct ofp_queue_prop_header * ) xmalloc( properties_length );
  memcpy( properties_head, packet_queue->properties, properties_length );
  prop_header = properties_head;

  while ( properties_length > 0 ) {
    dump( "  property: %#x", prop_header->property );
    dump( "  len: %#x", prop_header->len );

    if ( prop_header->property == OFPQT_MIN_RATE ) {
      prop_min_rate = ( struct ofp_queue_prop_min_rate * ) prop_header;
      dump( "  rate: %#x", prop_min_rate->rate );
    } else if ( prop_header->property == OFPQT_MAX_RATE ) {
      prop_max_rate = ( struct ofp_queue_prop_max_rate * ) prop_header;
      dump( "  rate: %#x", prop_max_rate->rate );
    } else if ( prop_header->property == OFPQT_EXPERIMENTER ) {
      prop_experimenter = ( struct ofp_queue_prop_experimenter * ) prop_header;
      dump( "  experimenter: %#x", prop_experimenter->experimenter );

      uint16_t offset = offsetof( struct ofp_queue_prop_experimenter, data );
      if ( prop_header->len > offset ) {
        uint16_t data_len = ( uint16_t ) ( prop_experimenter->prop_header.len - offset );

        if ( data_len > 0 ) {
          buffer *data = alloc_buffer();
          void *ptr = append_front_buffer( data, data_len );
          memcpy( ptr, prop_experimenter->data, data_len );

          dump( "  data:" );
          dump_buffer( data, dump );
          free_buffer( data );
        }
      }
    }

    properties_length = ( uint16_t ) ( properties_length - prop_header->len );
    prop_header =
      ( struct ofp_queue_prop_header * ) ( ( char * ) prop_header +
                                           prop_header->len );
  }

  xfree( properties_head );
}

static void
dump_meter_stats(
  const struct ofp_meter_band_stats *band_stats,
  uint16_t band_stats_length ) {
  struct ofp_meter_band_stats *meter_band_stats, *meter_band_head;
  int i = 0;

  meter_band_head = ( struct ofp_meter_band_stats * ) xmalloc( band_stats_length );
  memcpy( meter_band_head, band_stats, band_stats_length );
  meter_band_stats = meter_band_head;

  while ( band_stats_length > 0 ) {
    i++;
    dump( " band_stats:%d", i );
    dump( "  packet_band_count: %#" PRIx64, meter_band_stats->packet_band_count );
    dump( "  byte_band_count: %#" PRIx64, meter_band_stats->byte_band_count );

    band_stats_length = ( uint16_t ) ( band_stats_length - sizeof( struct ofp_meter_band_stats ) );
    meter_band_stats =
      ( struct ofp_meter_band_stats * ) ( ( char * ) meter_band_stats + sizeof( struct ofp_meter_band_stats ) );
  }

  xfree( meter_band_head );
}

static void
dump_bucket_counter(
  const struct ofp_bucket_counter *bucket_counter,
  uint16_t bucket_counter_length ) {
  struct ofp_bucket_counter *bucket_counter_stats, *bucket_counter_head;
  int i = 0;

  bucket_counter_head = ( struct ofp_bucket_counter * ) xmalloc( bucket_counter_length );
  memcpy( bucket_counter_head, bucket_counter, bucket_counter_length );
  bucket_counter_stats = bucket_counter_head;

  while ( bucket_counter_length > 0 ) {
    i++;
    dump( " bucket_stats:%d", i );
    dump( "  packet_count: %#" PRIx64, bucket_counter_stats->packet_count );
    dump( "  byte_count: %#" PRIx64, bucket_counter_stats->byte_count );

    bucket_counter_length = ( uint16_t ) ( bucket_counter_length - sizeof( struct ofp_bucket_counter ) );
    bucket_counter_stats =
      ( struct ofp_bucket_counter * ) ( ( char * ) bucket_counter_stats + sizeof( struct ofp_bucket_counter ) );
  }

  xfree( bucket_counter_head );
}

static void
dump_bucket(
  const struct ofp_bucket *bucket,
  uint16_t bucket_length ) {
  struct ofp_bucket *bucket_curr, *bucket_head;
  int i = 0;
  uint16_t act_len = 0;
  char act_str[ 4096 ] = {};

  bucket_head = ( struct ofp_bucket * ) xcalloc( 1, bucket_length );
  memcpy( bucket_head, bucket, bucket_length );
  bucket_curr = bucket_head;

  while ( bucket_length > 0 ) {
    i++;
    dump( " bucket:%d", i );
    dump( "  len: %#x", bucket_curr->len );
    dump( "  weight: %#x", bucket_curr->weight );
    dump( "  watch_port: %#x", bucket_curr->watch_port );
    dump( "  watch_group: %#x", bucket_curr->watch_group );

    act_str[ 0 ] = '\0';
    act_len = ( uint16_t ) ( bucket_curr->len - offsetof( struct ofp_bucket, actions ) );
    if ( act_len > 0 ) {
      actions_to_string( bucket_curr->actions, act_len, act_str, sizeof( act_str ) );
    }

    dump( "  actions: [%s]", act_str );

    bucket_length = ( uint16_t ) ( bucket_length - bucket_curr->len );
    bucket_curr =
      ( struct ofp_bucket * ) ( ( char * ) bucket_curr + bucket_curr->len );
  }

  xfree( bucket_head );
}


static void
handle_switch_ready( uint64_t datapath_id, void *user_data ) {
  UNUSED( user_data );

  dump( "[switch_ready]" );
  dump( "datapath_id: %#" PRIx64, datapath_id );
}

static void
handle_switch_disconnected( uint64_t datapath_id, void *user_data ) {
  UNUSED( user_data );

  dump( "[switch_disconnected]" );
  dump( "datapath_id: %#" PRIx64, datapath_id );
}

static void
handle_error(
  uint64_t datapath_id,
  uint32_t transaction_id,
  uint16_t type,
  uint16_t code,
  const buffer *data,
  void *user_data ) {
  UNUSED( user_data );

  dump( "[error]" );
  dump( " datapath_id: %#" PRIx64, datapath_id );
  dump( " transaction_id: %#x", transaction_id );
  dump( " type: %#x", type );
  dump( " code: %#x", code );
  if ( data != NULL ) {
    dump( " data:" );
    dump_buffer( data, dump );
  }
}

static void
handle_error_experimenter(
  uint64_t datapath_id,
  uint32_t transaction_id,
  uint16_t type,
  uint16_t exp_type,
  uint32_t experimenter,
  const buffer *data,
  void *user_data ) {
  UNUSED( user_data );

  dump( "[error experimenter]" );
  dump( " datapath_id: %#" PRIx64, datapath_id );
  dump( " transaction_id: %#x", transaction_id );
  dump( " type: %#x", type );
  dump( " exp_type: %#x", exp_type );
  dump( " experimenter: %#x", experimenter );
  if ( data != NULL ) {
    dump( " data:" );
    dump_buffer( data, dump );
  }
}

static void
handle_echo_reply(
  uint64_t datapath_id,
  uint32_t transaction_id,
  const buffer *data,
  void *user_data ) {
  UNUSED( user_data );

  dump( "[echo_reply]" );
  dump( " datapath_id: %#" PRIx64, datapath_id );
  dump( " transaction_id: %#x", transaction_id );
  if ( data != NULL ) {
    dump( " data:" );
    dump_buffer( data, dump );
  }
}

static void
handle_experimenter(
  uint64_t datapath_id,
  uint32_t transaction_id,
  uint32_t experimenter,
  uint32_t exp_type,
  const buffer *data,
  void *user_data ) {
  uint16_t body_len;
  UNUSED( user_data );
  struct ofp_experimenter_header *experimenter_header;
  buffer *body;
  
  experimenter_header = ( struct ofp_experimenter_header * ) data->data;
  body_len = ( uint16_t ) ( experimenter_header->header.length - sizeof( struct ofp_experimenter_header ) );
  if ( body_len > 0 ) {
    body = xcalloc( 1, body_len );
    memcpy( body, (char *) experimenter_header + sizeof( struct ofp_experimenter_header ), body_len );
  }
  
  dump( "[experimenter]" );
  dump( " datapath_id: %#" PRIx64, datapath_id );
  dump( " transaction_id: %#x", transaction_id );
  dump( " experimenter: %#x", experimenter );
  dump( " exp_type: %#x", exp_type );
  if ( data != NULL ) {
    dump( " data:" );
    dump_buffer( data, dump );
  }
  if ( 0 < body_len ) {
    xfree( body );
  }
}

static void
handle_features_reply(
  uint64_t datapath_id,
  uint32_t transaction_id,
  uint32_t n_buffers,
  uint8_t n_tables,
  uint8_t auxiliary_id,
  uint32_t capabilities,
  uint32_t reserved,
  void *user_data ) {
  UNUSED( user_data );

  dump( "[features_reply]" );
  dump( " datapath_id: %#" PRIx64, datapath_id );
  dump( " transaction_id: %#x", transaction_id );
  dump( " n_buffers: %#x", n_buffers );
  dump( " n_tables: %#x", n_tables );
  dump( " auxiliary_id: %#x", auxiliary_id );
  dump( " capabilities: %#x", capabilities );
  dump( " reserved: %#x", reserved );
}


static void
handle_get_config_reply(
  uint64_t datapath_id,
  uint32_t transaction_id,
  uint16_t flags,
  uint16_t miss_send_len,
  void *user_data ) {
  UNUSED( user_data );

  dump( "[get_config_reply]" );
  dump( " datapath_id: %#" PRIx64, datapath_id );
  dump( " transaction_id: %#x", transaction_id );
  dump( " flags: %#x", flags );
  dump( " miss_send_len: %#x", miss_send_len );
}


static void
handle_packet_in(
  uint64_t datapath_id,
  packet_in message ) {

  dump( "[packet_in]" );
  dump( " datapath_id: %#" PRIx64, datapath_id );
  dump( " transaction_id: %#x", message.transaction_id );
  dump( " buffer_id: %#x", message.buffer_id );
  dump( " total_len: %#x", message.total_len );
  dump( " reason: %#x", message.reason );
  dump( " table_id: %#x", message.table_id );
  dump( " cookie: %#" PRIx64, message.cookie );
  dump_match( message.match );
  if ( message.data ) {
    dump( " data:" );
    dump_buffer( message.data, dump );
  }
}


static void
handle_flow_removed(
  uint64_t datapath_id,
  flow_removed message ) {

  dump( "[flow_removed]" );
  dump( " datapath_id: %#" PRIx64, datapath_id );
  dump( " cookie: %#" PRIx64, message.cookie );
  dump( " priority: %#x", message.priority );
  dump( " reason: %#x", message.reason );
  dump( " table_id: %#x", message.table_id );
  dump( " duration_sec: %#x", message.duration_sec );
  dump( " duration_nsec: %#x", message.duration_nsec );
  dump( " idle_timeout: %#x", message.idle_timeout );
  dump( " hard_timeout: %#x", message.hard_timeout );
  dump( " packet_count: %#" PRIx64, message.packet_count );
  dump( " byte_count: %#" PRIx64, message.byte_count );
  dump_match( message.match );
}


static void
handle_port_status(
  uint64_t datapath_id,
  uint32_t transaction_id,
  uint8_t reason,
  struct ofp_port desc,
  void *user_data ) {
  UNUSED( user_data );

  dump( "[port_status]" );
  dump( " datapath_id: %#" PRIx64, datapath_id );
  dump( " transaction_id: %#x", transaction_id );
  dump( " reason: %#x", reason );
  dump_ofp_port( &desc );
}

static void
handle_multipart_reply_desc(
  struct ofp_desc *data ) {
  dump( "[multipart_reply_desc]" );
  dump( " mfr_desc: %s", data->mfr_desc );
  dump( " hw_desc: %s", data->hw_desc );
  dump( " sw_desc: %s", data->sw_desc );
  dump( " serial_num: %s", data->serial_num );
  dump( " dp_desc: %s", data->dp_desc );
}

static void
handle_multipart_reply_flow(
  struct ofp_flow_stats *data,
  uint16_t body_length
) {
  struct ofp_flow_stats *stats = data;
  uint16_t rest_length = body_length;
  uint16_t match_len = 0;
  uint16_t match_pad_len = 0;
  uint16_t inst_len = 0;
  struct ofp_instruction *inst;
  int i = 0;
  char inst_str[ 4096 ];
  struct ofp_match *tmp_match;
  oxm_matches *tmp_matches;
  char match_str[ MATCH_STRING_LENGTH ];

  while ( rest_length >= sizeof( struct ofp_flow_stats ) ) {
    struct ofp_flow_stats *next;
    next = ( struct ofp_flow_stats * ) ( ( char * ) stats + stats->length );

    i++;
    dump( "[multipart_reply_flow:%d]", i );
    dump( " length: %#x", stats->length );
    dump( " table_id: %#x", stats->table_id );
    dump( " duration_sec: %#x", stats->duration_sec );
    dump( " duration_nsec: %#x", stats->duration_nsec );
    dump( " priority: %#x", stats->priority );
    dump( " idle_timeout: %#x", stats->idle_timeout );
    dump( " hard_timeout: %#x", stats->hard_timeout );
    dump( " flags: %#x", stats->flags );
    dump( " cookie: %#" PRIx64, stats->cookie );
    dump( " packet_count: %#" PRIx64, stats->packet_count );
    dump( " byte_count: %#" PRIx64, stats->byte_count );
    match_len = stats->match.length;
    match_pad_len = ( uint16_t ) ( match_len + PADLEN_TO_64( match_len ) );
    {
      tmp_match = xcalloc( 1, match_pad_len );
      hton_match( tmp_match, &stats->match );
      tmp_matches = parse_ofp_match( tmp_match );
      match_to_string( tmp_matches, match_str, sizeof( match_str ) );
      xfree( tmp_match );
      delete_oxm_matches( tmp_matches );
    }
    dump( " match: [%s]", match_str );
    if ( stats->length > ( offsetof( struct ofp_flow_stats, match ) + match_pad_len ) ) {
      inst_len = ( uint16_t ) ( stats->length - ( offsetof( struct ofp_flow_stats, match ) + match_pad_len ) );
      inst = ( struct ofp_instruction * ) ( ( char * ) stats + offsetof( struct ofp_flow_stats, match ) + match_pad_len );
      instructions_to_string( inst, inst_len, inst_str, sizeof( inst_str ) );
      dump( " instructions: [%s]", inst_str );
    }

    rest_length = ( uint16_t ) ( rest_length - stats->length );
    stats = next;
  }
}

static void
handle_multipart_reply_aggregate(
  struct ofp_aggregate_stats_reply *data
) {
  dump( "[multipart_aggregate]" );
  dump( " packet_count: %#" PRIx64, data->packet_count );
  dump( " byte_count: %#" PRIx64, data->byte_count );
  dump( " flow_count: %#x", data->flow_count );
}

static void
handle_multipart_reply_table(
  struct ofp_table_stats *data,
  uint16_t body_length
) {
  struct ofp_table_stats *stats = data;
  uint16_t rest_length = body_length;
  uint16_t i = 0;

  while ( rest_length >= sizeof( struct ofp_table_stats ) ) {
    struct ofp_table_stats *next;
    next = ( struct ofp_table_stats * ) ( ( char * ) stats + sizeof( struct ofp_table_stats ) );
    
    i++;
    dump( "[multipart_reply_table:%d]", i );
    dump( " table_id: %#x", stats->table_id );
    dump( " active_count: %#x", stats->active_count );
    dump( " lookup_count: %#" PRIx64, stats->lookup_count );
    dump( " matched_count: %#" PRIx64, stats->matched_count );
    
    rest_length = ( uint16_t ) ( rest_length - ( uint16_t ) sizeof( struct ofp_table_stats ) );
    stats = next;
  }
}

static void
handle_multipart_reply_port_stats(
  struct ofp_port_stats *data,
  uint16_t body_length
) {
  struct ofp_port_stats *stats = data;
  uint16_t rest_length = body_length;
  uint16_t i = 0;

  while ( rest_length >= sizeof( struct ofp_port_stats ) ) {
    struct ofp_port_stats *next;
    next = ( struct ofp_port_stats * ) ( ( char * ) stats + sizeof( struct ofp_port_stats ) );
    
    i++;
    dump( "[multipart_reply_port_stats:%d]", i);
    dump( " port_no: %#x", stats->port_no );
    dump( " rx_packets: %#" PRIx64, stats->rx_packets );
    dump( " tx_packets: %#" PRIx64, stats->tx_packets );
    dump( " rx_bytes: %#" PRIx64, stats->rx_bytes );
    dump( " tx_bytes: %#" PRIx64, stats->tx_bytes );
    dump( " rx_dropped: %#" PRIx64, stats->rx_dropped );
    dump( " tx_dropped: %#" PRIx64, stats->tx_dropped );
    dump( " rx_errors: %#" PRIx64, stats->rx_errors );
    dump( " tx_errors: %#" PRIx64, stats->tx_errors );
    dump( " rx_frame_err: %#" PRIx64, stats->rx_frame_err );
    dump( " rx_over_err: %#" PRIx64, stats->rx_over_err );
    dump( " rx_crc_err: %#" PRIx64, stats->rx_crc_err );
    dump( " collisions: %#" PRIx64, stats->collisions );
    dump( " duration_sec: %#x", stats->duration_sec );
    dump( " duration_nsec: %#x", stats->duration_nsec );
    
    rest_length = ( uint16_t ) ( rest_length - ( uint16_t ) sizeof( struct ofp_port_stats ) );
    stats = next;
  }
}

static void
handle_multipart_reply_queue_stats(
  struct ofp_queue_stats *data,
  uint16_t body_length
) {
  struct ofp_queue_stats *stats = data;
  uint16_t rest_length = body_length;
  uint16_t i = 0;

  while ( rest_length >= sizeof( struct ofp_queue_stats ) ) {
    struct ofp_queue_stats *next;
    next = ( struct ofp_queue_stats * ) ( ( char * ) stats + sizeof( struct ofp_queue_stats ) );
    
    i++;
    dump( "[multipart_reply_queue_stats:%d]", i );
    dump( " port_no: %#x", stats->port_no );
    dump( " queue_id: %#x", stats->queue_id );
    dump( " tx_bytes: %#" PRIx64, stats->tx_bytes );
    dump( " tx_packets: %#" PRIx64, stats->tx_packets );
    dump( " tx_errors: %#" PRIx64, stats->tx_errors );
    dump( " duration_sec: %#x", stats->duration_sec );
    dump( " duration_nsec: %#x", stats->duration_nsec );
    
    rest_length = ( uint16_t ) ( rest_length - ( uint16_t ) sizeof( struct ofp_queue_stats ) );
    stats = next;
  }
}

static void
handle_multipart_reply_group_stats(
  struct ofp_group_stats *data,
  uint16_t body_length
) {
  struct ofp_group_stats *stats = data;
  uint16_t rest_length = body_length;
  uint16_t i = 0;

  while ( rest_length >= sizeof( struct ofp_group_stats ) ) {
    struct ofp_group_stats *next;
    next = ( struct ofp_group_stats * ) ( ( char * ) stats + stats->length );
    
    i++;
    dump( "[multipart_reply_group_stats:%d]", i );
    dump( " length: %#x", stats->length );
    dump( " group_id: %#x", stats->group_id );
    dump( " ref_count: %#x", stats->ref_count );
    dump( " packet_count: %#" PRIx64, stats->packet_count );
    dump( " byte_count: %#" PRIx64, stats->byte_count );
    dump( " duration_sec: %#x", stats->duration_sec );
    dump( " duration_nsec: %#x", stats->duration_nsec );
    uint16_t data_length = 
    ( uint16_t ) ( stats->length - offsetof( struct ofp_group_stats, bucket_stats ) );
    dump_bucket_counter( stats->bucket_stats, data_length );
    
    rest_length = ( uint16_t ) ( rest_length - stats->length );
    stats = next;
  }
}

static void
handle_multipart_reply_group_desc(
  struct ofp_group_desc_stats *data,
  uint16_t body_length
) {
  struct ofp_group_desc_stats *stats = data;
  uint16_t rest_length = body_length;
  uint16_t i = 0;

  while ( rest_length >= sizeof( struct ofp_group_desc_stats ) ) {
    struct ofp_group_desc_stats *next;
    next = ( struct ofp_group_desc_stats * ) ( ( char * ) stats + stats->length );
    
    i++;
    dump( "[multipart_reply_group_desc:%d]", i );
    dump( " length: %#x", stats->length );
    dump( " type: %#x", stats->type );
    dump( " group_id: %#x", stats->group_id );
    uint16_t data_length = 
    ( uint16_t ) ( stats->length - offsetof( struct ofp_group_desc_stats, buckets ) );
    dump_bucket( stats->buckets, data_length );
    
    rest_length = ( uint16_t ) ( rest_length - stats->length );
    stats = next;
  }
}

static void
handle_multipart_reply_group_features(
  struct ofp_group_features *data
) {
  dump( "[multipart_reply_group_features]" );
  dump( " types: %#x", data->types );
  dump( " capabilities: %#x", data->capabilities );
  dump( " max_groups: %#x, %#x, %#x, %#x", data->max_groups[0], data->max_groups[1], data->max_groups[2], data->max_groups[3] );
  dump( " actions: %#x, %#x, %#x, %#x", data->actions[0], data->actions[1], data->actions[2], data->actions[3] );
}

static void
handle_multipart_reply_meter_stats(
  struct ofp_meter_stats *data,
  uint16_t body_length
) {
  struct ofp_meter_stats *stats = data;
  uint16_t rest_length = body_length;
  uint16_t i = 0;

  while ( rest_length >= sizeof( struct ofp_meter_stats ) ) {
    struct ofp_meter_stats *next;
    next = ( struct ofp_meter_stats * ) ( ( char * ) stats + stats->len );
    
    i++;
    dump( "[multipart_reply_meter_stats:%d]", i );
    dump( " meter_id: %#x", stats->meter_id );
    dump( " len: %#x", stats->len );
    dump( " flow_count: %#x", stats->flow_count );
    dump( " packet_in_count: %#" PRIx64, stats->packet_in_count );
    dump( " byte_in_count: %#" PRIx64, stats->byte_in_count );
    dump( " duration_sec: %#x", stats->duration_sec );
    dump( " duration_nsec: %#x", stats->duration_nsec );
    uint16_t data_length = 
    ( uint16_t ) ( stats->len - offsetof( struct ofp_meter_stats, band_stats ) );
    dump_meter_stats( stats->band_stats, data_length );
    
    rest_length = ( uint16_t ) ( rest_length - stats->len );
    stats = next;
  }
}

static void
handle_multipart_reply_meter_config(
  struct ofp_meter_config *data,
  uint16_t body_length
) {
  struct ofp_meter_config *stats = data;
  uint16_t rest_length = body_length;
  
  uint16_t i = 0;
  uint16_t bands_len = 0;
  uint16_t bands_num = 0;

  while ( rest_length > 0 ) {
    if ( rest_length < stats->length ) {
      break;
    }
    struct ofp_meter_config *next;
    next = ( struct ofp_meter_config * ) ( ( char * ) stats + stats->length );
    
    i++;
    dump( "[multipart_reply_meter_config:%d]", i );
    dump( " length: %#x", stats->length );
    dump( " flags: %#x", stats->flags );
    dump( " meter_id: %#x", stats->meter_id );

    if ( stats->length > offsetof( struct ofp_meter_config, bands ) ) {
      bands_num = 0;
      bands_len = ( uint16_t ) ( stats->length - offsetof( struct ofp_meter_config, bands ) );
      struct ofp_meter_band_header *mtbnd = stats->bands;
      while ( bands_len > 0 ) {
        if ( bands_len < mtbnd->len ) {
          break;
        }
        dump( " bands:%d", ++bands_num );
        dump( "  type: %#x", mtbnd->type );
        dump( "  len: %#x", mtbnd->len );
        dump( "  rate: %#x", mtbnd->rate );
        dump( "  burst_size: %#x", mtbnd->burst_size );

        if ( mtbnd->type == OFPMBT_DSCP_REMARK ) {
          struct ofp_meter_band_dscp_remark *dscp = ( struct ofp_meter_band_dscp_remark * ) mtbnd;
          dump( "  prec_level: %#x", dscp->prec_level );
        } else if ( mtbnd->type == OFPMBT_EXPERIMENTER ) {
          struct ofp_meter_band_experimenter *exp = ( struct ofp_meter_band_experimenter * ) mtbnd;
          dump( "  experimenter: %#x", exp->experimenter );
        }

        bands_len = ( uint16_t ) ( bands_len - mtbnd->len );
        mtbnd = ( struct ofp_meter_band_header * ) ( ( char * ) mtbnd + mtbnd->len );
      }
    }

    rest_length = ( uint16_t ) ( rest_length - stats->length );
    stats = next;
  }
}

static void
handle_multipart_reply_meter_features(
  struct ofp_meter_features *data
) {
  dump( "[multipart_reply_meter_features]" );
  dump( " max_meter: %#x", data->max_meter );
  dump( " band_types: %#x", data->band_types );
  dump( " capabilities: %#x", data->capabilities );
  dump( " max_bands: %#x", data->max_bands );
  dump( " max_color: %#x", data->max_color );
}


static void
dump_table_feature_prop(
  struct ofp_table_feature_prop_header *props,
  uint16_t prop_len
) {
  struct ofp_table_feature_prop_header *prop_curr;
  uint16_t rest_len = prop_len;
  uint16_t part_len = 0;
  char act_str[ 4096 ] = {};
  char inst_str[ 4096 ] = {};

  prop_curr = props;
  while ( rest_len > sizeof( struct ofp_table_feature_prop_header ) ) {
    if ( rest_len < prop_curr->length ) {
      break;
    }

    switch ( prop_curr->type ) {
    case OFPTFPT_INSTRUCTIONS:
    case OFPTFPT_INSTRUCTIONS_MISS:
      {
        struct ofp_table_feature_prop_instructions *prop = ( struct ofp_table_feature_prop_instructions * ) prop_curr;
        dump( " prop_instructions:");
        dump( "  type: %#x", prop->type );
        dump( "  length: %#x", prop->length );
        uint16_t inst_len = ( uint16_t ) ( prop->length - sizeof( struct ofp_table_feature_prop_instructions ) );
        if ( inst_len > 0 ) {
          inst_str[ 0 ] = '\0';
          struct ofp_instruction *inst = ( struct ofp_instruction * ) ( ( char * ) prop + sizeof( struct ofp_table_feature_prop_instructions ) );
          instructions_to_string( inst, inst_len, inst_str, sizeof( inst_str ) );
          dump( "  instructions_ids: [%s]", inst_str );
        }
      }
      break;
    case OFPTFPT_NEXT_TABLES:
    case OFPTFPT_NEXT_TABLES_MISS:
      {
        struct ofp_table_feature_prop_next_tables *prop = ( struct ofp_table_feature_prop_next_tables * ) prop_curr;
        dump( " prop_next_tables:");
        dump( "  type: %#x", prop->type );
        dump( "  length: %#x", prop->length );
        uint16_t next_table_len = ( uint16_t ) ( prop->length - sizeof( struct ofp_table_feature_prop_next_tables ) );
        if ( next_table_len > 0 ) {
          for ( uint16_t i = 0; i < next_table_len; i++ ) {
            dump( "  next_table_ids[%u]: %#x", i, prop->next_table_ids[i] );
          }
        }
      }
      break;
    case OFPTFPT_WRITE_ACTIONS:
    case OFPTFPT_WRITE_ACTIONS_MISS:
    case OFPTFPT_APPLY_ACTIONS:
    case OFPTFPT_APPLY_ACTIONS_MISS:
      {
        struct ofp_table_feature_prop_actions *prop = ( struct ofp_table_feature_prop_actions * ) prop_curr;
        dump( " prop_actions:");
        dump( "  type: %#x", prop->type );
        dump( "  length: %#x", prop->length );
        uint16_t act_len = ( uint16_t ) ( prop->length - sizeof( struct ofp_table_feature_prop_actions ) );
        if ( act_len > 0 ) {
          act_str[ 0 ] = '\0';
          struct ofp_action_header *act = ( struct ofp_action_header * ) ( ( char * ) prop + sizeof( struct ofp_table_feature_prop_actions ) );
          actions_to_string( act, act_len, act_str, sizeof( act_str ) );
          dump( "  actions_ids: [%s]", act_str );
        }
      }
      break;
    case OFPTFPT_MATCH:
    case OFPTFPT_WILDCARDS:
    case OFPTFPT_WRITE_SETFIELD:
    case OFPTFPT_WRITE_SETFIELD_MISS:
    case OFPTFPT_APPLY_SETFIELD:
    case OFPTFPT_APPLY_SETFIELD_MISS:
      {
        struct ofp_table_feature_prop_oxm *prop = ( struct ofp_table_feature_prop_oxm * ) prop_curr;
        dump( " prop_oxm:");
        dump( "  type: %#x", prop->type );
        dump( "  length: %#x", prop->length );
        uint16_t oxm_ids_len = ( uint16_t ) ( ( prop->length - sizeof( struct ofp_table_feature_prop_oxm ) ) / sizeof( uint32_t ) );
        if ( oxm_ids_len > 0 ) {
          for ( uint16_t i = 0; i < oxm_ids_len; i++ ) {
            dump( "  oxm_ids[%u]: %#x", i, prop->oxm_ids[i] );
          }
        }
      }
      break;
    case OFPTFPT_EXPERIMENTER:
    case OFPTFPT_EXPERIMENTER_MISS:
      {
        struct ofp_table_feature_prop_experimenter *prop = ( struct ofp_table_feature_prop_experimenter * ) prop_curr;
        dump( " prop_experimenter:");
        dump( "  type: %#x", prop->type );
        dump( "  length: %#x", prop->length );
        dump( "  experimenter: %#x", prop->experimenter );
        dump( "  exp_type: %#x", prop->exp_type );
      }
      break;
    default:
      break;
    }

    part_len = ( uint16_t ) ( prop_curr->length + PADLEN_TO_64( prop_curr->length ) );
    rest_len = ( uint16_t ) ( rest_len - part_len );
    prop_curr = ( struct ofp_table_feature_prop_header * ) ( ( char * ) prop_curr + part_len );
  }
}


static void
handle_multipart_reply_table_features(
  struct ofp_table_features *data,
  uint16_t body_length
) {
  struct ofp_table_features *stats = data;
  uint16_t rest_length = body_length;
  uint16_t i = 0;
  uint16_t prop_len = 0;
  struct ofp_table_feature_prop_header *prop;

  while ( rest_length >= sizeof( struct ofp_table_features ) ) {
    struct ofp_table_features *next;
    next = ( struct ofp_table_features * ) ( ( char * ) stats + stats->length );
    
    i++;
    dump( "[multipart_reply_table_features:%d]", i );
    dump( " length: %#x", stats->length );
    dump( " table_id: %#x", stats->table_id );
    dump( " name: %s", stats->name );
    dump( " metadata_match: %#" PRIx64, stats->metadata_match );
    dump( " metadata_write: %#" PRIx64, stats->metadata_write );
    dump( " config: %#x", stats->config );
    dump( " max_entries: %#x", stats->max_entries );
    prop_len = ( uint16_t ) ( stats->length - sizeof( struct ofp_table_features ) );
    if ( prop_len > 0 ) {
      prop = ( struct ofp_table_feature_prop_header * ) ( ( char * ) stats + sizeof( struct ofp_table_features ) );
      dump_table_feature_prop( prop, prop_len );
    }

    rest_length = ( uint16_t ) ( rest_length - stats->length );
    stats = next;
  }
}

static void
handle_multipart_reply_port_desc(
  struct ofp_port *data,
  uint16_t body_length
) {
  struct ofp_port *stats = data;
  uint16_t rest_length = body_length;
  uint16_t i = 0;

  while ( rest_length >= sizeof( struct ofp_port ) ) {
    struct ofp_port *next;
    next = ( struct ofp_port * ) ( ( char * ) stats + sizeof( struct ofp_port ) );

    i++;
    dump( "[multipart_reply_port_desc:%d]", i );
    dump_ofp_port( stats );

    rest_length = ( uint16_t ) ( rest_length - ( uint16_t ) sizeof( struct ofp_port ) );
    stats = next;
  }
}

static void
handle_multipart_reply_experimenter(
  struct ofp_experimenter_multipart_header *data,
  uint16_t body_length
) {
  void *b;
  uint16_t data_len = ( uint16_t ) ( body_length - ( uint16_t ) sizeof( struct ofp_experimenter_multipart_header ) );
  dump( "[multipart_reply_experimenter]" );
  dump( " experimenter: %#x", data->experimenter );
  dump( " exp_type: %#x", data->exp_type );
  if ( data_len > 0 ) {
    b = ( void * ) ( ( char * ) data + sizeof( struct ofp_experimenter_multipart_header ) );
    buffer *payload = alloc_buffer();
    void *ptr = append_front_buffer( payload, data_len );
    memcpy( ptr, b, data_len );

    dump( " data:" );
    dump_buffer( payload, dump );

    free_buffer( payload );
  }
}

static void
handle_multipart_reply(
  uint64_t datapath_id,
  uint32_t transaction_id,
  uint16_t type,
  uint16_t flags,
  const buffer *data,
  void *user_data ) {
  UNUSED( user_data );
  buffer *body = NULL;
  void *multipart_data = NULL;
  uint16_t body_length = 0;

  dump( "[multipart_reply]" );
  dump( " datapath_id: %#" PRIx64, datapath_id );
  dump( " transaction_id: %#x", transaction_id );
  dump( " type: %#x", type );
  dump( " flags: %#x", flags );

  if ( data != NULL ) {
    body = duplicate_buffer( data );
    multipart_data = body->data;
    body_length = ( uint16_t ) body->length;
  }

  if ( body != NULL ) {
    switch( type ) {
    case OFPMP_DESC:
      handle_multipart_reply_desc( (struct ofp_desc *) multipart_data );
      break;
    case OFPMP_FLOW:
      handle_multipart_reply_flow( (struct ofp_flow_stats *) multipart_data, body_length );
      break;
    case OFPMP_AGGREGATE:
      handle_multipart_reply_aggregate( (struct ofp_aggregate_stats_reply *) multipart_data );
      break;
    case OFPMP_TABLE:
      handle_multipart_reply_table( (struct ofp_table_stats *) multipart_data, body_length );
      break;
    case OFPMP_PORT_STATS:
      handle_multipart_reply_port_stats( (struct ofp_port_stats *) multipart_data, body_length );
      break;
    case OFPMP_QUEUE:
      handle_multipart_reply_queue_stats( (struct ofp_queue_stats *) multipart_data, body_length );
      break;
    case OFPMP_GROUP:
      handle_multipart_reply_group_stats( (struct ofp_group_stats *) multipart_data, body_length );
      break;
    case OFPMP_GROUP_DESC:
      handle_multipart_reply_group_desc( (struct ofp_group_desc_stats *) multipart_data, body_length );
      break;
    case OFPMP_GROUP_FEATURES:
      handle_multipart_reply_group_features( (struct ofp_group_features *) multipart_data );
      break;
    case OFPMP_METER:
      handle_multipart_reply_meter_stats( (struct ofp_meter_stats *) multipart_data, body_length );
      break;
    case OFPMP_METER_CONFIG:
      handle_multipart_reply_meter_config( (struct ofp_meter_config *) multipart_data, body_length );
      break;
    case OFPMP_METER_FEATURES:
      handle_multipart_reply_meter_features( (struct ofp_meter_features *) multipart_data );
      break;
    case OFPMP_TABLE_FEATURES:
      handle_multipart_reply_table_features( (struct ofp_table_features *) multipart_data, body_length );
      break;
    case OFPMP_PORT_DESC:
      handle_multipart_reply_port_desc( (struct ofp_port *) multipart_data, body_length );
      break;
    case OFPMP_EXPERIMENTER:
      handle_multipart_reply_experimenter( (struct ofp_experimenter_multipart_header *) multipart_data, body_length );
      break;
    default:
      dump( "body::unknown type" );
      break;
    }
  }

  if ( body != NULL ) {
    free_buffer( body );
  }
}


static void
handle_barrier_reply(
  uint64_t datapath_id,
  uint32_t transaction_id,
  void *user_data ) {
  UNUSED( user_data );

  dump( "[barrier_reply]" );
  dump( " datapath_id: %#" PRIx64, datapath_id );
  dump( " transaction_id: %#x", transaction_id );
}

static void
handle_queue_get_config_reply(
  uint64_t datapath_id,
  uint32_t transaction_id,
  uint32_t port,
  const list_element *queues,
  void *user_data ) {
  UNUSED( user_data );

  dump( "[queue_get_config_reply]" );
  dump( " datapath_id: %#" PRIx64, datapath_id );
  dump( " traqnsaction_id: %#x", transaction_id );
  dump( " port: %#x", port );

  list_element *queues_head, *element;
  struct ofp_packet_queue *packet_queue;

  queues_head = ( list_element * ) xmalloc( sizeof( list_element ) );
  memcpy( queues_head, queues, sizeof( list_element ) );

  element = queues_head;
  while ( element != NULL ) {
    packet_queue = ( struct ofp_packet_queue * ) element->data;

    dump_packet_queue( packet_queue );

    element = element->next;
  }

  xfree( queues_head );
}

static void
handle_role_reply(
  uint64_t datapath_id,
  uint32_t transaction_id,
  uint32_t role,
  uint64_t generation_id,
  void *user_data ) {
  UNUSED( user_data );

  dump( "[role_reply]" );
  dump( " datapath_id: %#" PRIx64, datapath_id );
  dump( " transaction_id: %#x", transaction_id );
  dump( " role: %#x", role );
  dump( " generation_id: %#" PRIx64, generation_id );
}


static void
handle_get_async_reply(
  uint64_t datapath_id,
  uint32_t transaction_id,
  uint32_t packet_in_mask[2],
  uint32_t port_status_mask[2],
  uint32_t flow_removed_mask[2],
  void *user_data ) {
  UNUSED( user_data );

  dump( "[get_async_reply]" );
  dump( " datapath_id: %#" PRIx64, datapath_id );
  dump( " transaction_id: %#x", transaction_id );
  dump( " packet_in_mask[1]: %#x", packet_in_mask[0] );
  dump( " packet_in_mask[2]: %#x", packet_in_mask[1] );
  dump( " port_status_mask[1]: %#x", port_status_mask[0] );
  dump( " port_status_mask[2]: %#x", port_status_mask[1] );
  dump( " flow_removed_mask[1]: %#x", flow_removed_mask[0] );
  dump( " flow_removed_mask[2]: %#x", flow_removed_mask[1] );
}

int
main( int argc, char *argv[] ) {
  // Initialize the Trema world
  init_trema( &argc, &argv );

  // Set event handlers
  set_switch_ready_handler( handle_switch_ready, NULL );
  set_switch_disconnected_handler( handle_switch_disconnected, NULL );
  set_error_handler( handle_error, NULL );
  set_experimenter_error_handler( handle_error_experimenter, NULL );
  set_echo_reply_handler( handle_echo_reply, NULL );
  set_experimenter_handler( handle_experimenter, NULL );
  set_features_reply_handler( handle_features_reply, NULL );
  set_get_config_reply_handler( handle_get_config_reply, NULL );
  set_packet_in_handler( handle_packet_in, NULL );
  set_flow_removed_handler( handle_flow_removed, NULL );
  set_port_status_handler( handle_port_status, NULL );
  set_multipart_reply_handler( handle_multipart_reply, NULL );
  set_barrier_reply_handler( handle_barrier_reply, NULL );
  set_queue_get_config_reply_handler( handle_queue_get_config_reply, NULL );
  set_role_reply_handler( handle_role_reply, NULL );
  set_get_async_reply_handler( handle_get_async_reply, NULL );

  // Main loop
  start_trema();

  return 0;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
