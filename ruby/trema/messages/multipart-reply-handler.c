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
#include "unpack-util.h"


static const char *table_feature_prop_type_name[] = {
  "instructions",
  "instructions_miss",
  "next_tables",
  "next_tables_miss",
  "write_actions",
  "write_actions_miss",
  "apply_actions",
  "apply_actions_miss",
  "match",
  "",
  "wildcards",
  "",
  "write_setfield",
  "write_setfield_miss",
  "apply_setfield",
  "apply_setfield_miss"
};


static void
unpack_flow_multipart_reply( VALUE r_attributes, void *data ) {
  assert( data );
  const struct ofp_flow_stats *flow_stats = data;

  HASH_SET( r_attributes, "length", UINT2NUM( flow_stats->length ) );
  HASH_SET( r_attributes, "table_id", UINT2NUM( flow_stats->table_id ) );
  HASH_SET( r_attributes, "duration_sec", UINT2NUM( flow_stats->duration_sec ) );
  HASH_SET( r_attributes, "duration_nsec", UINT2NUM( flow_stats->duration_nsec ) );
  HASH_SET( r_attributes, "priority", UINT2NUM( flow_stats->priority ) );
  HASH_SET( r_attributes, "idle_timeout", UINT2NUM( flow_stats->idle_timeout ) );
  HASH_SET( r_attributes, "hard_timeout", UINT2NUM( flow_stats->hard_timeout ) );
  HASH_SET( r_attributes, "flags", UINT2NUM( flow_stats->flags ) );
  HASH_SET( r_attributes, "cookie", ULL2NUM( flow_stats->cookie ) );
  HASH_SET( r_attributes, "packet_count", ULL2NUM( flow_stats->packet_count ) );
  HASH_SET( r_attributes, "byte_count", ULL2NUM( flow_stats->byte_count ) );
  VALUE r_match = ofp_match_to_r_match( &flow_stats->match );
  if ( !NIL_P( r_match ) ) {
    HASH_SET( r_attributes, "match", r_match );
  }
  uint16_t match_length = ( uint16_t ) ( flow_stats->match.length + PADLEN_TO_64( flow_stats->match.length ) );
  size_t offset = offsetof( struct ofp_flow_stats, match ) + match_length;
  size_t instructions_length = flow_stats->length - offset;

  VALUE r_instruction_ary = rb_ary_new();
  while ( instructions_length > sizeof( struct ofp_instruction ) ) {
    const struct ofp_instruction *inst_src = ( const struct ofp_instruction * ) ( ( const char * ) flow_stats + offset );

    uint16_t part_length = inst_src->len;
    if ( instructions_length < part_length ) {
      break;
    }
    unpack_instruction( inst_src, r_instruction_ary );

    instructions_length -= part_length;
    offset += part_length;
  }
  if ( RARRAY_LEN( r_instruction_ary ) ) {
    HASH_SET( r_attributes, "instructions", r_instruction_ary );
  }
}


static void
unpack_desc_multipart_reply( VALUE r_attributes, void *data ) {
  assert( data );
  const struct ofp_desc *desc_stats = data;

  if ( strlen( desc_stats->mfr_desc ) ) {
    HASH_SET( r_attributes, "mfr_desc", rb_str_new2( desc_stats->mfr_desc ) );
  }
  if ( strlen( desc_stats->hw_desc ) ) {
    HASH_SET( r_attributes, "hw_desc", rb_str_new2( desc_stats->hw_desc ) );
  }
  if ( strlen( desc_stats->sw_desc ) ) {
    HASH_SET( r_attributes, "sw_desc", rb_str_new2( desc_stats->sw_desc ) );
  }
  if ( strlen( desc_stats->serial_num ) ) {
    HASH_SET( r_attributes, "serial_num", rb_str_new2( desc_stats->serial_num ) );
  }
  if ( strlen( desc_stats->dp_desc ) ) {
    HASH_SET( r_attributes, "dp_desc", rb_str_new2( desc_stats->dp_desc ) );
  }
} 


static void
unpack_aggregate_multipart_reply( VALUE r_attributes, void *data ) {
  assert( data );
  const struct ofp_aggregate_stats_reply *aggregate_stats = data;

  HASH_SET( r_attributes, "packet_count", ULL2NUM( aggregate_stats->packet_count ) );
  HASH_SET( r_attributes, "byte_count", ULL2NUM( aggregate_stats->byte_count ) );
  HASH_SET( r_attributes, "flow_count", UINT2NUM( aggregate_stats->flow_count ) );
}


static void
unpack_table_multipart_reply( VALUE r_attributes, void *data ) {
  assert( data );
  const struct ofp_table_stats *table_stats = data;
  
  HASH_SET( r_attributes, "table_id", UINT2NUM( table_stats->table_id ) );
  HASH_SET( r_attributes, "active_count", UINT2NUM( table_stats->active_count ) );
  HASH_SET( r_attributes, "lookup_count", ULL2NUM( table_stats->lookup_count ) );
  HASH_SET( r_attributes, "matched_count", ULL2NUM( table_stats->matched_count ) );
}


static void
unpack_port_multipart_reply( VALUE r_attributes, void *data ) {
  assert( data );
  const struct ofp_port_stats *port_stats = data;

  HASH_SET( r_attributes, "port_no", UINT2NUM( port_stats->port_no ) );
  HASH_SET( r_attributes, "rx_packets", ULL2NUM( port_stats->rx_packets ) );
  HASH_SET( r_attributes, "tx_packets", ULL2NUM( port_stats->tx_packets ) );
  HASH_SET( r_attributes, "rx_bytes", ULL2NUM( port_stats->rx_bytes ) );
  HASH_SET( r_attributes, "tx_bytes", ULL2NUM( port_stats->tx_bytes ) );
  HASH_SET( r_attributes, "rx_dropped", ULL2NUM( port_stats->rx_dropped ) );
  HASH_SET( r_attributes, "tx_dropped", ULL2NUM( port_stats->tx_dropped ) );
  HASH_SET( r_attributes, "rx_errors", ULL2NUM( port_stats->rx_errors ) );
  HASH_SET( r_attributes, "tx_errors", ULL2NUM( port_stats->tx_errors ) );
  HASH_SET( r_attributes, "rx_frame_err", ULL2NUM( port_stats->rx_frame_err ) );
  HASH_SET( r_attributes, "rx_over_err", ULL2NUM( port_stats->rx_over_err ) );
  HASH_SET( r_attributes, "rx_crc_err", ULL2NUM( port_stats->rx_crc_err ) );
  HASH_SET( r_attributes, "collisions", ULL2NUM( port_stats->collisions ) );
  HASH_SET( r_attributes, "duration_sec", UINT2NUM( port_stats->duration_sec ) );
  HASH_SET( r_attributes, "duration_nsec", UINT2NUM( port_stats->duration_nsec ) );
}


static VALUE
unpack_table_features_prop_instructions( const struct ofp_instruction *ins_hdr, uint16_t ins_len ) {
  uint16_t prop_len = ( uint16_t ) ( ins_len - offsetof( struct ofp_table_feature_prop_instructions, instruction_ids ) );
  uint16_t offset = 0;

  VALUE r_instruction_ids = rb_ary_new();
  while ( prop_len - offset >= ( uint16_t ) sizeof( struct ofp_instruction ) ) {
    const struct ofp_instruction *ins = ( const struct ofp_instruction * )( ( const char * ) ins_hdr + offset );
    VALUE r_type = UINT2NUM( ins->type );
    VALUE r_klass = rb_funcall( rb_eval_string( "Instruction" ), rb_intern( "search" ), 2, rb_str_new_cstr( "OFPIT" ), r_type );
    if ( !NIL_P( r_klass ) ) {
      r_type = r_klass;
    }
    rb_ary_push( r_instruction_ids, r_type );
    offset = ( uint16_t ) ( offset + ins->len ); 
  }

  return r_instruction_ids;
}


static VALUE
unpack_table_features_prop_actions( const struct ofp_action_header *act_hdr, uint16_t act_len ) {
  uint16_t prop_len = ( uint16_t ) ( act_len - offsetof( struct ofp_table_feature_prop_actions, action_ids ) );
  uint16_t offset = 0;

  VALUE r_action_ids = rb_ary_new();
  while ( prop_len - offset >= ( uint16_t ) sizeof( struct ofp_action_header ) ) {
    const struct ofp_action_header *act = ( const struct ofp_action_header * )( ( const char * ) act_hdr + offset );
    VALUE r_type = UINT2NUM( act->type );
    VALUE r_klass = rb_funcall( rb_eval_string( "BasicAction" ), rb_intern( "search" ), 2, rb_str_new_cstr( "OFPAT" ), r_type );
    if  ( !NIL_P( r_klass ) ) {
      r_type = r_klass;
    }
    rb_ary_push( r_action_ids, r_type );
    offset = ( uint16_t ) ( offset + act->len );
  }

  return r_action_ids;
}


static VALUE
unpack_table_features_prop_oxm( const uint32_t *oxm_hdr, uint16_t oxm_len ) {
  uint16_t prop_len = ( uint16_t ) ( oxm_len - offsetof( struct ofp_table_feature_prop_oxm, oxm_ids ) );
  uint16_t nr_oxms = ( uint16_t ) ( prop_len / sizeof( uint32_t ) );

  VALUE r_oxm_ids = rb_ary_new();
  for ( uint16_t i = 0; i < nr_oxms; i++ ) {
    VALUE r_field = UINT2NUM( OXM_FIELD( oxm_hdr[ i ] ) );
    VALUE r_klass = rb_funcall( rb_eval_string( "FlexibleAction" ), rb_intern( "search" ), 2, rb_str_new_cstr( "OFPXMT_OFB" ), r_field );
    if ( !NIL_P( r_klass ) ) {
      r_field = r_klass;
    }
    rb_ary_push( r_oxm_ids, r_field );
  }

  return r_oxm_ids;
}


static VALUE
unpack_table_features_prop_next_tables( const uint8_t *next_table_hdr, uint16_t next_table_len ) {
  uint16_t prop_len = ( uint16_t ) ( next_table_len - offsetof( struct ofp_table_feature_prop_next_tables, next_table_ids ) );
  uint16_t nr_next_table_ids = ( uint16_t ) ( prop_len / sizeof( uint8_t ) );

  VALUE r_next_table_ids = rb_ary_new();
  for ( uint16_t i = 0; i < nr_next_table_ids; i++ ) {
    rb_ary_push( r_next_table_ids, UINT2NUM( next_table_hdr[ i ] ) );
  }

  return r_next_table_ids;
}


static VALUE
unpack_table_features_properties( const struct ofp_table_feature_prop_header *prop_hdr, uint16_t properties_len ) {
  uint16_t offset = 0;
  uint16_t type = prop_hdr->type;

  VALUE r_properties = rb_hash_new();
  while ( properties_len - offset >= ( uint16_t ) ( sizeof( struct ofp_table_feature_prop_header ) ) ) {
    type = ( ( const struct ofp_table_feature_prop_header * )( ( const char * ) prop_hdr + offset ) )->type;
    switch( type ) {
      case OFPTFPT_INSTRUCTIONS:
      case OFPTFPT_INSTRUCTIONS_MISS: {
        const struct ofp_table_feature_prop_instructions *tfpi = ( const struct ofp_table_feature_prop_instructions * )( ( const char * ) prop_hdr + offset );
        offset = ( uint16_t ) ( offset + tfpi->length + PADLEN_TO_64( tfpi->length ) );
        VALUE r_instruction_ids = unpack_table_features_prop_instructions( tfpi->instruction_ids, tfpi->length );
        HASH_SET( r_properties, table_feature_prop_type_name[ type ], r_instruction_ids );
      }
      break;
      case OFPTFPT_WRITE_ACTIONS:
      case OFPTFPT_WRITE_ACTIONS_MISS:
      case OFPTFPT_APPLY_ACTIONS:
      case  OFPTFPT_APPLY_ACTIONS_MISS: {
        const struct ofp_table_feature_prop_actions *tfpa = ( const struct ofp_table_feature_prop_actions * )( ( const char * ) prop_hdr + offset );
        offset = ( uint16_t ) ( offset + tfpa->length + PADLEN_TO_64( tfpa->length ) );
        VALUE r_action_ids = unpack_table_features_prop_actions( tfpa->action_ids, tfpa->length );
        HASH_SET( r_properties, table_feature_prop_type_name[ type ], r_action_ids );
      }
      break;
      case OFPTFPT_MATCH:
      case OFPTFPT_WILDCARDS:
      case OFPTFPT_WRITE_SETFIELD:
      case OFPTFPT_WRITE_SETFIELD_MISS:
      case OFPTFPT_APPLY_SETFIELD:
      case OFPTFPT_APPLY_SETFIELD_MISS: {
        const struct ofp_table_feature_prop_oxm *tfpo = ( const struct ofp_table_feature_prop_oxm * )( ( const char * ) prop_hdr + offset );
        offset = ( uint16_t ) ( offset + tfpo->length + PADLEN_TO_64( tfpo->length ) );
        VALUE r_oxm_ids = unpack_table_features_prop_oxm( tfpo->oxm_ids, tfpo->length );
        HASH_SET( r_properties, table_feature_prop_type_name[ type ], r_oxm_ids );
      }
      break;
      case OFPTFPT_NEXT_TABLES:
      case OFPTFPT_NEXT_TABLES_MISS: {
        const struct ofp_table_feature_prop_next_tables *tfpnt = ( const struct ofp_table_feature_prop_next_tables * )( ( const char * ) prop_hdr + offset );
        offset = ( uint16_t ) ( offset + tfpnt->length + PADLEN_TO_64( tfpnt->length ) );
        VALUE r_next_table_ids = unpack_table_features_prop_next_tables( tfpnt->next_table_ids, tfpnt->length );
        HASH_SET( r_properties, table_feature_prop_type_name[ type ], r_next_table_ids );
      }
      break;
      default:
        assert( 0 );
      break;
    }
  }
  return r_properties;
}


static void
unpack_table_features_multipart_reply( VALUE r_attributes, void *data ) {
  assert( data );
  const struct ofp_table_features *table_features = data;

  HASH_SET( r_attributes, "length", UINT2NUM( table_features->length ) );
  HASH_SET( r_attributes, "table_id", UINT2NUM( table_features->table_id ) );
  HASH_SET( r_attributes, "name", rb_str_new2( table_features->name ) );
  HASH_SET( r_attributes, "metadata_match", ULL2NUM( table_features->metadata_match ) );
  HASH_SET( r_attributes, "metadata_write", ULL2NUM( table_features->metadata_write ) );
  HASH_SET( r_attributes, "config", UINT2NUM( table_features->config ) );
  HASH_SET( r_attributes, "max_entries", UINT2NUM( table_features->max_entries ) );

  uint16_t total_prop_len = ( uint16_t ) ( table_features->length - offsetof( struct ofp_table_features, properties ) );
  if  ( total_prop_len >= ( uint16_t ) sizeof( struct ofp_table_feature_prop_header ) ) {
    VALUE r_properties = unpack_table_features_properties( table_features->properties, total_prop_len );
    HASH_SET( r_attributes, "properties", r_properties );
  }
}


static VALUE
unpack_bucket_counter( const struct ofp_bucket_counter  *src_bucket_counter, uint16_t bucket_counter_len ) {
  VALUE r_bucket_stats_ary = rb_ary_new();
  uint16_t offset = 0;
  uint16_t nr_bucket_counters = bucket_counter_len / ( uint16_t ) sizeof( *src_bucket_counter );

  for ( uint16_t i = 0; i < nr_bucket_counters; i++ ) {
    rb_ary_push( r_bucket_stats_ary, ULL2NUM( src_bucket_counter->packet_count ) );
    rb_ary_push( r_bucket_stats_ary, ULL2NUM( src_bucket_counter->byte_count ) );
    offset = ( uint16_t ) ( offset + sizeof( *src_bucket_counter ) );
    src_bucket_counter = ( const struct ofp_bucket_counter * )( ( const char * ) src_bucket_counter + offset );
  }
  return r_bucket_stats_ary;
}


static void
unpack_group_multipart_reply( VALUE r_attributes, void *data ) {
  assert( data );
  const struct ofp_group_stats *group_stats = data;

  HASH_SET( r_attributes, "length", UINT2NUM( group_stats->length ) );
  HASH_SET( r_attributes, "group_id", UINT2NUM( group_stats->group_id ) );
  HASH_SET( r_attributes, "ref_count", UINT2NUM( group_stats->ref_count ) );
  HASH_SET( r_attributes, "packet_count", ULL2NUM( group_stats->packet_count ) );
  HASH_SET( r_attributes, "byte_count", ULL2NUM( group_stats->byte_count ) );
  HASH_SET( r_attributes, "duration_sec", UINT2NUM( group_stats->duration_sec ) );
  HASH_SET( r_attributes, "duration_nsec", UINT2NUM( group_stats->duration_nsec ) );

  uint16_t bucket_counter_len = ( uint16_t ) ( group_stats->length - offsetof( struct ofp_group_stats, bucket_stats ) );
  VALUE r_bucket_stats_ary = Qnil;
  if ( bucket_counter_len >= ( uint16_t ) sizeof( struct ofp_bucket_counter ) ) {
    const struct ofp_bucket_counter *bc_src = ( const struct ofp_bucket_counter * )( ( const char * ) group_stats + offsetof( struct ofp_group_stats, bucket_stats ) );
    r_bucket_stats_ary = unpack_bucket_counter( bc_src, bucket_counter_len );
  }
  HASH_SET( r_attributes, "bucket_stats", r_bucket_stats_ary );
}


static VALUE
unpack_bucket( const struct ofp_bucket *bucket ) {
  VALUE r_action_ary = rb_ary_new();
  uint32_t offset = offsetof( struct ofp_bucket, actions );
  uint32_t actions_len = bucket->len - offset;

  VALUE r_bucket_attrs = rb_hash_new();
  HASH_SET( r_bucket_attrs, "weight", UINT2NUM( bucket->weight ) );
  HASH_SET( r_bucket_attrs, "watch_port", UINT2NUM( bucket->watch_port ) );
  HASH_SET( r_bucket_attrs, "watch_group", UINT2NUM( bucket->watch_group ) );

  while ( actions_len >= sizeof( struct ofp_action_header * ) ) {
    const struct ofp_action_header *ac_hdr = ( const struct ofp_action_header * ) ( ( const char * ) bucket + offset ); 

    uint16_t part_length = ac_hdr->len;
    if ( actions_len < part_length ) {
      break;
    }
    unpack_action( ac_hdr, r_action_ary );
    
    actions_len -= part_length;
    offset += part_length;
  }
  HASH_SET( r_bucket_attrs, "actions", r_action_ary );
  VALUE r_bucket = rb_funcall( rb_eval_string( "Messages::Bucket" ), rb_intern( "new" ), 1, r_bucket_attrs );
  return r_bucket;
}


static void
unpack_group_desc_multipart_reply( VALUE r_attributes, void *data ) {
  assert( data );
  const struct ofp_group_desc_stats *group_desc_stats = data;

  HASH_SET( r_attributes, "length", UINT2NUM( group_desc_stats->length ) );
  HASH_SET( r_attributes, "group_id", UINT2NUM( group_desc_stats->group_id ) );

  uint32_t offset = offsetof( struct ofp_group_desc_stats, buckets );
  uint32_t buckets_len = group_desc_stats->length - offset;
  VALUE r_bucket_ary = rb_ary_new();
  while ( buckets_len >= sizeof( struct ofp_bucket ) ) {
    const struct ofp_bucket *bucket = ( const struct ofp_bucket * ) ( ( const char * ) group_desc_stats + offset );

    uint16_t part_length = bucket->len;
    if ( buckets_len < part_length ) {
      break;
    }
    buckets_len -= part_length;
    offset += part_length;
    VALUE r_bucket = unpack_bucket( bucket );
    rb_ary_push( r_bucket_ary, r_bucket );
  }
  HASH_SET( r_attributes, "buckets", r_bucket_ary );
}


static void
unpack_group_features_multipart_reply( VALUE r_attributes, void *data ) {
  assert( data );
  const struct ofp_group_features *group_features = data;

  HASH_SET( r_attributes, "types", UINT2NUM( group_features->types ) );
  HASH_SET( r_attributes, "capabilities", UINT2NUM( group_features->capabilities ) );
  VALUE r_max_groups = rb_ary_new();
  for ( uint8_t i = 0; i < sizeof( group_features->max_groups ) / sizeof( group_features->max_groups[ 0 ] ); i++ ) {
    rb_ary_push( r_max_groups, UINT2NUM( group_features->max_groups[ i ] ) );
  }
  HASH_SET( r_attributes, "max_groups", r_max_groups );
  
  VALUE r_actions = rb_ary_new();
  for ( uint8_t i = 0; i < sizeof( group_features->actions ) / sizeof( group_features->actions[ 0 ] ); i++ ) {
    rb_ary_push( r_actions, UINT2NUM( group_features->actions[ i ] ) );
  }
  HASH_SET( r_attributes, "actions", r_actions );
}


static void
unpack_port_desc_multipart_reply( VALUE r_attributes, void *data, size_t length ) {
  const struct ofp_port *port = data;

  VALUE r_ports_ary = rb_ary_new();
  VALUE r_port_attrs = rb_hash_new();
  while ( length >= sizeof( struct ofp_port ) ) {
    unpack_port( port, r_port_attrs );
    VALUE port = rb_funcall( rb_eval_string( "Messages::Port" ), rb_intern( "new" ), 1, r_port_attrs );
    rb_ary_push( r_ports_ary, port );
    length -= sizeof( struct ofp_port );
    port++;
  }
  HASH_SET( r_attributes, "ports", r_ports_ary );
}

  
static VALUE
unpack_multipart_reply( void *controller, VALUE r_attributes, const uint16_t stats_type, const buffer *frame ) {
  VALUE r_dpid = HASH_REF( r_attributes, datapath_id );
  VALUE r_reply_obj = Qnil;
  VALUE r_parts = rb_ary_new();

  switch ( stats_type ) {
    case OFPMP_DESC: {
      unpack_desc_multipart_reply( r_attributes, frame->data );
      r_reply_obj = rb_funcall( rb_eval_string( "Messages::DescMultipartReply" ), rb_intern( "new" ), 1, r_attributes );
      rb_ary_push( r_parts, r_reply_obj );
      HASH_SET( r_attributes, "parts", r_parts );
      r_reply_obj = rb_funcall( rb_eval_string( "Messages::MultipartReply" ), rb_intern( "new" ), 1, r_attributes );
      if ( rb_respond_to( ( VALUE ) controller, rb_intern( "desc_multipart_reply"  ) ) ) {
        rb_funcall( ( VALUE ) controller, rb_intern( "desc_multipart_reply" ), 2, r_dpid, r_reply_obj );
      }
    }
    break;
    case OFPMP_FLOW: {
      if ( frame != NULL ) {
        if ( frame->length ) {
          size_t len = sizeof( struct ofp_flow_stats );
          size_t total_len = frame->length;
          size_t offset = 0;
          while( total_len >= len ) {
            unpack_flow_multipart_reply( r_attributes, ( ( char * ) frame->data + offset ) );
            r_reply_obj = rb_funcall( rb_eval_string( "Messages::FlowMultipartReply" ), rb_intern( "new" ), 1, r_attributes );
            rb_ary_push( r_parts, r_reply_obj );
            const struct ofp_flow_stats *flow_stats = ( const struct ofp_flow_stats * )( ( const char * ) frame->data + offset );
            total_len -= flow_stats->length;
            offset += flow_stats->length;
          }
        }
      }
     HASH_SET( r_attributes, "parts", r_parts );
      r_reply_obj = rb_funcall( rb_eval_string( "Messages::MultipartReply" ), rb_intern( "new" ), 1, r_attributes );
      if ( rb_respond_to( ( VALUE ) controller, rb_intern( "flow_multipart_reply" ) ) ) {
        rb_funcall( ( VALUE ) controller, rb_intern( "flow_multipart_reply" ), 2, r_dpid, r_reply_obj );
      }
    }
    break;
    case OFPMP_AGGREGATE: {
      // we always expect a reply
      unpack_aggregate_multipart_reply( r_attributes, frame->data );
      r_reply_obj = rb_funcall( rb_eval_string( "Messages::AggregateMultipartReply" ), rb_intern( "new" ), 1, r_attributes );
      rb_ary_push( r_parts, r_reply_obj );
      HASH_SET( r_attributes, "parts", r_parts );
      r_reply_obj = rb_funcall( rb_eval_string( "Messages::MultipartReply" ), rb_intern( "new" ), 1, r_attributes );
      if ( rb_respond_to( ( VALUE ) controller, rb_intern( "aggregate_multipart_reply" ) ) ) {
        rb_funcall( ( VALUE ) controller, rb_intern( "aggregate_multipart_reply" ), 2, r_dpid, r_reply_obj ); 
      }
    }
    break;
    case OFPMP_TABLE: {
      size_t len = sizeof( struct ofp_table_stats );
      size_t total_len = frame->length;
      size_t offset = 0;
      while ( total_len >= len ) {
        unpack_table_multipart_reply( r_attributes, ( ( char * ) frame->data + offset ) );
        r_reply_obj = rb_funcall( rb_eval_string( "Messages::TableMultipartReply" ), rb_intern( "new" ), 1, r_attributes );
        rb_ary_push( r_parts, r_reply_obj );
        total_len -= len;
        offset += len;
      }
      HASH_SET( r_attributes, "parts", r_parts );
      r_reply_obj = rb_funcall( rb_eval_string( "Messages::MultipartReply" ), rb_intern( "new" ), 1, r_attributes );
      if ( rb_respond_to( ( VALUE ) controller, rb_intern( "table_multipart_reply" ) ) ) {
        rb_funcall( ( VALUE ) controller, rb_intern( "table_multipart_reply" ), 2, r_dpid, r_reply_obj ); 
      }
    }
    break;
    case OFPMP_PORT_STATS: {
      if ( frame != NULL ) {
        if ( frame->length ) {
          size_t len = sizeof( struct ofp_port_stats );
          size_t total_len = frame->length;
          size_t offset = 0;
          while( total_len >= len ) {
            unpack_port_multipart_reply( r_attributes, ( ( char * ) frame->data + offset ) );
            r_reply_obj = rb_funcall( rb_eval_string( "Messages::PortMultipartReply" ), rb_intern( "new" ), 1, r_attributes );
            rb_ary_push( r_parts, r_reply_obj );
            total_len -= len;
            offset += len;
          }
        }
      }
      HASH_SET( r_attributes, "parts", r_parts );
      r_reply_obj = rb_funcall( rb_eval_string( "Messages::MultipartReply" ), rb_intern( "new" ), 1, r_attributes );
      if ( rb_respond_to( ( VALUE ) controller, rb_intern( "port_multipart_reply" ) ) ) {
        rb_funcall( ( VALUE ) controller, rb_intern( "port_multipart_reply" ), 2, r_dpid, r_reply_obj );
      }
    }
    break;
    case OFPMP_TABLE_FEATURES: {
      size_t len = sizeof( struct ofp_table_features );
      size_t total_len = frame->length;
      size_t offset = 0;
      while ( total_len >= len ) {
        unpack_table_features_multipart_reply( r_attributes, ( ( char * ) frame->data + offset ) );
        r_reply_obj = rb_funcall( rb_eval_string( "Messages::TableFeaturesMultipartReply" ), rb_intern( "new" ), 1, r_attributes );
        rb_ary_push( r_parts, r_reply_obj );
        const struct ofp_table_features *table_features = ( const struct ofp_table_features * )( ( const char * ) frame->data + offset );
        total_len -= table_features->length;
        offset += table_features->length;
      }
      HASH_SET( r_attributes, "parts", r_parts );
      r_reply_obj = rb_funcall( rb_eval_string( "Messages::MultipartReply" ), rb_intern( "new" ), 1, r_attributes );
      if ( rb_respond_to( ( VALUE ) controller, rb_intern( "table_features_multipart_reply" ) ) ) {
        rb_funcall( ( VALUE ) controller, rb_intern( "table_features_multipart_reply" ), 2, r_dpid, r_reply_obj );
      }
    }
    break;
    case OFPMP_GROUP: {
      if ( frame != NULL ) {
        if ( frame->length ) {
          size_t len = sizeof( struct ofp_group_stats );
          size_t total_len = frame->length;
          size_t offset = 0;
          while ( total_len >= len ) {
            unpack_group_multipart_reply( r_attributes, ( ( char * ) frame->data + offset ) );
            r_reply_obj = rb_funcall( rb_eval_string( "Messages::GroupMultipartReply" ), rb_intern( "new" ), 1, r_attributes );
            rb_ary_push( r_parts, r_reply_obj );
            const struct ofp_group_stats *group_stats = ( const struct ofp_group_stats * )( ( const char * ) frame->data + offset ); 
            total_len -= group_stats->length;
            offset += group_stats->length;
          }
        }
      }
      HASH_SET( r_attributes, "parts", r_parts );
      r_reply_obj = rb_funcall( rb_eval_string( "Messages::MultipartReply" ), rb_intern( "new" ), 1, r_attributes );
      if ( rb_respond_to( ( VALUE ) controller, rb_intern( "group_multipart_reply" ) ) ) {
        rb_funcall( ( VALUE ) controller, rb_intern( "group_multipart_reply" ), 2, r_dpid, r_reply_obj );
      }
    }
    break;
    case OFPMP_GROUP_DESC: {
      if ( frame != NULL ) {
        if ( frame->length ) {
          size_t len = sizeof( struct ofp_group_desc_stats );
          size_t total_len = frame->length;
          size_t offset = 0;
          while ( total_len >= len ) {
            unpack_group_desc_multipart_reply( r_attributes, ( ( char * ) frame->data + offset ) );
            r_reply_obj = rb_funcall( rb_eval_string( "Messages::GroupDescMultipartReply" ), rb_intern( "new" ), 1, r_attributes );
            rb_ary_push( r_parts, r_reply_obj );
            const struct ofp_group_desc_stats *group_desc_stats = ( const struct ofp_group_desc_stats * )( ( const char * ) frame->data + offset ); 
            total_len -= group_desc_stats->length;
            offset += group_desc_stats->length;
          }
        }
      }
      HASH_SET( r_attributes, "parts", r_parts );
      r_reply_obj = rb_funcall( rb_eval_string( "Messages::MultipartReply" ), rb_intern( "new" ), 1, r_attributes );
      if ( rb_respond_to( ( VALUE ) controller, rb_intern( "group_desc_multipart_reply" )  ) ) {
        rb_funcall( ( VALUE ) controller, rb_intern( "group_desc_multipart_reply" ), 2, r_dpid, r_reply_obj );
      }
    }
    break;
    case OFPMP_GROUP_FEATURES: {
      unpack_group_features_multipart_reply( r_attributes, frame->data );
      r_reply_obj = rb_funcall( rb_eval_string( "Messages::GroupFeaturesMultipartReply" ), rb_intern( "new" ), 1, r_attributes );
      rb_ary_push( r_parts, r_reply_obj );
      HASH_SET( r_attributes, "parts", r_parts );
      r_reply_obj = rb_funcall( rb_eval_string( "Messages::MultipartReply" ), rb_intern( "new" ), 1, r_attributes );
      if ( rb_respond_to( ( VALUE ) controller, rb_intern( "group_features_multipart_reply" ) ) ) {
        rb_funcall( ( VALUE ) controller, rb_intern( "group_features_multipart_reply" ), 2, r_dpid, r_reply_obj ); 
      }
    }
    break;
    case OFPMP_PORT_DESC: {
      if ( frame != NULL ) {
        if ( frame->length ) {
          unpack_port_desc_multipart_reply( r_attributes, frame->data, frame->length );
          r_reply_obj = rb_funcall( rb_eval_string( "Messages::PortDescMultipartReply" ), rb_intern( "new" ), 1, r_attributes );
          rb_ary_push( r_parts, r_reply_obj );
        }
      }
      HASH_SET( r_attributes, "parts", r_parts );
      r_reply_obj = rb_funcall( rb_eval_string( "Messages::MultipartReply" ), rb_intern( "new" ), 1, r_attributes );
      if ( rb_respond_to( ( VALUE ) controller, rb_intern( "port_desc_multipart_reply" ) ) ) {
        rb_funcall( ( VALUE ) controller, rb_intern( "port_desc_multipart_reply" ), 2, r_dpid, r_reply_obj );
      }
    }
    break;
    default:
      warn( "Received invalid mutlipart reply type %u", stats_type );
    break;
  }

  return r_reply_obj;
}


void
handle_multipart_reply( uint64_t datapath_id,
                        uint32_t transaction_id,
                        uint16_t type,
                        uint16_t flags,
                        const buffer *data,
                        void *controller ) {
  VALUE r_attributes = rb_hash_new();
  VALUE r_dpid = ULL2NUM( datapath_id );
  HASH_SET( r_attributes, "datapath_id", r_dpid );
  HASH_SET( r_attributes, "transaction_id", UINT2NUM( transaction_id ) );
  HASH_SET( r_attributes, "type", UINT2NUM( type ) );
  HASH_SET( r_attributes, "flags", UINT2NUM( flags ) );
  unpack_multipart_reply( controller, r_attributes, type, data );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
