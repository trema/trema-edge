/*
 * Author: Yasunobu Chiba
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


#include <arpa/inet.h>
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include "byteorder.h"
#include "log.h"
#include "wrapper.h"
#include "oxm_byteorder.h"


void
ntoh_hello_elem_versionbitmap( struct ofp_hello_elem_versionbitmap *dst, const struct ofp_hello_elem_versionbitmap *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->type ) == OFPHET_VERSIONBITMAP );

  dst->type = ntohs( src->type );
  dst->length = ntohs( src->length );

  size_t n_bitmaps = ( dst->length - offsetof( struct ofp_hello_elem_versionbitmap, bitmaps ) ) / sizeof( uint32_t );

  for ( size_t i = 0; i < n_bitmaps; i++ ) {
    dst->bitmaps[ i ] = ntohl( src->bitmaps[ i ] );
  }
}


void
hton_hello_elem_versionbitmap( struct ofp_hello_elem_versionbitmap *dst, const struct ofp_hello_elem_versionbitmap *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->type == OFPHET_VERSIONBITMAP );

  size_t n_bitmaps = ( src->length - offsetof( struct ofp_hello_elem_versionbitmap, bitmaps ) ) / sizeof( uint32_t );

  dst->type = htons( src->type );
  dst->length = htons( src->length );

  for ( size_t i = 0; i < n_bitmaps; i++ ) {
    dst->bitmaps[ i ] = htonl( src->bitmaps[ i ] );
  }
}


void
ntoh_hello_elem( struct ofp_hello_elem_header *dst, const struct ofp_hello_elem_header *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  switch ( ntohs( src->type ) ) {
    case OFPHET_VERSIONBITMAP:
    {
      ntoh_hello_elem_versionbitmap( ( struct ofp_hello_elem_versionbitmap * ) dst,
                                     ( const struct ofp_hello_elem_versionbitmap * ) src );
    }
    break;

    default:
    {
      die( "Undefined hello element type ( type = %#x ).", ntohs( src->type ) );
    }
    break;
  }
}


void
hton_hello_elem( struct ofp_hello_elem_header *dst, const struct ofp_hello_elem_header *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  switch ( src->type ) {
    case OFPHET_VERSIONBITMAP:
    {
      hton_hello_elem_versionbitmap( ( struct ofp_hello_elem_versionbitmap * ) dst,
                                     ( const struct ofp_hello_elem_versionbitmap * ) src );
    }
    break;

    default:
    {
      die( "Undefined hello element type ( type = %#x ).", src->type );
    }
    break;
  }
}


void
ntoh_port( struct ofp_port *dst, const struct ofp_port *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->port_no = ntohl( src->port_no );
  memset( &dst->pad, 0, sizeof( dst->pad ) );

  memmove( dst->hw_addr, src->hw_addr, OFP_ETH_ALEN );
  memset( &dst->pad2, 0, sizeof( dst->pad2 ) );

  memmove( dst->name, src->name, OFP_MAX_PORT_NAME_LEN );

  dst->config = ntohl( src->config );
  dst->state = ntohl( src->state );

  dst->curr = ntohl( src->curr );
  dst->advertised = ntohl( src->advertised );
  dst->supported = ntohl( src->supported );
  dst->peer = ntohl( src->peer );

  dst->curr_speed = ntohl( src->curr_speed );
  dst->max_speed = ntohl( src->max_speed );
}


void
ntoh_action_output( struct ofp_action_output *dst, const struct ofp_action_output *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  dst->port = ntohl( src->port );
  dst->max_len = ntohs( src->max_len );
  memset( &dst->pad, 0, sizeof( dst->pad ) );
}


void ntoh_action_set_field( struct ofp_action_set_field *dst, const struct ofp_action_set_field *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->len ) != 0 );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );

  size_t field_length = dst->len - offsetof( struct ofp_action_set_field, field );
  if ( field_length > sizeof( oxm_match_header ) ) {
    const oxm_match_header *s_oxm = ( const oxm_match_header * ) src->field;
    oxm_match_header *d_oxm = ( oxm_match_header * ) dst->field;
    ntoh_oxm_match( d_oxm, s_oxm );
  }
  else {
    memset( dst->field, 0, field_length );
  }
}


void hton_action_set_field( struct ofp_action_set_field *dst, const struct ofp_action_set_field *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->len != 0 );

  dst->type = htons( src->type );
  dst->len = htons( src->len );

  size_t field_length = ntohs( dst->len ) - offsetof( struct ofp_action_set_field, field );
  if ( field_length > sizeof( oxm_match_header ) ) {
    const oxm_match_header *s_oxm = ( const oxm_match_header * ) src->field;
    oxm_match_header *d_oxm = ( oxm_match_header * ) dst->field;
    hton_oxm_match( d_oxm, s_oxm );
  }
  else {
    memset( dst->field, 0, field_length );
  }
}


void
ntoh_action_set_queue( struct ofp_action_set_queue *dst, const struct ofp_action_set_queue *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  dst->queue_id = ntohl( src->queue_id );
}


void
ntoh_action_experimenter( struct ofp_action_experimenter_header *dst, const struct ofp_action_experimenter_header *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  dst->experimenter = ntohl( src->experimenter );

  uint16_t offset = ( uint16_t ) sizeof( struct ofp_action_experimenter_header );
  if ( dst->len > offset ) {
    uint16_t data_length = ( uint16_t ) ( dst->len - offset );
    memmove( ( char * ) dst + offset, ( const char * ) src + offset, data_length );
  }
}


void
hton_action_experimenter( struct ofp_action_experimenter_header *dst, const struct ofp_action_experimenter_header *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = htons( src->type );
  dst->len = htons( src->len );
  dst->experimenter = htonl( src->experimenter );

  uint16_t offset = sizeof( struct ofp_action_experimenter_header );
  if ( ntohs( dst->len ) > offset ) {
    uint16_t data_length = ( uint16_t ) ( ntohs( dst->len ) - offset );
    memmove( ( char * ) dst + offset, ( const char * ) src + offset, data_length );
  }
}


void
ntoh_action_mpls_ttl( struct ofp_action_mpls_ttl *dst, const struct ofp_action_mpls_ttl *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  dst->mpls_ttl = src->mpls_ttl;
  memset( &dst->pad, 0, sizeof( dst->pad ) );
}


void
ntoh_action_push( struct ofp_action_push *dst, const struct ofp_action_push *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  dst->ethertype = ntohs( src->ethertype );
  memset( &dst->pad, 0, sizeof( dst->pad ) );
}


void
ntoh_action_pop_mpls( struct ofp_action_pop_mpls *dst, const struct ofp_action_pop_mpls *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  dst->ethertype = ntohs( src->ethertype );
  memset( &dst->pad, 0, sizeof( dst->pad ) );
}


void
ntoh_action_group( struct ofp_action_group *dst, const struct ofp_action_group *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  dst->group_id = ntohl( src->group_id );
}


void
ntoh_action_nw_ttl( struct ofp_action_nw_ttl *dst, const struct ofp_action_nw_ttl *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  dst->nw_ttl = src->nw_ttl;
  memset( &dst->pad, 0, sizeof( dst->pad ) );
}


void
ntoh_action_header( struct ofp_action_header *dst, const struct ofp_action_header *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  memset( &dst->pad, 0, sizeof( dst->pad ) );
}


void
ntoh_action( struct ofp_action_header *dst, const struct ofp_action_header *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  switch ( ntohs( src->type ) ) {
    case OFPAT_OUTPUT:
    {
      ntoh_action_output( ( struct ofp_action_output * ) dst, ( const struct ofp_action_output * ) src );
    }
    break;

    case OFPAT_COPY_TTL_OUT:
    case OFPAT_COPY_TTL_IN:
    case OFPAT_DEC_MPLS_TTL:
    case OFPAT_POP_VLAN:
    case OFPAT_POP_PBB:
    case OFPAT_DEC_NW_TTL:
    {
      ntoh_action_header( dst, src );
    }
    break;

    case OFPAT_SET_MPLS_TTL:
    {
      ntoh_action_mpls_ttl( ( struct ofp_action_mpls_ttl * ) dst, ( const struct ofp_action_mpls_ttl * ) src );
    }
    break;

    case OFPAT_PUSH_VLAN:
    case OFPAT_PUSH_MPLS:
    case OFPAT_PUSH_PBB:
    {
      ntoh_action_push( ( struct ofp_action_push * ) dst, ( const struct ofp_action_push * ) src );
    }
    break;

    case OFPAT_POP_MPLS:
    {
      ntoh_action_pop_mpls( ( struct ofp_action_pop_mpls * ) dst, ( const struct ofp_action_pop_mpls * ) src );
    }
    break;

    case OFPAT_SET_QUEUE:
    {
      ntoh_action_set_queue( ( struct ofp_action_set_queue * ) dst, ( const struct ofp_action_set_queue * ) src );
    }
    break;

    case OFPAT_GROUP:
    {
      ntoh_action_group( ( struct ofp_action_group * ) dst, ( const struct ofp_action_group * ) src );
    }
    break;

    case OFPAT_SET_NW_TTL:
    {
      ntoh_action_nw_ttl( ( struct ofp_action_nw_ttl * ) dst, ( const struct ofp_action_nw_ttl * ) src );
    }
    break;

    case OFPAT_SET_FIELD:
    {
      ntoh_action_set_field( ( struct ofp_action_set_field * ) dst, ( const struct ofp_action_set_field * ) src );
    }
    break;

    case OFPAT_EXPERIMENTER:
    {
      ntoh_action_experimenter( ( struct ofp_action_experimenter_header * ) dst, ( const struct ofp_action_experimenter_header * ) src );
    }
    break;

    default:
    {
      die( "Undefined action type ( type = %#x ).", ntohs( src->type ) );
    }
    break;
  }
}


void
hton_action( struct ofp_action_header *dst, const struct ofp_action_header *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  switch ( src->type ) {
    case OFPAT_OUTPUT:
    {
      hton_action_output( ( struct ofp_action_output * ) dst, ( const struct ofp_action_output * ) src );
    }
    break;

    case OFPAT_COPY_TTL_OUT:
    case OFPAT_COPY_TTL_IN:
    case OFPAT_DEC_MPLS_TTL:
    case OFPAT_POP_VLAN:
    case OFPAT_POP_PBB:
    case OFPAT_DEC_NW_TTL:
    {
      hton_action_header( dst, src );
    }
    break;

    case OFPAT_SET_MPLS_TTL:
    {
      hton_action_mpls_ttl( ( struct ofp_action_mpls_ttl * ) dst, ( const struct ofp_action_mpls_ttl * ) src );
    }
    break;

    case OFPAT_PUSH_VLAN:
    case OFPAT_PUSH_MPLS:
    case OFPAT_PUSH_PBB:
    {
      hton_action_push( ( struct ofp_action_push * ) dst, ( const struct ofp_action_push * ) src );
    }
    break;

    case OFPAT_POP_MPLS:
    {
      hton_action_pop_mpls( ( struct ofp_action_pop_mpls * ) dst, ( const struct ofp_action_pop_mpls * ) src );
    }
    break;

    case OFPAT_SET_QUEUE:
    {
      hton_action_set_queue( ( struct ofp_action_set_queue * ) dst, ( const struct ofp_action_set_queue * ) src );
    }
    break;

    case OFPAT_GROUP:
    {
      hton_action_group( ( struct ofp_action_group * ) dst, ( const struct ofp_action_group * ) src );
    }
    break;

    case OFPAT_SET_NW_TTL:
    {
      hton_action_nw_ttl( ( struct ofp_action_nw_ttl * ) dst, ( const struct ofp_action_nw_ttl * ) src );
    }
    break;

    case OFPAT_SET_FIELD:
    {
      hton_action_set_field( ( struct ofp_action_set_field * ) dst, ( const struct ofp_action_set_field * ) src );
    }
    break;

    case OFPAT_EXPERIMENTER:
    {
      hton_action_experimenter( ( struct ofp_action_experimenter_header * ) dst, ( const struct ofp_action_experimenter_header * ) src );
    }
    break;

    default:
    {
      die( "Undefined action type ( type = %#x ).", src->type );
    }
    break;
  }
}


void
ntoh_flow_stats( struct ofp_flow_stats *dst, const struct ofp_flow_stats *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->length ) != 0 );

  dst->length = ntohs( src->length );
  dst->table_id = src->table_id;
  dst->pad = 0;
  dst->duration_sec = ntohl( src->duration_sec );
  dst->duration_nsec = ntohl( src->duration_nsec );
  dst->priority = ntohs( src->priority );
  dst->idle_timeout = ntohs( src->idle_timeout );
  dst->hard_timeout = ntohs( src->hard_timeout );
  dst->flags = ntohs( src->flags );
  memset( &dst->pad2, 0, sizeof( dst->pad2 ) );
  dst->cookie = ntohll( src->cookie );
  dst->packet_count = ntohll( src->packet_count );
  dst->byte_count = ntohll( src->byte_count );
  ntoh_match( &dst->match, &src->match );

  uint16_t match_length = ( uint16_t ) ( dst->match.length + PADLEN_TO_64( dst->match.length ) );
  size_t offset = offsetof( struct ofp_flow_stats, match ) + match_length;
  size_t instructions_length = dst->length - offset;

  while ( instructions_length > sizeof( struct ofp_instruction ) ) {
    const struct ofp_instruction *inst_src = ( const struct ofp_instruction * ) ( ( const char * ) src + offset );
    struct ofp_instruction *inst_dst = ( struct ofp_instruction * ) ( ( char * ) dst + offset );

    uint16_t part_length = ntohs( inst_src->len );
    if ( instructions_length < part_length ) {
      break;
    }
    ntoh_instruction( inst_dst, inst_src );

    instructions_length -= part_length;
    offset += part_length;
  }
}


void
hton_flow_stats( struct ofp_flow_stats *dst, const struct ofp_flow_stats *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->length != 0 );

  dst->length = htons( src->length );
  dst->table_id = src->table_id;
  dst->pad = 0;
  dst->duration_sec = htonl( src->duration_sec );
  dst->duration_nsec = htonl( src->duration_nsec );
  dst->priority = htons( src->priority );
  dst->idle_timeout = htons( src->idle_timeout );
  dst->hard_timeout = htons( src->hard_timeout );
  dst->flags = htons( src->flags );
  memset( &dst->pad2, 0, sizeof( dst->pad2 ) );
  dst->cookie = htonll( src->cookie );
  dst->packet_count = htonll( src->packet_count );
  dst->byte_count = htonll( src->byte_count );
  hton_match( &dst->match, &src->match );

  uint16_t match_length = ( uint16_t ) ( ntohs( dst->match.length ) + PADLEN_TO_64( ntohs( dst->match.length ) ) );
  size_t offset = offsetof( struct ofp_flow_stats, match ) + match_length;
  size_t instructions_length = ntohs( dst->length ) - offset;

  while ( instructions_length > sizeof( struct ofp_instruction ) ) {
    const struct ofp_instruction *inst_src = ( const struct ofp_instruction * ) ( ( const char * ) src + offset );
    struct ofp_instruction *inst_dst = ( struct ofp_instruction * ) ( ( char * ) dst + offset );

    uint16_t part_length = inst_src->len;
    if ( instructions_length < part_length ) {
        break;
    }
    hton_instruction( inst_dst, inst_src );

    instructions_length -= part_length;
    offset += part_length;
  }
}


void
ntoh_aggregate_stats( struct ofp_aggregate_stats_reply *dst, const struct ofp_aggregate_stats_reply *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->packet_count = ntohll( src->packet_count );
  dst->byte_count = ntohll( src->byte_count );
  dst->flow_count = ntohl( src->flow_count );
  memset( &dst->pad, 0, sizeof( dst->pad ) );
}


void
ntoh_table_stats( struct ofp_table_stats *dst, const struct ofp_table_stats *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->table_id = src->table_id;
  memset( &dst->pad, 0, sizeof( dst->pad ) );
  dst->active_count = ntohl( src->active_count );
  dst->lookup_count = ntohll( src->lookup_count );
  dst->matched_count = ntohll( src->matched_count );
}


void
ntoh_port_stats( struct ofp_port_stats *dst, const struct ofp_port_stats *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->port_no = ntohl( src->port_no );
  memset( &dst->pad, 0, sizeof( dst->pad ) );
  dst->rx_packets = ntohll( src->rx_packets );
  dst->tx_packets = ntohll( src->tx_packets );
  dst->rx_bytes = ntohll( src->rx_bytes );
  dst->tx_bytes = ntohll( src->tx_bytes );
  dst->rx_dropped = ntohll( src->rx_dropped );
  dst->tx_dropped = ntohll( src->tx_dropped );
  dst->rx_errors = ntohll( src->rx_errors );
  dst->tx_errors = ntohll( src->tx_errors );
  dst->rx_frame_err = ntohll( src->rx_frame_err );
  dst->rx_over_err = ntohll( src->rx_over_err );
  dst->rx_crc_err = ntohll( src->rx_crc_err );
  dst->collisions = ntohll( src->collisions );
  dst->duration_sec = ntohl( src->duration_sec );
  dst->duration_nsec = ntohl( src->duration_nsec );
}


void
ntoh_queue_stats( struct ofp_queue_stats *dst, const struct ofp_queue_stats *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->port_no = ntohl( src->port_no );
  dst->queue_id = ntohl( src->queue_id );
  dst->tx_bytes = ntohll( src->tx_bytes );
  dst->tx_packets = ntohll( src->tx_packets );
  dst->tx_errors = ntohll( src->tx_errors );
  dst->duration_sec = ntohl( src->duration_sec );
  dst->duration_nsec = ntohl( src->duration_nsec );
}


void
ntoh_queue_property( struct ofp_queue_prop_header *dst, const struct ofp_queue_prop_header *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->len ) != 0 );

  dst->property = ntohs( src->property );
  dst->len = ntohs( src->len );
  
  if ( dst->property == OFPQT_MIN_RATE ) {
    const struct ofp_queue_prop_min_rate *mr_src = ( const struct ofp_queue_prop_min_rate * ) src;
    struct ofp_queue_prop_min_rate *mr_dst = ( struct ofp_queue_prop_min_rate * ) dst;

    mr_dst->rate = ntohs( mr_src->rate );
  }
  else if ( dst->property == OFPQT_MAX_RATE ) {
    const struct ofp_queue_prop_max_rate *mr_src = ( const struct ofp_queue_prop_max_rate * ) src;
    struct ofp_queue_prop_max_rate *mr_dst = ( struct ofp_queue_prop_max_rate * ) dst;

    mr_dst->rate = ntohs( mr_src->rate );
  }
  else if ( dst->property == OFPQT_EXPERIMENTER ) {
    const struct ofp_queue_prop_experimenter *exp_src = ( const struct ofp_queue_prop_experimenter * ) src;
    struct ofp_queue_prop_experimenter *exp_dst = ( struct ofp_queue_prop_experimenter * ) dst;

    exp_dst->experimenter = ntohl( exp_src->experimenter );

    uint16_t offset = offsetof( struct ofp_queue_prop_experimenter, data );
    if ( dst->len > offset ) {
      uint16_t data_length = ( uint16_t ) ( dst->len - offset );
      memmove( exp_dst->data, exp_src->data, data_length );
    }
  }
}


void
hton_queue_property( struct ofp_queue_prop_header *dst, const struct ofp_queue_prop_header *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->len != 0 );

  dst->property = htons( src->property );
  dst->len = htons( src->len );
  
  if ( src->property == OFPQT_MIN_RATE ) {
    const struct ofp_queue_prop_min_rate *mr_src = ( const struct ofp_queue_prop_min_rate * ) src;
    struct ofp_queue_prop_min_rate *mr_dst = ( struct ofp_queue_prop_min_rate * ) dst;

    mr_dst->rate = htons( mr_src->rate );
  }
  else if ( src->property == OFPQT_MAX_RATE ) {
    const struct ofp_queue_prop_max_rate *mr_src = ( const struct ofp_queue_prop_max_rate * ) src;
    struct ofp_queue_prop_max_rate *mr_dst = ( struct ofp_queue_prop_max_rate * ) dst;

    mr_dst->rate = htons( mr_src->rate );
  }
  else if ( src->property == OFPQT_EXPERIMENTER ) {
    const struct ofp_queue_prop_experimenter *exp_src = ( const struct ofp_queue_prop_experimenter * ) src;
    struct ofp_queue_prop_experimenter *exp_dst = ( struct ofp_queue_prop_experimenter * ) dst;

    exp_dst->experimenter = htonl( exp_src->experimenter );

    uint16_t offset = offsetof( struct ofp_queue_prop_experimenter, data );
    if ( ntohs( dst->len ) > offset ) {
      uint16_t data_length = ( uint16_t ) ( ntohs( dst->len ) - offset );
      memmove( exp_dst->data, exp_src->data, data_length );
    }
  }
}


void
ntoh_packet_queue( struct ofp_packet_queue *dst, const struct ofp_packet_queue *src ) {
  /* Note that ofp_packet_queue is variable length.
   * Please make sure that dst and src have the same length.
   */
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->len ) != 0 );

  dst->queue_id = ntohl( src->queue_id );
  dst->port = ntohl( src->port );
  dst->len = ntohs( src->len );
  memset( &dst->pad, 0, sizeof( dst->pad ) );

  size_t offset = offsetof( struct ofp_packet_queue, properties );
  size_t properties_length = dst->len - offset;

  while ( properties_length >= sizeof( struct ofp_queue_prop_header ) ) {
    const struct ofp_queue_prop_header *ph_src = ( const struct ofp_queue_prop_header * ) ( ( const char * ) src + offset );
    struct ofp_queue_prop_header *ph_dst = ( struct ofp_queue_prop_header * ) ( ( char * ) dst + offset );

    uint16_t part_length = ntohs( ph_src->len );
    if ( properties_length < part_length ) {
      break;
    }
    ntoh_queue_property( ph_dst, ph_src );

    properties_length -= part_length;
    offset += part_length;
  }
}


void
hton_packet_queue( struct ofp_packet_queue *dst, const struct ofp_packet_queue *src ) {
  /* Note that ofp_packet_queue is variable length.
   * Please make sure that dst and src have the same length.
   */
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->len != 0 );

  dst->queue_id = htonl( src->queue_id );
  dst->port = htonl( src->port );
  dst->len = htons( src->len );
  memset( &dst->pad, 0, sizeof( dst->pad ) );

  size_t offset = offsetof( struct ofp_packet_queue, properties );
  size_t properties_length = ntohs( dst->len ) - offset;

  while ( properties_length >= sizeof( struct ofp_queue_prop_header ) ) {
    const struct ofp_queue_prop_header *ph_src = ( const struct ofp_queue_prop_header * ) ( ( const char * ) src + offset );
    struct ofp_queue_prop_header *ph_dst = ( struct ofp_queue_prop_header * ) ( ( char * ) dst + offset );

    uint16_t part_length = ph_src->len;
    if ( properties_length < part_length ) {
      break;
    }
    hton_queue_property( ph_dst, ph_src );

    properties_length -= part_length;
    offset += part_length;
  }
}


void
ntoh_instruction( struct ofp_instruction *dst, const struct ofp_instruction *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->type ) <= OFPIT_METER || ntohs( src->type ) == OFPIT_EXPERIMENTER );

  if ( ntohs( src->len ) == sizeof( struct ofp_instruction ) ) {
    dst->type = ntohs( src->type );
    dst->len = ntohs( src->len );
    return;
  }

  switch ( ntohs( src->type ) ) {
    case OFPIT_GOTO_TABLE:
    {
      ntoh_instruction_goto_table( ( struct ofp_instruction_goto_table * ) dst, ( const struct ofp_instruction_goto_table * ) src );
    }
    break;

    case OFPIT_WRITE_METADATA:
    {
      ntoh_instruction_write_metadata( ( struct ofp_instruction_write_metadata * ) dst, ( const struct ofp_instruction_write_metadata * ) src );
    }
    break;

    case OFPIT_WRITE_ACTIONS:
    case OFPIT_APPLY_ACTIONS:
    case OFPIT_CLEAR_ACTIONS:
    {
      ntoh_instruction_actions( ( struct ofp_instruction_actions * ) dst, ( const struct ofp_instruction_actions * ) src );
    }
    break;

    case OFPIT_METER:
    {
      ntoh_instruction_meter( ( struct ofp_instruction_meter * ) dst, ( const struct ofp_instruction_meter * ) src );
    }
    break;

    case OFPIT_EXPERIMENTER:
    {
      ntoh_instruction_experimenter( ( struct ofp_instruction_experimenter * ) dst, ( const struct ofp_instruction_experimenter * ) src );
    }
    break;

    default:
    {
      die( "Undefined instruction type ( type = %#x ).", ntohs( src->type ) );
    }
    break;
  }
}


void
hton_instruction( struct ofp_instruction *dst, const struct ofp_instruction *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->type <= OFPIT_METER || src->type == OFPIT_EXPERIMENTER );

  if ( src->len == sizeof( struct ofp_instruction ) ) {
    dst->type = htons( src->type );
    dst->len = htons( src->len );
    return;
  }

  switch ( src->type ) {
    case OFPIT_GOTO_TABLE:
    {
      hton_instruction_goto_table( ( struct ofp_instruction_goto_table * ) dst, ( const struct ofp_instruction_goto_table * ) src );
    }
    break;

    case OFPIT_WRITE_METADATA:
    {
      hton_instruction_write_metadata( ( struct ofp_instruction_write_metadata * ) dst, ( const struct ofp_instruction_write_metadata * ) src );
    }
    break;

    case OFPIT_WRITE_ACTIONS:
    case OFPIT_APPLY_ACTIONS:
    case OFPIT_CLEAR_ACTIONS:
    {
      hton_instruction_actions( ( struct ofp_instruction_actions * ) dst, ( const struct ofp_instruction_actions * ) src );
    }
    break;

    case OFPIT_METER:
    {
      hton_instruction_meter( ( struct ofp_instruction_meter * ) dst, ( const struct ofp_instruction_meter * ) src );
    }
    break;

    case OFPIT_EXPERIMENTER:
    {
      hton_instruction_experimenter( ( struct ofp_instruction_experimenter * ) dst, ( const struct ofp_instruction_experimenter * ) src );
    }
    break;

    default:
    {
      die( "Undefined instruction type ( type = %#x ).", src->type );
    }
    break;
  }
}


void
ntoh_instruction_goto_table( struct ofp_instruction_goto_table *dst, const struct ofp_instruction_goto_table *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  dst->table_id = src->table_id;
  memset( &dst->pad, 0, sizeof( dst->pad ) );
}


void
ntoh_instruction_write_metadata( struct ofp_instruction_write_metadata *dst, const struct ofp_instruction_write_metadata *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  memset( &dst->pad, 0, sizeof( dst->pad ) );
  dst->metadata = ntohll( src->metadata );
  dst->metadata_mask = ntohll( src->metadata_mask );
}


void
ntoh_instruction_actions( struct ofp_instruction_actions *dst, const struct ofp_instruction_actions *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->len ) != 0 );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  memset( &dst->pad, 0, sizeof( dst->pad ) );

  size_t offset = offsetof( struct ofp_instruction_actions, actions );
  size_t actions_length = dst->len - offset;

  while ( actions_length >= sizeof( struct ofp_action_header ) ) {
    const struct ofp_action_header *ah_src = ( const struct ofp_action_header * ) ( ( const char * ) src + offset );
    struct ofp_action_header *ah_dst = ( struct ofp_action_header * ) ( ( char * ) dst + offset );

    uint16_t part_length = ntohs( ah_src->len );
    if ( actions_length < part_length ) {
      break;
    }
    ntoh_action( ah_dst, ah_src );

    actions_length -= part_length;
    offset += part_length;
  }
}


void
hton_instruction_actions( struct ofp_instruction_actions *dst, const struct ofp_instruction_actions *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->len != 0 );

  dst->type = htons( src->type );
  dst->len = htons( src->len );
  memset( &dst->pad, 0, sizeof( dst->pad ) );

  size_t offset = offsetof( struct ofp_instruction_actions, actions );
  size_t actions_length = ntohs( dst->len ) - offset;

  while ( actions_length >= sizeof( struct ofp_action_header ) ) {
    const struct ofp_action_header *ah_src = ( const struct ofp_action_header * ) ( ( const char * ) src + offset );
    struct ofp_action_header *ah_dst = ( struct ofp_action_header * ) ( ( char * ) dst + offset );

    uint16_t part_length = ah_src->len;
    if ( actions_length < part_length ) {
      break;
    }
    hton_action( ah_dst, ah_src );

    actions_length -= part_length;
    offset += part_length;
  }
}


void
ntoh_instruction_meter( struct ofp_instruction_meter *dst, const struct ofp_instruction_meter *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  dst->meter_id = ntohl( src->meter_id );
}


void
ntoh_instruction_experimenter( struct ofp_instruction_experimenter *dst, const struct ofp_instruction_experimenter *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  dst->experimenter = ntohl( src->experimenter );

  uint16_t offset = sizeof( struct ofp_instruction_experimenter );
  if ( dst->len > offset ) {
    uint16_t data_length = ( uint16_t ) ( dst->len - offset );
    memmove( ( char * ) dst + offset, ( const char * ) src + offset, data_length );
  }
}


void
hton_instruction_experimenter( struct ofp_instruction_experimenter *dst, const struct ofp_instruction_experimenter *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = htons( src->type );
  dst->len = htons( src->len );
  dst->experimenter = htonl( src->experimenter );

  uint16_t offset = sizeof( struct ofp_instruction_experimenter );
  if ( ntohs( dst->len ) > offset ) {
    uint16_t data_length = ( uint16_t ) ( ntohs( dst->len ) - offset );
    memmove( ( char * ) dst + offset, ( const char * ) src + offset, data_length );
  }
}


void ntoh_bucket( struct ofp_bucket *dst, const struct ofp_bucket *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->len ) != 0 );

  dst->len = ntohs( src->len );
  dst->weight = ntohs( src->weight );
  dst->watch_port = ntohl( src->watch_port );
  dst->watch_group = ntohl( src->watch_group );
  memset( &dst->pad, 0, sizeof( dst->pad ) );

  size_t offset = offsetof( struct ofp_bucket, actions );
  size_t actions_length = dst->len - offset;

  while ( actions_length >= sizeof( struct ofp_action_header ) ) {
    const struct ofp_action_header *ah_src = ( const struct ofp_action_header * ) ( ( const char * ) src + offset );
    struct ofp_action_header *ah_dst = ( struct ofp_action_header * ) ( ( char * ) dst + offset );

    uint16_t part_length = ntohs( ah_src->len );
    if ( actions_length < part_length ) {
      break;
    }
    ntoh_action( ah_dst, ah_src );

    actions_length -= part_length;
    offset += part_length;
  }
}


void hton_bucket( struct ofp_bucket *dst, const struct ofp_bucket *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->len != 0 );

  dst->len = htons( src->len );
  dst->weight = htons( src->weight );
  dst->watch_port = htonl( src->watch_port );
  dst->watch_group = htonl( src->watch_group );
  memset( &dst->pad, 0, sizeof( dst->pad ) );

  size_t offset = offsetof( struct ofp_bucket, actions );
  size_t actions_length = ntohs( dst->len ) - offset;

  while ( actions_length >= sizeof( struct ofp_action_header ) ) {
    const struct ofp_action_header *ah_src = ( const struct ofp_action_header * ) ( ( const char * ) src + offset );
    struct ofp_action_header *ah_dst = ( struct ofp_action_header * ) ( ( char * ) dst + offset );

    uint16_t part_length = ah_src->len;
    if ( actions_length < part_length ) {
      break;
    }
    hton_action( ah_dst, ah_src );

    actions_length -= part_length;
    offset += part_length;
  }
}


void ntoh_meter_band_drop( struct ofp_meter_band_drop *dst, const struct ofp_meter_band_drop *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  dst->rate = ntohl( src->rate );
  dst->burst_size = ntohl( src->burst_size );
  memset( &dst->pad, 0, sizeof( dst->pad ) );
}


void ntoh_meter_band_dscp_remark( struct ofp_meter_band_dscp_remark *dst, const struct ofp_meter_band_dscp_remark *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  dst->rate = ntohl( src->rate );
  dst->burst_size = ntohl( src->burst_size );
  dst->prec_level = src->prec_level;
  memset( &dst->pad, 0, sizeof( dst->pad ) );
}


void ntoh_meter_band_experimenter( struct ofp_meter_band_experimenter *dst, const struct ofp_meter_band_experimenter *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  dst->rate = ntohl( src->rate );
  dst->burst_size = ntohl( src->burst_size );
  dst->experimenter = ntohl( src->experimenter );

  uint16_t offset = sizeof( struct ofp_meter_band_experimenter );
  if ( dst->len > offset ) {
    uint16_t data_length = ( uint16_t ) ( dst->len - offset );
    memmove( ( char * ) dst + offset, ( const char * ) src + offset, data_length );
  }
}


void hton_meter_band_experimenter( struct ofp_meter_band_experimenter *dst, const struct ofp_meter_band_experimenter *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = htons( src->type );
  dst->len = htons( src->len );
  dst->rate = htonl( src->rate );
  dst->burst_size = htonl( src->burst_size );
  dst->experimenter = htonl( src->experimenter );

  uint16_t offset = sizeof( struct ofp_meter_band_experimenter );
  if ( ntohs( dst->len ) > offset ) {
    uint16_t data_length = ( uint16_t ) ( ntohs( dst->len ) - offset );
    memmove( ( char * ) dst + offset, ( const char * ) src + offset, data_length );
  }
}


void ntoh_meter_band_header( struct ofp_meter_band_header *dst, const struct ofp_meter_band_header *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  switch ( ntohs( src->type ) ) {
    case OFPMBT_DROP:
    {
      ntoh_meter_band_drop( ( struct ofp_meter_band_drop * ) dst, ( const struct ofp_meter_band_drop * ) src );
    }
    break;

    case OFPMBT_DSCP_REMARK:
    {
      ntoh_meter_band_dscp_remark( ( struct ofp_meter_band_dscp_remark * ) dst, ( const struct ofp_meter_band_dscp_remark * ) src );
    }
    break;

    case OFPMBT_EXPERIMENTER:
    {
      ntoh_meter_band_experimenter( ( struct ofp_meter_band_experimenter * ) dst, ( const struct ofp_meter_band_experimenter * ) src );
    }
    break;

    default:
    {
      die( "Undefined meter band type ( type = %#x ).", ntohs( src->type ) );
    }
    break;
  }
}


void hton_meter_band_header( struct ofp_meter_band_header *dst, const struct ofp_meter_band_header *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  switch ( src->type ) {
    case OFPMBT_DROP:
    {
      hton_meter_band_drop( ( struct ofp_meter_band_drop * ) dst, ( const struct ofp_meter_band_drop * ) src );
    }
    break;

    case OFPMBT_DSCP_REMARK:
    {
      hton_meter_band_dscp_remark( ( struct ofp_meter_band_dscp_remark * ) dst, ( const struct ofp_meter_band_dscp_remark * ) src );
    }
    break;

    case OFPMBT_EXPERIMENTER:
    {
      hton_meter_band_experimenter( ( struct ofp_meter_band_experimenter * ) dst, ( const struct ofp_meter_band_experimenter * ) src );
    }
    break;

    default:
    {
      die( "Undefined meter band type ( type = %#x ).", src->type );
    }
    break;
  }
}


void ntoh_table_feature_prop_instructions( struct ofp_table_feature_prop_instructions *dst, const struct ofp_table_feature_prop_instructions *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->length ) != 0 );

  dst->type = ntohs( src->type );
  dst->length = ntohs( src->length );

  size_t offset = offsetof( struct ofp_table_feature_prop_instructions, instruction_ids );
  size_t instructions_length = dst->length - offset;

  while ( instructions_length >= sizeof( struct ofp_instruction ) ) {
    const struct ofp_instruction *inst_src = ( const struct ofp_instruction * ) ( ( const char * ) src + offset );
    struct ofp_instruction *inst_dst = ( struct ofp_instruction * ) ( ( char * ) dst + offset );

    uint16_t part_length = ntohs( inst_src->len );
    if ( instructions_length < part_length ) {
      break;
    }
    ntoh_instruction( inst_dst, inst_src );

    instructions_length -= part_length;
    offset += part_length;
  }

  size_t padding_length = ( size_t ) PADLEN_TO_64( dst->length );
  if ( padding_length > 0 ) {
    memset( ( char * ) dst + dst->length, 0, padding_length );
  }
}


void hton_table_feature_prop_instructions( struct ofp_table_feature_prop_instructions *dst, const struct ofp_table_feature_prop_instructions *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->length != 0 );

  dst->type = htons( src->type );
  dst->length = htons( src->length );

  size_t offset = offsetof( struct ofp_table_feature_prop_instructions, instruction_ids );
  size_t instructions_length = ntohs( dst->length ) - offset;

  while ( instructions_length >= sizeof( struct ofp_instruction ) ) {
    const struct ofp_instruction *inst_src = ( const struct ofp_instruction * ) ( ( const char * ) src + offset );
    struct ofp_instruction *inst_dst = ( struct ofp_instruction * ) ( ( char * ) dst + offset );

    uint16_t part_length = inst_src->len;
    if ( instructions_length < part_length ) {
      break;
    }
    hton_instruction( inst_dst, inst_src );

    instructions_length -= part_length;
    offset += part_length;
  }

  size_t padding_length = ( size_t ) PADLEN_TO_64( ntohs( dst->length ) );
  if ( padding_length > 0 ) {
    memset( ( char * ) dst + ntohs( dst->length ), 0, padding_length );
  }
}


void ntoh_table_feature_prop_next_tables( struct ofp_table_feature_prop_next_tables *dst, const struct ofp_table_feature_prop_next_tables *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->length ) != 0 );

  dst->type = ntohs( src->type );
  dst->length = ntohs( src->length );

  size_t offset = offsetof( struct ofp_table_feature_prop_next_tables, next_table_ids );
  size_t table_length = dst->length - offset;
  memmove( ( char * ) dst + offset, ( const char * ) src + offset, table_length );
  size_t padding_length = ( size_t ) PADLEN_TO_64( dst->length );
  if ( padding_length > 0 ) {
    memset( ( char * ) dst + dst->length, 0, padding_length );
  }
}


void hton_table_feature_prop_next_tables( struct ofp_table_feature_prop_next_tables *dst, const struct ofp_table_feature_prop_next_tables *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->length != 0 );

  dst->type = htons( src->type );
  dst->length = htons( src->length );

  size_t offset = offsetof( struct ofp_table_feature_prop_next_tables, next_table_ids );
  size_t table_length = ntohs( dst->length ) - offset;
  memmove( ( char * ) dst + offset, ( const char * ) src + offset, table_length );
  size_t padding_length = ( size_t ) PADLEN_TO_64( ntohs( dst->length ) );
  if ( padding_length > 0 ) {
    memset( ( char * ) dst + ntohs( dst->length ), 0, padding_length );
  }
}


void ntoh_table_feature_prop_actions( struct ofp_table_feature_prop_actions *dst, const struct ofp_table_feature_prop_actions *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->length ) != 0 );

  dst->type = ntohs( src->type );
  dst->length = ntohs( src->length );

  size_t offset = offsetof( struct ofp_table_feature_prop_actions, action_ids );
  size_t actions_length = dst->length - offset;

  while ( actions_length >= sizeof( struct ofp_action_header ) ) {
    const struct ofp_action_header *act_src = ( const struct ofp_action_header * ) ( ( const char * ) src + offset );
    struct ofp_action_header *act_dst = ( struct ofp_action_header * ) ( ( char * ) dst + offset );

    uint16_t part_length = ntohs( act_src->len );
    if ( actions_length < part_length ) {
      break;
    }
    ntoh_action( act_dst, act_src );

    actions_length -= part_length;
    offset += part_length;
  }

  size_t padding_length = ( size_t ) PADLEN_TO_64( dst->length );
  if ( padding_length > 0 ) {
    memset( ( char * ) dst + dst->length, 0, padding_length );
  }
}


void hton_table_feature_prop_actions( struct ofp_table_feature_prop_actions *dst, const struct ofp_table_feature_prop_actions *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->length != 0 );

  dst->type = htons( src->type );
  dst->length = htons( src->length );

  size_t offset = offsetof( struct ofp_table_feature_prop_actions, action_ids );
  size_t actions_length = ntohs( dst->length ) - offset;

  while ( actions_length >= sizeof( struct ofp_action_header ) ) {
    const struct ofp_action_header *act_src = ( const struct ofp_action_header * ) ( ( const char * ) src + offset );
    struct ofp_action_header *act_dst = ( struct ofp_action_header * ) ( ( char * ) dst + offset );

    uint16_t part_length = act_src->len;
    if ( actions_length < part_length ) {
      break;
    }
    hton_action( act_dst, act_src );

    actions_length -= part_length;
    offset += part_length;
  }

  size_t padding_length = ( size_t ) PADLEN_TO_64( ntohs( dst->length ) );
  if ( padding_length > 0 ) {
    memset( ( char * ) dst + ntohs( dst->length ), 0, padding_length );
  }
}


void ntoh_table_feature_prop_oxm( struct ofp_table_feature_prop_oxm *dst, const struct ofp_table_feature_prop_oxm *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->length ) != 0 );

  dst->type = ntohs( src->type );
  dst->length = ntohs( src->length );

  size_t offset = offsetof( struct ofp_table_feature_prop_oxm, oxm_ids );
  size_t oxm_length = dst->length - offset;

  int i = 0;
  while ( oxm_length >= sizeof( uint32_t ) ) {
    dst->oxm_ids[ i ] = ntohl( src->oxm_ids[ i ] );
    oxm_length -= sizeof( uint32_t );
    i++;
  }

  size_t padding_length = ( size_t ) PADLEN_TO_64( dst->length );
  if ( padding_length > 0 ) {
    memset( ( char * ) dst + dst->length, 0, padding_length );
  }
}


void hton_table_feature_prop_oxm( struct ofp_table_feature_prop_oxm *dst, const struct ofp_table_feature_prop_oxm *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->length != 0 );

  dst->type = htons( src->type );
  dst->length = htons( src->length );

  size_t offset = offsetof( struct ofp_table_feature_prop_oxm, oxm_ids );
  size_t oxm_length = ntohs( dst->length ) - offset;

  int i = 0;
  while ( oxm_length >= sizeof( uint32_t ) ) {
    dst->oxm_ids[ i ] = htonl( src->oxm_ids[ i ] );
    oxm_length -= sizeof( uint32_t );
    i++;
  }

  size_t padding_length = ( size_t ) PADLEN_TO_64( ntohs( dst->length ) );
  if ( padding_length > 0 ) {
    memset( ( char * ) dst + ntohs( dst->length ), 0, padding_length );
  }
}


void ntoh_table_feature_prop_experimenter( struct ofp_table_feature_prop_experimenter *dst, const struct ofp_table_feature_prop_experimenter *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->length = ntohs( src->length );
  dst->experimenter = ntohl( src->experimenter );
  dst->exp_type = ntohl( src->exp_type );

  uint16_t offset = offsetof( struct ofp_table_feature_prop_experimenter, experimenter_data );
  if ( dst->length > offset ) {
    uint16_t data_length = ( uint16_t ) ( dst->length - offset );
    memmove( dst->experimenter_data, src->experimenter_data, data_length );
  }

  size_t padding_length = ( size_t ) PADLEN_TO_64( dst->length );
  if ( padding_length > 0 ) {
    memset( ( char * ) dst + dst->length, 0, padding_length );
  }
}


void hton_table_feature_prop_experimenter( struct ofp_table_feature_prop_experimenter *dst, const struct ofp_table_feature_prop_experimenter *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = htons( src->type );
  dst->length = htons( src->length );
  dst->experimenter = htonl( src->experimenter );
  dst->exp_type = htonl( src->exp_type );

  uint16_t offset = offsetof( struct ofp_table_feature_prop_experimenter, experimenter_data );
  if ( ntohs( dst->length ) > offset ) {
    uint16_t data_length = ( uint16_t ) ( ntohs( dst->length ) - offset );
    memmove( dst->experimenter_data, src->experimenter_data, data_length );
  }

  size_t padding_length = ( size_t ) PADLEN_TO_64( ntohs( dst->length ) );
  if ( padding_length > 0 ) {
    memset( ( char * ) dst + ntohs( dst->length ), 0, padding_length );
  }
}


void ntoh_table_feature_prop_header( struct ofp_table_feature_prop_header *dst, const struct ofp_table_feature_prop_header *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  switch ( ntohs( src->type ) ) {
    case OFPTFPT_INSTRUCTIONS:
    case OFPTFPT_INSTRUCTIONS_MISS:
    {
      ntoh_table_feature_prop_instructions( ( struct ofp_table_feature_prop_instructions * ) dst, ( const struct ofp_table_feature_prop_instructions * ) src );
    }
    break;

    case OFPTFPT_NEXT_TABLES:
    case OFPTFPT_NEXT_TABLES_MISS:
    {
      ntoh_table_feature_prop_next_tables( ( struct ofp_table_feature_prop_next_tables * ) dst, ( const struct ofp_table_feature_prop_next_tables * ) src );
    }
    break;

    case OFPTFPT_WRITE_ACTIONS:
    case OFPTFPT_WRITE_ACTIONS_MISS:
    case OFPTFPT_APPLY_ACTIONS:
    case OFPTFPT_APPLY_ACTIONS_MISS:
    {
      ntoh_table_feature_prop_actions( ( struct ofp_table_feature_prop_actions * ) dst, ( const struct ofp_table_feature_prop_actions * ) src );
    }
    break;

    case OFPTFPT_MATCH:
    case OFPTFPT_WILDCARDS:
    case OFPTFPT_WRITE_SETFIELD:
    case OFPTFPT_WRITE_SETFIELD_MISS:
    case OFPTFPT_APPLY_SETFIELD:
    case OFPTFPT_APPLY_SETFIELD_MISS:
    {
      ntoh_table_feature_prop_oxm( ( struct ofp_table_feature_prop_oxm * ) dst, ( const struct ofp_table_feature_prop_oxm * ) src );
    }
    break;

    case OFPTFPT_EXPERIMENTER:
    case OFPTFPT_EXPERIMENTER_MISS:
    {
      ntoh_table_feature_prop_experimenter( ( struct ofp_table_feature_prop_experimenter * ) dst, ( const struct ofp_table_feature_prop_experimenter * ) src );
    }
    break;

    default:
    {
      die( "Undefined table feature property type ( type = %#x ).", ntohs( src->type ) );
    }
    break;
  }
}


void hton_table_feature_prop_header( struct ofp_table_feature_prop_header *dst, const struct ofp_table_feature_prop_header *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  switch ( src->type ) {
    case OFPTFPT_INSTRUCTIONS:
    case OFPTFPT_INSTRUCTIONS_MISS:
    {
      hton_table_feature_prop_instructions( ( struct ofp_table_feature_prop_instructions * ) dst, ( const struct ofp_table_feature_prop_instructions * ) src );
    }
    break;

    case OFPTFPT_NEXT_TABLES:
    case OFPTFPT_NEXT_TABLES_MISS:
    {
      hton_table_feature_prop_next_tables( ( struct ofp_table_feature_prop_next_tables * ) dst, ( const struct ofp_table_feature_prop_next_tables * ) src );
    }
    break;

    case OFPTFPT_WRITE_ACTIONS:
    case OFPTFPT_WRITE_ACTIONS_MISS:
    case OFPTFPT_APPLY_ACTIONS:
    case OFPTFPT_APPLY_ACTIONS_MISS:
    {
      hton_table_feature_prop_actions( ( struct ofp_table_feature_prop_actions * ) dst, ( const struct ofp_table_feature_prop_actions * ) src );
    }
    break;

    case OFPTFPT_MATCH:
    case OFPTFPT_WILDCARDS:
    case OFPTFPT_WRITE_SETFIELD:
    case OFPTFPT_WRITE_SETFIELD_MISS:
    case OFPTFPT_APPLY_SETFIELD:
    case OFPTFPT_APPLY_SETFIELD_MISS:
    {
      hton_table_feature_prop_oxm( ( struct ofp_table_feature_prop_oxm * ) dst, ( const struct ofp_table_feature_prop_oxm * ) src );
    }
    break;

    case OFPTFPT_EXPERIMENTER:
    case OFPTFPT_EXPERIMENTER_MISS:
    {
      hton_table_feature_prop_experimenter( ( struct ofp_table_feature_prop_experimenter * ) dst, ( const struct ofp_table_feature_prop_experimenter * ) src );
    }
    break;

    default:
    {
      die( "Undefined table feature property type ( type = %#x ).", src->type );
    }
    break;
  }
}


void ntoh_table_features( struct ofp_table_features *dst, const struct ofp_table_features *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->length ) != 0 );

  dst->length = ntohs( src->length );
  dst->table_id = src->table_id;
  memset( &dst->pad, 0, sizeof( dst->pad ) );
  memmove( dst->name, src->name, OFP_MAX_TABLE_NAME_LEN );
  dst->metadata_match = ntohll( src->metadata_match );
  dst->metadata_write = ntohll( src->metadata_write );
  dst->config = ntohl( src->config );
  dst->max_entries = ntohl( src->max_entries );

  size_t offset = offsetof( struct ofp_table_features, properties );
  size_t table_features_length = dst->length - offset;

  while ( table_features_length >= sizeof( struct ofp_table_feature_prop_header ) ) {
    const struct ofp_table_feature_prop_header *ph_src = ( const struct ofp_table_feature_prop_header * ) ( ( const char * ) src + offset );
    struct ofp_table_feature_prop_header *ph_dst = ( struct ofp_table_feature_prop_header * ) ( ( char * ) dst + offset );

    uint16_t part_length = ( uint16_t ) ( ntohs( ph_src->length ) + PADLEN_TO_64( ntohs( ph_src->length ) ) );
    if ( table_features_length < part_length ) {
      break;
    }
    ntoh_table_feature_prop_header( ph_dst, ph_src );

    table_features_length -= part_length;
    offset += part_length;
  }
}


void hton_table_features( struct ofp_table_features *dst, const struct ofp_table_features *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->length != 0 );

  dst->length = htons( src->length );
  dst->table_id = src->table_id;
  memset( &dst->pad, 0, sizeof( dst->pad ) );
  memmove( dst->name, src->name, OFP_MAX_TABLE_NAME_LEN );
  dst->metadata_match = htonll( src->metadata_match );
  dst->metadata_write = htonll( src->metadata_write );
  dst->config = htonl( src->config );
  dst->max_entries = htonl( src->max_entries );

  size_t offset = offsetof( struct ofp_table_features, properties );
  size_t table_features_length = ntohs( dst->length ) - offset;

  while ( table_features_length >= sizeof( struct ofp_table_feature_prop_header ) ) {
    const struct ofp_table_feature_prop_header *ph_src = ( const struct ofp_table_feature_prop_header * ) ( ( const char * ) src + offset );
    struct ofp_table_feature_prop_header *ph_dst = ( struct ofp_table_feature_prop_header * ) ( ( char * ) dst + offset );

    uint16_t part_length = ( uint16_t ) ( ph_src->length + PADLEN_TO_64( ph_src->length ) );
    if ( table_features_length < part_length ) {
      break;
    }
    hton_table_feature_prop_header( ph_dst, ph_src );

    table_features_length -= part_length;
    offset += part_length;
  }
}


void ntoh_bucket_counter( struct ofp_bucket_counter *dst, const struct ofp_bucket_counter *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->packet_count = ntohll( src->packet_count );
  dst->byte_count = ntohll( src->byte_count );
}


void ntoh_group_stats( struct ofp_group_stats *dst, const struct ofp_group_stats *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->length ) != 0 );

  dst->length = ntohs( src->length );
  memset( &dst->pad, 0, sizeof( dst->pad ) );
  dst->group_id = ntohl( src->group_id );
  dst->ref_count = ntohl( src->ref_count );
  memset( &dst->pad2, 0, sizeof( dst->pad2 ) );
  dst->packet_count = ntohll( src->packet_count );
  dst->byte_count = ntohll( src->byte_count );
  dst->duration_sec = ntohl( src->duration_sec );
  dst->duration_nsec = ntohl( src->duration_nsec );

  size_t offset = offsetof( struct ofp_group_stats, bucket_stats );
  size_t stats_length = dst->length - offset;

  while ( stats_length >= sizeof( struct ofp_bucket_counter ) ) {
    const struct ofp_bucket_counter *bc_src = ( const struct ofp_bucket_counter * ) ( ( const char * ) src + offset );
    struct ofp_bucket_counter *bc_dst = ( struct ofp_bucket_counter * ) ( ( char * ) dst + offset );

    ntoh_bucket_counter( bc_dst, bc_src );

    stats_length -= sizeof( struct ofp_bucket_counter );
    offset += sizeof( struct ofp_bucket_counter );
  }
}


void hton_group_stats( struct ofp_group_stats *dst, const struct ofp_group_stats *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->length != 0 );

  dst->length = htons( src->length );
  memset( &dst->pad, 0, sizeof( dst->pad ) );
  dst->group_id = htonl( src->group_id );
  dst->ref_count = htonl( src->ref_count );
  memset( &dst->pad2, 0, sizeof( dst->pad2 ) );
  dst->packet_count = htonll( src->packet_count );
  dst->byte_count = htonll( src->byte_count );
  dst->duration_sec = htonl( src->duration_sec );
  dst->duration_nsec = htonl( src->duration_nsec );

  size_t offset = offsetof( struct ofp_group_stats, bucket_stats );
  size_t stats_length = ntohs( dst->length ) - offset;

  while ( stats_length >= sizeof( struct ofp_bucket_counter ) ) {
    const struct ofp_bucket_counter *bc_src = ( const struct ofp_bucket_counter * ) ( ( const char * ) src + offset );
    struct ofp_bucket_counter *bc_dst = ( struct ofp_bucket_counter * ) ( ( char * ) dst + offset );

    hton_bucket_counter( bc_dst, bc_src );

    stats_length -= sizeof( struct ofp_bucket_counter );
    offset += sizeof( struct ofp_bucket_counter );
  }
}


void ntoh_group_desc( struct ofp_group_desc *dst, const struct ofp_group_desc *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->length ) != 0 );

  dst->length = ntohs( src->length );
  dst->type = src->type;
  dst->pad = 0;
  dst->group_id = ntohl( src->group_id );

  size_t offset = offsetof( struct ofp_group_desc, buckets );
  size_t buckets_length = dst->length - offset;

  while ( buckets_length >= sizeof( struct ofp_bucket ) ) {
    const struct ofp_bucket *bc_src = ( const struct ofp_bucket * ) ( ( const char * ) src + offset );
    struct ofp_bucket *bc_dst = ( struct ofp_bucket * ) ( ( char * ) dst + offset );

    uint16_t part_length = ntohs( bc_src->len );
    if ( buckets_length < part_length ) {
      break;
    }
    ntoh_bucket( bc_dst, bc_src );

    buckets_length -= part_length;
    offset += part_length;
  }
}


void hton_group_desc( struct ofp_group_desc *dst, const struct ofp_group_desc *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->length != 0 );

  dst->length = htons( src->length );
  dst->type = src->type;
  dst->pad = 0;
  dst->group_id = htonl( src->group_id );

  size_t offset = offsetof( struct ofp_group_desc, buckets );
  size_t buckets_length = ntohs( dst->length ) - offset;

  while ( buckets_length >= sizeof( struct ofp_bucket ) ) {
    const struct ofp_bucket *bc_src = ( const struct ofp_bucket * ) ( ( const char * ) src + offset );
    struct ofp_bucket *bc_dst = ( struct ofp_bucket * ) ( ( char * ) dst + offset );

    uint16_t part_length = bc_src->len;
    if ( buckets_length < part_length ) {
      break;
    }
    hton_bucket( bc_dst, bc_src );

    buckets_length -= part_length;
    offset += part_length;
  }
}


void ntoh_group_features_stats( struct ofp_group_features *dst, const struct ofp_group_features *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->types = ntohl( src->types );
  dst->capabilities = ntohl( src->capabilities );

  for ( int i = 0; i < 4; i++ ) {
    dst->max_groups[ i ] = ntohl( src->max_groups[ i ] );
    dst->actions[ i ] = ntohl( src->actions[ i ] );
  }
}


void ntoh_meter_band_stats( struct ofp_meter_band_stats *dst, const struct ofp_meter_band_stats *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->packet_band_count = ntohll( src->packet_band_count );
  dst->byte_band_count = ntohll( src->byte_band_count );
}


void ntoh_meter_stats( struct ofp_meter_stats *dst, const struct ofp_meter_stats *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->len ) != 0 );

  dst->meter_id = ntohl( src->meter_id );
  dst->len = ntohs( src->len );
  memset( &dst->pad, 0, sizeof( dst->pad ) );
  dst->flow_count = ntohl( src->flow_count );
  dst->packet_in_count = ntohll( src->packet_in_count );
  dst->byte_in_count = ntohll( src->byte_in_count );
  dst->duration_sec = ntohl( src->duration_sec );
  dst->duration_nsec = ntohl( src->duration_nsec );

  size_t offset = offsetof( struct ofp_meter_stats, band_stats );
  size_t stats_length = dst->len - offset;

  while ( stats_length >= sizeof( struct ofp_meter_band_stats ) ) {
    const struct ofp_meter_band_stats *bs_src = ( const struct ofp_meter_band_stats * ) ( ( const char * ) src + offset );
    struct ofp_meter_band_stats *bs_dst = ( struct ofp_meter_band_stats * ) ( ( char * ) dst + offset );

    ntoh_meter_band_stats( bs_dst, bs_src );

    stats_length -= sizeof( struct ofp_meter_band_stats );
    offset += sizeof( struct ofp_meter_band_stats );
  }
}


void hton_meter_stats( struct ofp_meter_stats *dst, const struct ofp_meter_stats *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->len != 0 );

  dst->meter_id = htonl( src->meter_id );
  dst->len = htons( src->len );
  memset( &dst->pad, 0, sizeof( dst->pad ) );
  dst->flow_count = htonl( src->flow_count );
  dst->packet_in_count = htonll( src->packet_in_count );
  dst->byte_in_count = htonll( src->byte_in_count );
  dst->duration_sec = htonl( src->duration_sec );
  dst->duration_nsec = htonl( src->duration_nsec );

  size_t offset = offsetof( struct ofp_meter_stats, band_stats );
  size_t stats_length = ntohs( dst->len ) - offset;

  while ( stats_length >= sizeof( struct ofp_meter_band_stats ) ) {
    const struct ofp_meter_band_stats *bs_src = ( const struct ofp_meter_band_stats * ) ( ( const char * ) src + offset );
    struct ofp_meter_band_stats *bs_dst = ( struct ofp_meter_band_stats * ) ( ( char * ) dst + offset );

    hton_meter_band_stats( bs_dst, bs_src );

    stats_length -= sizeof( struct ofp_meter_band_stats );
    offset += sizeof( struct ofp_meter_band_stats );
  }
}


void ntoh_meter_config( struct ofp_meter_config *dst, const struct ofp_meter_config *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->length ) != 0 );

  dst->length = ntohs( src->length );
  dst->flags = ntohs( src->flags );
  dst->meter_id = ntohl( src->meter_id );

  size_t offset = offsetof( struct ofp_meter_config, bands );
  size_t bands_length = dst->length - offset;

  while ( bands_length >= sizeof( struct ofp_meter_band_header ) ) {
    const struct ofp_meter_band_header *bh_src = ( const struct ofp_meter_band_header * ) ( ( const char * ) src + offset );
    struct ofp_meter_band_header *bh_dst = ( struct ofp_meter_band_header * ) ( ( char * ) dst + offset );

    uint16_t part_length = ntohs( bh_src->len );
    if ( bands_length < part_length ) {
      break;
    }

    ntoh_meter_band_header( bh_dst, bh_src );

    bands_length -= part_length;
    offset += part_length;
  }
}


void hton_meter_config( struct ofp_meter_config *dst, const struct ofp_meter_config *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->length != 0 );

  dst->length = htons( src->length );
  dst->flags = htons( src->flags );
  dst->meter_id = htonl( src->meter_id );

  size_t offset = offsetof( struct ofp_meter_config, bands );
  size_t bands_length = src->length - offset;

  while ( bands_length >= sizeof( struct ofp_meter_band_header ) ) {
    const struct ofp_meter_band_header *bh_src = ( const struct ofp_meter_band_header * ) ( ( const char * ) src + offset );
    struct ofp_meter_band_header *bh_dst = ( struct ofp_meter_band_header * ) ( ( char * ) dst + offset );

    uint16_t part_length = bh_src->len;
    if ( bands_length < part_length ) {
      break;
    }

    hton_meter_band_header( bh_dst, bh_src );

    bands_length -= part_length;
    offset += part_length;
  }
}


void ntoh_meter_features( struct ofp_meter_features *dst, const struct ofp_meter_features *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->max_meter = ntohl( src->max_meter );
  dst->band_types = ntohl( src->band_types );
  dst->capabilities = ntohl( src->capabilities );
  dst->max_bands = src->max_bands;
  dst->max_color = src->max_color;
  memset( &dst->pad, 0, sizeof( dst->pad ) );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
