/*
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
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include "byteorder.h"
#include "log.h"
#include "wrapper.h"
#include "oxm_byteorder.h"


void
ntoh_port( struct ofp_port *dst, const struct ofp_port *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->port_no = ntohl( src->port_no );
  memset( dst->pad, 0, sizeof( dst->pad ) );

  bcopy( src->hw_addr, dst->hw_addr, OFP_ETH_ALEN );
  memset( dst->pad2, 0, sizeof( dst->pad2 ) );

  bcopy( src->name, dst->name, OFP_MAX_PORT_NAME_LEN );

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
  memset( dst->pad, 0, sizeof( dst->pad ) );
}


void ntoh_action_set_field( struct ofp_action_set_field *dst, const struct ofp_action_set_field *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->len ) != 0 );

  oxm_match_header *d_oxm, *s_oxm;

  struct ofp_action_set_field *asf = xcalloc( 1, ntohs( src->len ) );
  memcpy( asf, src, ntohs( src->len ) );

  dst->type = ntohs( asf->type );
  dst->len = ntohs( asf->len );

  s_oxm = ( oxm_match_header * ) asf->field;
  d_oxm = ( oxm_match_header * ) dst->field;

  ntoh_oxm_match( d_oxm, s_oxm );

  xfree( asf );
}


void hton_action_set_field( struct ofp_action_set_field *dst, const struct ofp_action_set_field *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->len != 0 );

  oxm_match_header *d_oxm, *s_oxm;

  struct ofp_action_set_field *asf = xcalloc( 1, src->len );
  memcpy( asf, src, src->len );

  dst->type = htons( asf->type );
  dst->len = htons( asf->len );

  s_oxm = ( oxm_match_header * ) asf->field;
  d_oxm = ( oxm_match_header * ) dst->field;

  hton_oxm_match( d_oxm, s_oxm );

  xfree( asf );
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

  struct ofp_action_experimenter_header *eh = xcalloc( 1, ntohs( src->len ) );
  memcpy( eh, src, ntohs( src->len ) );

  dst->type = ntohs( eh->type );
  dst->len = ntohs( eh->len );
  dst->experimenter = ntohl( eh->experimenter );

  uint16_t offset = sizeof( struct ofp_action_experimenter_header );
  if ( dst->len > offset ) {
    uint16_t data_len = ( uint16_t ) ( dst->len - offset );
    memcpy( ( char * ) dst + offset, ( char * ) eh + offset, data_len );
  }

  xfree( eh );
}


void
hton_action_experimenter( struct ofp_action_experimenter_header *dst, const struct ofp_action_experimenter_header *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  uint16_t src_len = src->len;

  struct ofp_action_experimenter_header *eh = xcalloc( 1, src->len );
  memcpy( eh, src, src->len );

  dst->type = htons( eh->type );
  dst->len = htons( eh->len );
  dst->experimenter = htonl( eh->experimenter );

  uint16_t offset = sizeof( struct ofp_action_experimenter_header );
  if ( src_len > offset ) {
    uint16_t data_len = ( uint16_t ) ( src_len - offset );
    memcpy( ( char * ) dst + offset, ( char * ) eh + offset, data_len );
  }

  xfree( eh );
}


void
ntoh_action_mpls_ttl( struct ofp_action_mpls_ttl *dst, const struct ofp_action_mpls_ttl *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  dst->mpls_ttl = src->mpls_ttl;
  memset( dst->pad, 0, sizeof( dst->pad ) );
}


void
ntoh_action_push( struct ofp_action_push *dst, const struct ofp_action_push *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  dst->ethertype = ntohs( src->ethertype );
  memset( dst->pad, 0, sizeof( dst->pad ) );
}


void
ntoh_action_pop_mpls( struct ofp_action_pop_mpls *dst, const struct ofp_action_pop_mpls *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  dst->ethertype = ntohs( src->ethertype );
  memset( dst->pad, 0, sizeof( dst->pad ) );
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
  memset( dst->pad, 0, sizeof( dst->pad ) );
}


void
ntoh_action_header( struct ofp_action_header *dst, const struct ofp_action_header *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  memset( dst->pad, 0, sizeof( dst->pad ) );
}


void
ntoh_action( struct ofp_action_header *dst, const struct ofp_action_header *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  switch ( ntohs( src->type ) ) {
    case OFPAT_OUTPUT:
      ntoh_action_output( ( struct ofp_action_output * ) dst, ( const struct ofp_action_output * ) src );
      break;
    case OFPAT_COPY_TTL_OUT:
    case OFPAT_COPY_TTL_IN:
    case OFPAT_DEC_MPLS_TTL:
    case OFPAT_POP_VLAN:
    case OFPAT_POP_PBB:
    case OFPAT_DEC_NW_TTL:
      ntoh_action_header( dst, src );
      break;
    case OFPAT_SET_MPLS_TTL:
      ntoh_action_mpls_ttl( ( struct ofp_action_mpls_ttl * ) dst, ( const struct ofp_action_mpls_ttl * ) src );
      break;
    case OFPAT_PUSH_VLAN:
    case OFPAT_PUSH_MPLS:
    case OFPAT_PUSH_PBB:
      ntoh_action_push( ( struct ofp_action_push * ) dst, ( const struct ofp_action_push * ) src );
      break;
    case OFPAT_POP_MPLS:
      ntoh_action_pop_mpls( ( struct ofp_action_pop_mpls * ) dst, ( const struct ofp_action_pop_mpls * ) src );
      break;
    case OFPAT_SET_QUEUE:
      ntoh_action_set_queue( ( struct ofp_action_set_queue * ) dst, ( const struct ofp_action_set_queue * ) src );
      break;
    case OFPAT_GROUP:
      ntoh_action_group( ( struct ofp_action_group * ) dst, ( const struct ofp_action_group * ) src );
      break;
    case OFPAT_SET_NW_TTL:
      ntoh_action_nw_ttl( ( struct ofp_action_nw_ttl * ) dst, ( const struct ofp_action_nw_ttl * ) src );
      break;
    case OFPAT_SET_FIELD:
      ntoh_action_set_field( ( struct ofp_action_set_field * ) dst, ( const struct ofp_action_set_field * ) src );
      break;
    case OFPAT_EXPERIMENTER:
      ntoh_action_experimenter( ( struct ofp_action_experimenter_header * ) dst, ( const struct ofp_action_experimenter_header * ) src );
      break;
    default:
      die( "Undefined action type ( type = %d ).", ntohs( src->type ) );
      break;
  }
}


void
hton_action( struct ofp_action_header *dst, const struct ofp_action_header *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  switch ( src->type ) {
    case OFPAT_OUTPUT:
      hton_action_output( ( struct ofp_action_output * ) dst, ( const struct ofp_action_output * ) src );
      break;
    case OFPAT_COPY_TTL_OUT:
    case OFPAT_COPY_TTL_IN:
    case OFPAT_DEC_MPLS_TTL:
    case OFPAT_POP_VLAN:
    case OFPAT_POP_PBB:
    case OFPAT_DEC_NW_TTL:
      hton_action_header( dst, src );
      break;
    case OFPAT_SET_MPLS_TTL:
      hton_action_mpls_ttl( ( struct ofp_action_mpls_ttl * ) dst, ( const struct ofp_action_mpls_ttl * ) src );
      break;
    case OFPAT_PUSH_VLAN:
    case OFPAT_PUSH_MPLS:
    case OFPAT_PUSH_PBB:
      hton_action_push( ( struct ofp_action_push * ) dst, ( const struct ofp_action_push * ) src );
      break;
    case OFPAT_POP_MPLS:
      hton_action_pop_mpls( ( struct ofp_action_pop_mpls * ) dst, ( const struct ofp_action_pop_mpls * ) src );
      break;
    case OFPAT_SET_QUEUE:
      hton_action_set_queue( ( struct ofp_action_set_queue * ) dst, ( const struct ofp_action_set_queue * ) src );
      break;
    case OFPAT_GROUP:
      hton_action_group( ( struct ofp_action_group * ) dst, ( const struct ofp_action_group * ) src );
      break;
    case OFPAT_SET_NW_TTL:
      hton_action_nw_ttl( ( struct ofp_action_nw_ttl * ) dst, ( const struct ofp_action_nw_ttl * ) src );
      break;
    case OFPAT_SET_FIELD:
      hton_action_set_field( ( struct ofp_action_set_field * ) dst, ( const struct ofp_action_set_field * ) src );
      break;
    case OFPAT_EXPERIMENTER:
      hton_action_experimenter( ( struct ofp_action_experimenter_header * ) dst, ( const struct ofp_action_experimenter_header * ) src );
      break;
    default:
      die( "Undefined action type ( type = %d ).", src->type );
      break;
  }
}


void
ntoh_flow_stats( struct ofp_flow_stats *dst, const struct ofp_flow_stats *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->length ) != 0 );

  struct ofp_flow_stats *fs = xcalloc( 1, ntohs( src->length ) );
  memcpy( fs, src, ntohs( src->length ) );

  dst->length = ntohs( fs->length );
  dst->table_id = fs->table_id;
  dst->pad = 0;
  dst->duration_sec = ntohl( fs->duration_sec );
  dst->duration_nsec = ntohl( fs->duration_nsec );
  dst->priority = ntohs( fs->priority );
  dst->idle_timeout = ntohs( fs->idle_timeout );
  dst->hard_timeout = ntohs( fs->hard_timeout );
  dst->flags = ntohs( fs->flags );
  memset( dst->pad2, 0, sizeof( dst->pad2 ) );
  dst->cookie = ntohll( fs->cookie );
  dst->packet_count = ntohll( fs->packet_count );
  dst->byte_count = ntohll( fs->byte_count );
  ntoh_match( &dst->match, &fs->match );

  uint16_t match_len = ( uint16_t ) ( dst->match.length + PADLEN_TO_64( dst->match.length ) );

  size_t offset = ( size_t ) ( offsetof( struct ofp_flow_stats, match ) + match_len );

  if ( dst->length >= offset ) {
    struct ofp_instruction *inst_src = ( struct ofp_instruction * ) ( ( char * ) fs + offset );
    struct ofp_instruction *inst_dst = ( struct ofp_instruction * ) ( ( char * ) dst + offset );

    uint16_t instructions_len = ( uint16_t ) ( dst->length - offset );
    uint16_t part_len;

    while ( instructions_len >= sizeof( struct ofp_instruction ) ) {
      part_len = ntohs( inst_src->len );
      if ( instructions_len < part_len ) {
        break;
      }
      ntoh_instruction( inst_dst, inst_src );

      instructions_len = ( uint16_t ) ( instructions_len - part_len );

      inst_src = ( struct ofp_instruction * ) ( ( char * ) inst_src + part_len );
      inst_dst = ( struct ofp_instruction * ) ( ( char * ) inst_dst + part_len );
    }
  }

  xfree( fs );
}


void
hton_flow_stats( struct ofp_flow_stats *dst, const struct ofp_flow_stats *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->length != 0 );

  uint16_t total_len = src->length;

  struct ofp_flow_stats *fs = xcalloc( 1, total_len );
  memcpy( fs, src, total_len );

  dst->length = htons( fs->length );
  dst->table_id = fs->table_id;
  dst->pad = 0;
  dst->duration_sec = htonl( fs->duration_sec );
  dst->duration_nsec = htonl( fs->duration_nsec );
  dst->priority = htons( fs->priority );
  dst->idle_timeout = htons( fs->idle_timeout );
  dst->hard_timeout = htons( fs->hard_timeout );
  dst->flags = htons( fs->flags );
  memset( dst->pad2, 0, sizeof( dst->pad2 ) );
  dst->cookie = htonll( fs->cookie );
  dst->packet_count = htonll( fs->packet_count );
  dst->byte_count = htonll( fs->byte_count );
  hton_match( &dst->match, &fs->match );

  uint16_t match_len = ( uint16_t ) ( src->match.length + PADLEN_TO_64( src->match.length ) );
  size_t offset = ( size_t ) ( offsetof( struct ofp_flow_stats, match ) + match_len );

  if ( total_len >= offset ) {
    struct ofp_instruction *inst_src = ( struct ofp_instruction * ) ( ( char * ) fs + offset );
    struct ofp_instruction *inst_dst = ( struct ofp_instruction * ) ( ( char * ) dst + offset );

    uint16_t instructions_len = ( uint16_t ) ( total_len - offset );
    uint16_t part_len;

    while ( instructions_len >= sizeof( struct ofp_instruction ) ) {
      part_len = inst_src->len;
      if ( instructions_len < part_len ) {
        break;
      }

      hton_instruction( inst_dst, inst_src );

      instructions_len = ( uint16_t ) ( instructions_len - part_len );

      inst_dst = ( struct ofp_instruction * ) ( ( char * ) inst_dst + part_len );
      inst_src = ( struct ofp_instruction * ) ( ( char * ) inst_src + part_len );
    }
  }

  xfree( fs );
}


void
ntoh_aggregate_stats( struct ofp_aggregate_stats_reply *dst, const struct ofp_aggregate_stats_reply *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->packet_count = ntohll( src->packet_count );
  dst->byte_count = ntohll( src->byte_count );
  dst->flow_count = ntohl( src->flow_count );
  memset( dst->pad, 0, sizeof( dst->pad ) );
}


void
ntoh_table_stats( struct ofp_table_stats *dst, const struct ofp_table_stats *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->table_id = src->table_id;
  memset( dst->pad, 0, sizeof( dst->pad ) );
  dst->active_count = ntohl( src->active_count );
  dst->lookup_count = ntohll( src->lookup_count );
  dst->matched_count = ntohll( src->matched_count );
}


void
ntoh_port_stats( struct ofp_port_stats *dst, const struct ofp_port_stats *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->port_no = ntohl( src->port_no );
  memset( dst->pad, 0, sizeof( dst->pad ) );
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

  struct ofp_queue_prop_header *ph = xcalloc( 1, ntohs( src->len ) );
  memcpy( ph, src, ntohs( src->len ) );

  dst->property = ntohs( ph->property );
  dst->len = ntohs( ph->len );
  
  if ( dst->property == OFPQT_MIN_RATE ) {
    struct ofp_queue_prop_min_rate *mr_src = ( struct ofp_queue_prop_min_rate * ) ph;
    struct ofp_queue_prop_min_rate *mr_dst = ( struct ofp_queue_prop_min_rate * ) dst;

    mr_dst->rate = ntohs( mr_src->rate );

  } else if ( dst->property == OFPQT_MAX_RATE ) {
    struct ofp_queue_prop_max_rate *mr_src = ( struct ofp_queue_prop_max_rate * ) ph;
    struct ofp_queue_prop_max_rate *mr_dst = ( struct ofp_queue_prop_max_rate * ) dst;

    mr_dst->rate = ntohs( mr_src->rate );

  } else if ( dst->property == OFPQT_EXPERIMENTER ) {
    struct ofp_queue_prop_experimenter *exp_src = ( struct ofp_queue_prop_experimenter * ) ph;
    struct ofp_queue_prop_experimenter *exp_dst = ( struct ofp_queue_prop_experimenter * ) dst;

    exp_dst->experimenter = ntohl( exp_src->experimenter );

    uint16_t offset = offsetof( struct ofp_queue_prop_experimenter, data );
    if ( dst->len > offset ) {
      uint16_t data_len = ( uint16_t ) ( dst->len - offset );
      memcpy( exp_dst->data, exp_src->data, data_len );
    }
  }

  xfree( ph );
}


void
hton_queue_property( struct ofp_queue_prop_header *dst, const struct ofp_queue_prop_header *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->len != 0 );

  struct ofp_queue_prop_header *ph = xcalloc( 1, src->len );
  memcpy( ph, src, src->len );

  uint16_t src_len = src->len;

  dst->property = htons( ph->property );
  dst->len = htons( ph->len );
  
  if ( src->property == OFPQT_MIN_RATE ) {
    struct ofp_queue_prop_min_rate *mr_src = ( struct ofp_queue_prop_min_rate * ) ph;
    struct ofp_queue_prop_min_rate *mr_dst = ( struct ofp_queue_prop_min_rate * ) dst;

    mr_dst->rate = htons( mr_src->rate );

  } else if ( src->property == OFPQT_MAX_RATE ) {
    struct ofp_queue_prop_max_rate *mr_src = ( struct ofp_queue_prop_max_rate * ) ph;
    struct ofp_queue_prop_max_rate *mr_dst = ( struct ofp_queue_prop_max_rate * ) dst;

    mr_dst->rate = htons( mr_src->rate );

  } else if ( src->property == OFPQT_EXPERIMENTER ) {
    struct ofp_queue_prop_experimenter *exp_src = ( struct ofp_queue_prop_experimenter * ) ph;
    struct ofp_queue_prop_experimenter *exp_dst = ( struct ofp_queue_prop_experimenter * ) dst;

    exp_dst->experimenter = htonl( exp_src->experimenter );

    uint16_t offset = offsetof( struct ofp_queue_prop_experimenter, data );
    if ( src_len > offset ) {
      uint16_t data_len = ( uint16_t ) ( src_len - offset );
      memcpy( exp_dst->data, exp_src->data, data_len );
    }
  }

  xfree( ph );
}


void
ntoh_packet_queue( struct ofp_packet_queue *dst, const struct ofp_packet_queue *src ) {
  /* Note that ofp_packet_queue is variable length.
   * Please make sure that dst and src have the same length.
   */
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->len ) != 0 );

  struct ofp_packet_queue *pq = xcalloc( 1, ntohs( src->len ) );
  memcpy( pq, src, ntohs( src->len ) );

  dst->queue_id = ntohl( pq->queue_id );
  dst->port = ntohl( pq->port );
  dst->len = ntohs( pq->len );
  memset( dst->pad, 0, sizeof( dst->pad ) );

  size_t offset = offsetof( struct ofp_packet_queue, properties );
  if ( dst->len >= offset ) {
    struct ofp_queue_prop_header *ph_src = ( struct ofp_queue_prop_header * ) ( ( char * ) pq + offset );
    struct ofp_queue_prop_header *ph_dst = ( struct ofp_queue_prop_header * ) ( ( char * ) dst + offset );

    uint16_t properties_length = ( uint16_t ) ( dst->len - offset );
    uint16_t part_len;

    while ( properties_length >= sizeof( struct ofp_queue_prop_header ) ) {
      part_len = ntohs( ph_src->len );
      if ( properties_length < part_len ) {
        break;
      }

      ntoh_queue_property( ph_dst, ph_src );

      properties_length = ( uint16_t ) ( properties_length - part_len );

      ph_src = ( struct ofp_queue_prop_header * ) ( ( char * ) ph_src + part_len );
      ph_dst = ( struct ofp_queue_prop_header * ) ( ( char * ) ph_dst + part_len );
    }
  }

  xfree( pq );
}


void
hton_packet_queue( struct ofp_packet_queue *dst, const struct ofp_packet_queue *src ) {
  /* Note that ofp_packet_queue is variable length.
   * Please make sure that dst and src have the same length.
   */
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->len != 0 );

  uint16_t total_len = src->len;
  struct ofp_packet_queue *pq = xcalloc( 1, total_len );
  memcpy( pq, src, total_len );

  dst->queue_id = htonl( pq->queue_id );
  dst->port = htonl( pq->port );
  dst->len = htons( pq->len );
  memset( dst->pad, 0, sizeof( dst->pad ) );

  size_t offset = offsetof( struct ofp_packet_queue, properties );
  if ( total_len >= offset ) {
    struct ofp_queue_prop_header *ph_src = ( struct ofp_queue_prop_header * ) ( ( char * ) pq + offset );
    struct ofp_queue_prop_header *ph_dst = ( struct ofp_queue_prop_header * ) ( ( char * ) dst + offset );

    uint16_t properties_length = ( uint16_t ) ( total_len - offset );
    uint16_t part_len;

    while ( properties_length >= sizeof( struct ofp_queue_prop_header ) ) {
      part_len = ph_src->len;
      if ( properties_length < part_len ) {
        break;
      }
      hton_queue_property( ph_dst, ph_src );

      properties_length = ( uint16_t ) ( properties_length - part_len );

      ph_dst = ( struct ofp_queue_prop_header * ) ( ( char * ) ph_dst + part_len );
      ph_src = ( struct ofp_queue_prop_header * ) ( ( char * ) ph_src + part_len );
    }
  }

  xfree( pq );
}


void
ntoh_instruction( struct ofp_instruction *dst, const struct ofp_instruction *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  switch ( ntohs( src->type ) ) {
    case OFPIT_GOTO_TABLE:
      ntoh_instruction_goto_table( ( struct ofp_instruction_goto_table * ) dst, ( const struct ofp_instruction_goto_table * ) src );
      break;
    case OFPIT_WRITE_METADATA:
      ntoh_instruction_write_metadata( ( struct ofp_instruction_write_metadata * ) dst, ( const struct ofp_instruction_write_metadata * ) src );
      break;
    case OFPIT_WRITE_ACTIONS:
    case OFPIT_APPLY_ACTIONS:
    case OFPIT_CLEAR_ACTIONS:
      ntoh_instruction_actions( ( struct ofp_instruction_actions * ) dst, ( const struct ofp_instruction_actions * ) src );
      break;
    case OFPIT_METER:
      ntoh_instruction_meter( ( struct ofp_instruction_meter * ) dst, ( const struct ofp_instruction_meter * ) src );
      break;
    case OFPIT_EXPERIMENTER:
      ntoh_instruction_experimenter( ( struct ofp_instruction_experimenter * ) dst, ( const struct ofp_instruction_experimenter * ) src );
      break;
    default:
      die( "Undefined instruction type ( type = %d ).", ntohs( src->type ) );
      break;
  }
}


void
hton_instruction( struct ofp_instruction *dst, const struct ofp_instruction *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  switch ( src->type ) {
    case OFPIT_GOTO_TABLE:
      hton_instruction_goto_table( ( struct ofp_instruction_goto_table * ) dst, ( const struct ofp_instruction_goto_table * ) src );
      break;
    case OFPIT_WRITE_METADATA:
      hton_instruction_write_metadata( ( struct ofp_instruction_write_metadata * ) dst, ( const struct ofp_instruction_write_metadata * ) src );
      break;
    case OFPIT_WRITE_ACTIONS:
    case OFPIT_APPLY_ACTIONS:
    case OFPIT_CLEAR_ACTIONS:
      hton_instruction_actions( ( struct ofp_instruction_actions * ) dst, ( const struct ofp_instruction_actions * ) src );
      break;
    case OFPIT_METER:
      hton_instruction_meter( ( struct ofp_instruction_meter * ) dst, ( const struct ofp_instruction_meter * ) src );
      break;
    case OFPIT_EXPERIMENTER:
      hton_instruction_experimenter( ( struct ofp_instruction_experimenter * ) dst, ( const struct ofp_instruction_experimenter * ) src );
      break;
    default:
      die( "Undefined instruction type ( type = %d ).", src->type );
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
  memset( dst->pad, 0, sizeof( dst->pad ) );
}


void
ntoh_instruction_write_metadata( struct ofp_instruction_write_metadata *dst, const struct ofp_instruction_write_metadata *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  memset( dst->pad, 0, sizeof( dst->pad ) );
  dst->metadata = ntohll( src->metadata );
  dst->metadata_mask = ntohll( src->metadata_mask );
}


void
ntoh_instruction_actions( struct ofp_instruction_actions *dst, const struct ofp_instruction_actions *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->len ) != 0 );

  struct ofp_instruction_actions *fs = xcalloc( 1, ntohs( src->len ) );
  memcpy( fs, src, ntohs( src->len ) );

  dst->type = ntohs( fs->type );
  dst->len = ntohs( fs->len );
  memset( dst->pad, 0, sizeof( dst->pad ) );

  size_t offset = offsetof( struct ofp_instruction_actions, actions );
  if ( dst->len >= offset ) {
    uint16_t actions_length = ( uint16_t ) ( dst->len - offset );

    struct ofp_action_header *ah_src = ( struct ofp_action_header * ) ( ( char * ) fs + offset );
    struct ofp_action_header *ah_dst = ( struct ofp_action_header * ) ( ( char * ) dst + offset );
    uint16_t part_len;

    while ( actions_length >= sizeof( struct ofp_action_header ) ) {
      part_len = ntohs( ah_src->len );
      if ( actions_length < part_len ) {
        break;
      }

      ntoh_action( ah_dst, ah_src );

      actions_length = ( uint16_t ) ( actions_length - part_len );

      ah_src = ( struct ofp_action_header * ) ( ( char * ) ah_src + part_len );
      ah_dst = ( struct ofp_action_header * ) ( ( char * ) ah_dst + part_len );
    }
  }

  xfree( fs );
}


void
hton_instruction_actions( struct ofp_instruction_actions *dst, const struct ofp_instruction_actions *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->len != 0 );

  uint16_t total_len = src->len;
  struct ofp_instruction_actions *fs = xcalloc( 1, total_len );
  memcpy( fs, src, total_len );

  dst->type = htons( fs->type );
  dst->len = htons( fs->len );
  memset( dst->pad, 0, sizeof( dst->pad ) );

  size_t offset = offsetof( struct ofp_instruction_actions, actions );
  if ( total_len >= offset ) {
    uint16_t actions_length = ( uint16_t ) ( total_len - offset );

    struct ofp_action_header *ah_src = ( struct ofp_action_header * ) ( ( char * ) fs + offset );
    struct ofp_action_header *ah_dst = ( struct ofp_action_header * ) ( ( char * ) dst + offset );
    uint16_t part_len;

    while ( actions_length >= sizeof( struct ofp_action_header ) ) {
      part_len = ah_src->len;
      if ( actions_length < part_len ) {
        break;
      }

      hton_action( ah_dst, ah_src );

      actions_length = ( uint16_t ) ( actions_length - part_len );

      ah_dst = ( struct ofp_action_header * ) ( ( char * ) ah_dst + part_len );
      ah_src = ( struct ofp_action_header * ) ( ( char * ) ah_src + part_len );
    }
  }

  xfree( fs );
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

  struct ofp_instruction_experimenter *ie = xcalloc( 1, ntohs( src->len ) );
  memcpy( ie, src, ntohs( src->len ) );

  dst->type = ntohs( ie->type );
  dst->len = ntohs( ie->len );
  dst->experimenter = ntohl( ie->experimenter );

  uint16_t offset = sizeof( struct ofp_instruction_experimenter );
  if ( dst->len > offset ) {
    uint16_t data_len = ( uint16_t ) ( dst->len - offset );
    memcpy( ( char * ) dst + offset, ( char * ) ie + offset, data_len );
  }

  xfree( ie );
}


void
hton_instruction_experimenter( struct ofp_instruction_experimenter *dst, const struct ofp_instruction_experimenter *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  uint16_t src_len = src->len;

  struct ofp_instruction_experimenter *ie = xcalloc( 1, src->len );
  memcpy( ie, src, src->len );

  dst->type = htons( ie->type );
  dst->len = htons( ie->len );
  dst->experimenter = htonl( ie->experimenter );

  uint16_t offset = sizeof( struct ofp_instruction_experimenter );
  if ( src_len > offset ) {
    uint16_t data_len = ( uint16_t ) ( src_len - offset );
    memcpy( ( char * ) dst + offset, ( char * ) ie + offset, data_len );
  }

  xfree( ie );
}


void ntoh_bucket( struct ofp_bucket *dst, const struct ofp_bucket *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->len ) != 0 );

  struct ofp_bucket *fs = xcalloc( 1, ntohs( src->len ) );
  memcpy( fs, src, ntohs( src->len ) );

  dst->len = ntohs( fs->len );
  dst->weight = ntohs( fs->weight );
  dst->watch_port = ntohl( fs->watch_port );
  dst->watch_group = ntohl( fs->watch_group );
  memset( dst->pad, 0, sizeof( dst->pad ) );

  size_t offset = offsetof( struct ofp_bucket, actions );
  if ( dst->len >= offset ) {
    uint16_t actions_length = ( uint16_t ) ( dst->len - offset );

    struct ofp_action_header *ah_src = ( struct ofp_action_header * ) ( ( char * ) fs + offset );
    struct ofp_action_header *ah_dst = ( struct ofp_action_header * ) ( ( char * ) dst + offset );
    uint16_t part_len;

    while ( actions_length >= sizeof( struct ofp_action_header ) ) {
      part_len = ntohs( ah_src->len );
      if ( actions_length < part_len ) {
        break;
      }
      ntoh_action( ah_dst, ah_src );

      actions_length = ( uint16_t ) ( actions_length - part_len );

      ah_src = ( struct ofp_action_header * ) ( ( char * ) ah_src + part_len );
      ah_dst = ( struct ofp_action_header * ) ( ( char * ) ah_dst + part_len );
    }
  }

  xfree( fs );
}


void hton_bucket( struct ofp_bucket *dst, const struct ofp_bucket *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->len != 0 );

  uint16_t total_len = src->len;
  struct ofp_bucket *fs = xcalloc( 1, total_len );
  memcpy( fs, src, total_len );

  dst->len = htons( fs->len );
  dst->weight = htons( fs->weight );
  dst->watch_port = htonl( fs->watch_port );
  dst->watch_group = htonl( fs->watch_group );
  memset( dst->pad, 0, sizeof( dst->pad ) );

  size_t offset = offsetof( struct ofp_bucket, actions );
  if ( total_len >= offset ) {
    uint16_t actions_length = ( uint16_t ) ( total_len - offset );

    struct ofp_action_header *ah_src = ( struct ofp_action_header * ) ( ( char * ) fs + offset );
    struct ofp_action_header *ah_dst = ( struct ofp_action_header * ) ( ( char * ) dst + offset );
    uint16_t part_len;

    while ( actions_length >= sizeof( struct ofp_action_header ) ) {
      part_len = ah_src->len;
      if ( actions_length < part_len ) {
        break;
      }
      hton_action( ah_dst, ah_src );

      actions_length = ( uint16_t ) ( actions_length - part_len );

      ah_dst = ( struct ofp_action_header * ) ( ( char * ) ah_dst + part_len );
      ah_src = ( struct ofp_action_header * ) ( ( char * ) ah_src + part_len );
    }
  }

  xfree( fs );
}


void ntoh_meter_band_drop( struct ofp_meter_band_drop *dst, const struct ofp_meter_band_drop *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  dst->rate = ntohl( src->rate );
  dst->burst_size = ntohl( src->burst_size );
  memset( dst->pad, 0, sizeof( dst->pad ) );
}


void ntoh_meter_band_dscp_remark( struct ofp_meter_band_dscp_remark *dst, const struct ofp_meter_band_dscp_remark *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->type = ntohs( src->type );
  dst->len = ntohs( src->len );
  dst->rate = ntohl( src->rate );
  dst->burst_size = ntohl( src->burst_size );
  dst->prec_level = src->prec_level;
  memset( dst->pad, 0, sizeof( dst->pad ) );
}


void ntoh_meter_band_experimenter( struct ofp_meter_band_experimenter *dst, const struct ofp_meter_band_experimenter *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  struct ofp_meter_band_experimenter *be = xcalloc( 1, ntohs( src->len ) );
  memcpy( be, src, ntohs( src->len ) );

  dst->type = ntohs( be->type );
  dst->len = ntohs( be->len );
  dst->rate = ntohl( be->rate );
  dst->burst_size = ntohl( be->burst_size );
  dst->experimenter = ntohl( be->experimenter );

  uint16_t offset = sizeof( struct ofp_meter_band_experimenter );
  if ( dst->len > offset ) {
    uint16_t data_len = ( uint16_t ) ( dst->len - offset );
    memcpy( ( char * ) dst + offset, ( char * ) be + offset, data_len );
  }

  xfree( be );
}


void hton_meter_band_experimenter( struct ofp_meter_band_experimenter *dst, const struct ofp_meter_band_experimenter *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  uint16_t src_len = src->len;

  struct ofp_meter_band_experimenter *be = xcalloc( 1, src->len );
  memcpy( be, src, src->len );

  dst->type = htons( be->type );
  dst->len = htons( be->len );
  dst->rate = htonl( be->rate );
  dst->burst_size = htonl( be->burst_size );
  dst->experimenter = htonl( be->experimenter );

  uint16_t offset = sizeof( struct ofp_meter_band_experimenter );
  if ( src_len > offset ) {
    uint16_t data_len = ( uint16_t ) ( src_len - offset );
    memcpy( ( char * ) dst + offset, ( char * ) be + offset, data_len );
  }

  xfree( be );
}


void ntoh_meter_band_header( struct ofp_meter_band_header *dst, const struct ofp_meter_band_header *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  switch ( ntohs( src->type ) ) {
    case OFPMBT_DROP:
      ntoh_meter_band_drop( ( struct ofp_meter_band_drop * ) dst, ( const struct ofp_meter_band_drop * ) src );
      break;
    case OFPMBT_DSCP_REMARK:
      ntoh_meter_band_dscp_remark( ( struct ofp_meter_band_dscp_remark * ) dst, ( const struct ofp_meter_band_dscp_remark * ) src );
      break;
    case OFPMBT_EXPERIMENTER:
      ntoh_meter_band_experimenter( ( struct ofp_meter_band_experimenter * ) dst, ( const struct ofp_meter_band_experimenter * ) src );
      break;
    default:
      die( "Undefined meter band type ( type = %d ).", ntohs( src->type ) );
      break;
  }
}


void hton_meter_band_header( struct ofp_meter_band_header *dst, const struct ofp_meter_band_header *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  switch ( src->type ) {
    case OFPMBT_DROP:
      hton_meter_band_drop( ( struct ofp_meter_band_drop * ) dst, ( const struct ofp_meter_band_drop * ) src );
      break;
    case OFPMBT_DSCP_REMARK:
      hton_meter_band_dscp_remark( ( struct ofp_meter_band_dscp_remark * ) dst, ( const struct ofp_meter_band_dscp_remark * ) src );
      break;
    case OFPMBT_EXPERIMENTER:
      hton_meter_band_experimenter( ( struct ofp_meter_band_experimenter * ) dst, ( const struct ofp_meter_band_experimenter * ) src );
      break;
    default:
      die( "Undefined meter band type ( type = %d ).", src->type );
      break;
  }
}


void ntoh_table_feature_prop_instructions( struct ofp_table_feature_prop_instructions *dst, const struct ofp_table_feature_prop_instructions *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->length ) != 0 );

  struct ofp_table_feature_prop_instructions *tfpi = xcalloc( 1, ntohs( src->length ) );
  memcpy( tfpi, src, ntohs( src->length ) );

  dst->type = ntohs( tfpi->type );
  dst->length = ntohs( tfpi->length );

  size_t offset = sizeof( struct ofp_table_feature_prop_instructions );
  if ( dst->length >= offset ) {
    uint16_t instructions_len = ( uint16_t ) ( dst->length - offset );

    struct ofp_instruction *inst_src = ( struct ofp_instruction * ) ( ( char * ) tfpi + offset );
    struct ofp_instruction *inst_dst = ( struct ofp_instruction * ) ( ( char * ) dst + offset );
    uint16_t part_len;

    while ( instructions_len >= sizeof( struct ofp_instruction ) ) {
      part_len = ntohs( inst_src->len );
      if ( instructions_len < part_len ) {
        break;
      }
      ntoh_instruction( inst_dst, inst_src );

      instructions_len = ( uint16_t ) ( instructions_len - part_len );

      inst_src = ( struct ofp_instruction * ) ( ( char * ) inst_src + part_len );
      inst_dst = ( struct ofp_instruction * ) ( ( char * ) inst_dst + part_len );
    }

    uint16_t pad_len = PADLEN_TO_64( dst->length );
    if ( pad_len > 0 ) {
      memset( inst_dst, 0, pad_len );
    }
  }

  xfree( tfpi );
}


void hton_table_feature_prop_instructions( struct ofp_table_feature_prop_instructions *dst, const struct ofp_table_feature_prop_instructions *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->length != 0 );

  uint16_t total_len = src->length;
  struct ofp_table_feature_prop_instructions *tfpi = xcalloc( 1, total_len );
  memcpy( tfpi, src, total_len );

  dst->type = htons( tfpi->type );
  dst->length = htons( tfpi->length );

  size_t offset = sizeof( struct ofp_table_feature_prop_instructions );
  if ( total_len >= offset ) {
    uint16_t instructions_len = ( uint16_t ) ( total_len - offset );

    struct ofp_instruction *inst_src = ( struct ofp_instruction * ) ( ( char * ) tfpi + offset );
    struct ofp_instruction *inst_dst = ( struct ofp_instruction * ) ( ( char * ) dst + offset );
    uint16_t part_len;

    while ( instructions_len >= sizeof( struct ofp_instruction ) ) {
      part_len = inst_src->len;
      if ( instructions_len < part_len ) {
        break;
      }
      hton_instruction( inst_dst, inst_src );

      instructions_len = ( uint16_t ) ( instructions_len - part_len );

      inst_dst = ( struct ofp_instruction * ) ( ( char * ) inst_dst + part_len );
      inst_src = ( struct ofp_instruction * ) ( ( char * ) inst_src + part_len );
    }

    uint16_t pad_len = PADLEN_TO_64( total_len );
    if ( pad_len > 0 ) {
      memset( inst_dst, 0, pad_len );
    }
  }

  xfree( tfpi );
}


void ntoh_table_feature_prop_next_tables( struct ofp_table_feature_prop_next_tables *dst, const struct ofp_table_feature_prop_next_tables *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->length ) != 0 );

  struct ofp_table_feature_prop_next_tables *tfpnt = xcalloc( 1, ntohs( src->length ) );
  memcpy( tfpnt, src, ntohs( src->length ) );

  dst->type = ntohs( tfpnt->type );
  dst->length = ntohs( tfpnt->length );

  size_t offset = offsetof( struct ofp_table_feature_prop_next_tables, next_table_ids );
  if ( dst->length >= offset ) {
    uint16_t table_len = ( uint16_t ) ( dst->length - offset );
    uint16_t table_num = ( uint16_t ) ( table_len / sizeof( uint8_t ) );

    uint16_t i;
    for ( i = 0; i < table_num; i++ ) {
      dst->next_table_ids[ i ] = tfpnt->next_table_ids[ i ];
    }

    uint16_t pad_len = PADLEN_TO_64( dst->length );
    if ( pad_len > 0 ) {
      memset( &dst->next_table_ids[ i ], 0, pad_len );
    }
  }

  xfree( tfpnt );
}


void hton_table_feature_prop_next_tables( struct ofp_table_feature_prop_next_tables *dst, const struct ofp_table_feature_prop_next_tables *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->length != 0 );

  uint16_t total_len = src->length;
  struct ofp_table_feature_prop_next_tables *tfpnt = xcalloc( 1, total_len );
  memcpy( tfpnt, src, total_len );

  dst->type = htons( tfpnt->type );
  dst->length = htons( tfpnt->length );

  size_t offset = offsetof( struct ofp_table_feature_prop_next_tables, next_table_ids );
  if ( total_len >= offset ) {
    uint16_t table_len = ( uint16_t ) ( total_len - offset );
    uint16_t table_num = ( uint16_t ) ( table_len / sizeof( uint8_t ) );

    uint16_t i;
    for ( i = 0; i < table_num; i++ ) {
      dst->next_table_ids[ i ] = tfpnt->next_table_ids[ i ];
    }

    uint16_t pad_len = PADLEN_TO_64( total_len );
    if ( pad_len > 0 ) {
      memset( &dst->next_table_ids[ i ], 0, pad_len );
    }
  }

  xfree( tfpnt );
}


void ntoh_table_feature_prop_actions( struct ofp_table_feature_prop_actions *dst, const struct ofp_table_feature_prop_actions *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->length ) != 0 );

  struct ofp_table_feature_prop_actions *tfpa = xcalloc( 1, ntohs( src->length ) );
  memcpy( tfpa, src, ntohs( src->length ) );

  dst->type = ntohs( tfpa->type );
  dst->length = ntohs( tfpa->length );

  size_t offset = ( size_t ) ( offsetof( struct ofp_table_feature_prop_actions, action_ids ) );
  if ( dst->length >= offset ) {
    uint16_t actions_len = ( uint16_t ) ( dst->length - offset );

    struct ofp_action_header *act_src = ( struct ofp_action_header * ) ( ( char * ) tfpa + offset );
    struct ofp_action_header *act_dst = ( struct ofp_action_header * ) ( ( char * ) dst + offset );
    uint16_t part_len;

    while ( actions_len >= sizeof( struct ofp_action_header ) ) {
      part_len = ntohs( act_src->len );
      if ( actions_len < part_len ) {
        break;
      }

      ntoh_action( act_dst, act_src );

      actions_len = ( uint16_t ) ( actions_len - part_len );

      act_src = ( struct ofp_action_header * ) ( ( char * ) act_src + part_len );
      act_dst = ( struct ofp_action_header * ) ( ( char * ) act_dst + part_len );
    }

    uint16_t pad_len = PADLEN_TO_64( dst->length );
    if ( pad_len > 0 ) {
      memset( act_dst, 0, pad_len );
    }
  }

  xfree( tfpa );
}


void hton_table_feature_prop_actions( struct ofp_table_feature_prop_actions *dst, const struct ofp_table_feature_prop_actions *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->length != 0 );

  uint16_t total_len = src->length;
  struct ofp_table_feature_prop_actions *tfpa = xcalloc( 1, total_len );
  memcpy( tfpa, src, total_len );

  dst->type = htons( tfpa->type );
  dst->length = htons( tfpa->length );

  size_t offset = ( size_t ) ( offsetof( struct ofp_table_feature_prop_actions, action_ids ) );
  if ( total_len >= offset ) {
    uint16_t actions_len = ( uint16_t ) ( total_len - offset );

    struct ofp_action_header *act_src = ( struct ofp_action_header * ) ( ( char * ) tfpa + offset );
    struct ofp_action_header *act_dst = ( struct ofp_action_header * ) ( ( char * ) dst + offset );
    uint16_t part_len;

    while ( actions_len >= sizeof( struct ofp_action_header ) ) {
      part_len = act_src->len;
      if ( actions_len < part_len ) {
        break;
      }

      hton_action( act_dst, act_src );

      actions_len = ( uint16_t ) ( actions_len - part_len );

      act_dst = ( struct ofp_action_header * ) ( ( char * ) act_dst + part_len );
      act_src = ( struct ofp_action_header * ) ( ( char * ) act_src + part_len );
    }

    uint16_t pad_len = PADLEN_TO_64( total_len );
    if ( pad_len > 0 ) {
      memset( act_dst, 0, pad_len );
    }
  }

  xfree( tfpa );
}


void ntoh_table_feature_prop_oxm( struct ofp_table_feature_prop_oxm *dst, const struct ofp_table_feature_prop_oxm *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->length ) != 0 );

  struct ofp_table_feature_prop_oxm *tfpo = xcalloc( 1, ntohs( src->length ) );
  memcpy( tfpo, src, ntohs( src->length ) );

  dst->type = ntohs( tfpo->type );
  dst->length = ntohs( tfpo->length );

  size_t offset = ( size_t ) ( offsetof( struct ofp_table_feature_prop_oxm, oxm_ids ) );
  if ( dst->length >= offset ) {
    uint16_t oxm_len = ( uint16_t ) ( dst->length - offset );
    uint16_t oxm_num = ( uint16_t ) ( oxm_len / sizeof( uint32_t ) );

    uint16_t i;
    for ( i = 0; i < oxm_num; i++ ) {
      dst->oxm_ids[ i ] = ntohl( tfpo->oxm_ids[ i ] );
    }

    uint16_t pad_len = PADLEN_TO_64( dst->length );
    if ( pad_len > 0 ) {
      memset( &dst->oxm_ids[ i ], 0, pad_len );
    }
  }

  xfree( tfpo );
}


void hton_table_feature_prop_oxm( struct ofp_table_feature_prop_oxm *dst, const struct ofp_table_feature_prop_oxm *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->length != 0 );

  uint16_t total_len = src->length;
  struct ofp_table_feature_prop_oxm *tfpo = xcalloc( 1, total_len );
  memcpy( tfpo, src, total_len );

  dst->type = htons( tfpo->type );
  dst->length = htons( tfpo->length );

  size_t offset = ( size_t ) ( offsetof( struct ofp_table_feature_prop_oxm, oxm_ids ) );
  if ( total_len >= offset ) {
    uint16_t oxm_len = ( uint16_t ) ( total_len - offset );
    uint16_t oxm_num = ( uint16_t ) ( oxm_len / sizeof( uint32_t ) );

    uint16_t i;
    for ( i = 0; i < oxm_num; i++ ) {
      dst->oxm_ids[ i ] = htonl( tfpo->oxm_ids[ i ] );
    }

    uint16_t pad_len = PADLEN_TO_64( total_len );
    if ( pad_len > 0 ) {
      memset( &dst->oxm_ids[ i ], 0, pad_len );
    }
  }

  xfree( tfpo );
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
    uint16_t data_len = ( uint16_t ) ( dst->length - offset );
    memcpy( dst->experimenter_data, src->experimenter_data, data_len );
  }
}


void hton_table_feature_prop_experimenter( struct ofp_table_feature_prop_experimenter *dst, const struct ofp_table_feature_prop_experimenter *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  uint16_t src_len = src->length;

  dst->type = htons( src->type );
  dst->length = htons( src->length );
  dst->experimenter = htonl( src->experimenter );
  dst->exp_type = htonl( src->exp_type );

  uint16_t offset = offsetof( struct ofp_table_feature_prop_experimenter, experimenter_data );
  if ( src_len > offset ) {
    uint16_t data_len = ( uint16_t ) ( src_len - offset );
    memcpy( dst->experimenter_data, src->experimenter_data, data_len );
  }
}


void ntoh_table_feature_prop_header( struct ofp_table_feature_prop_header *dst, const struct ofp_table_feature_prop_header *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  switch ( ntohs( src->type ) ) {
    case OFPTFPT_INSTRUCTIONS:
    case OFPTFPT_INSTRUCTIONS_MISS:
      ntoh_table_feature_prop_instructions( ( struct ofp_table_feature_prop_instructions * ) dst, ( const struct ofp_table_feature_prop_instructions * ) src );
      break;
    case OFPTFPT_NEXT_TABLES:
    case OFPTFPT_NEXT_TABLES_MISS:
      ntoh_table_feature_prop_next_tables( ( struct ofp_table_feature_prop_next_tables * ) dst, ( const struct ofp_table_feature_prop_next_tables * ) src );
      break;
    case OFPTFPT_WRITE_ACTIONS:
    case OFPTFPT_WRITE_ACTIONS_MISS:
    case OFPTFPT_APPLY_ACTIONS:
    case OFPTFPT_APPLY_ACTIONS_MISS:
      ntoh_table_feature_prop_actions( ( struct ofp_table_feature_prop_actions * ) dst, ( const struct ofp_table_feature_prop_actions * ) src );
      break;
    case OFPTFPT_MATCH:
    case OFPTFPT_WILDCARDS:
    case OFPTFPT_WRITE_SETFIELD:
    case OFPTFPT_WRITE_SETFIELD_MISS:
    case OFPTFPT_APPLY_SETFIELD:
    case OFPTFPT_APPLY_SETFIELD_MISS:
      ntoh_table_feature_prop_oxm( ( struct ofp_table_feature_prop_oxm * ) dst, ( const struct ofp_table_feature_prop_oxm * ) src );
      break;
    case OFPTFPT_EXPERIMENTER:
    case OFPTFPT_EXPERIMENTER_MISS:
      ntoh_table_feature_prop_experimenter( ( struct ofp_table_feature_prop_experimenter * ) dst, ( const struct ofp_table_feature_prop_experimenter * ) src );
      break;
    default:
      die( "Undefined table feature property type ( type = %d ).", ntohs( src->type ) );
      break;
  }
}


void hton_table_feature_prop_header( struct ofp_table_feature_prop_header *dst, const struct ofp_table_feature_prop_header *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  switch ( src->type ) {
    case OFPTFPT_INSTRUCTIONS:
    case OFPTFPT_INSTRUCTIONS_MISS:
      hton_table_feature_prop_instructions( ( struct ofp_table_feature_prop_instructions * ) dst, ( const struct ofp_table_feature_prop_instructions * ) src );
      break;
    case OFPTFPT_NEXT_TABLES:
    case OFPTFPT_NEXT_TABLES_MISS:
      hton_table_feature_prop_next_tables( ( struct ofp_table_feature_prop_next_tables * ) dst, ( const struct ofp_table_feature_prop_next_tables * ) src );
      break;
    case OFPTFPT_WRITE_ACTIONS:
    case OFPTFPT_WRITE_ACTIONS_MISS:
    case OFPTFPT_APPLY_ACTIONS:
    case OFPTFPT_APPLY_ACTIONS_MISS:
      hton_table_feature_prop_actions( ( struct ofp_table_feature_prop_actions * ) dst, ( const struct ofp_table_feature_prop_actions * ) src );
      break;
    case OFPTFPT_MATCH:
    case OFPTFPT_WILDCARDS:
    case OFPTFPT_WRITE_SETFIELD:
    case OFPTFPT_WRITE_SETFIELD_MISS:
    case OFPTFPT_APPLY_SETFIELD:
    case OFPTFPT_APPLY_SETFIELD_MISS:
      hton_table_feature_prop_oxm( ( struct ofp_table_feature_prop_oxm * ) dst, ( const struct ofp_table_feature_prop_oxm * ) src );
      break;
    case OFPTFPT_EXPERIMENTER:
    case OFPTFPT_EXPERIMENTER_MISS:
      hton_table_feature_prop_experimenter( ( struct ofp_table_feature_prop_experimenter * ) dst, ( const struct ofp_table_feature_prop_experimenter * ) src );
      break;
    default:
      die( "Undefined table feature property type ( type = %d ).", src->type );
      break;
  }
}


void ntoh_table_features( struct ofp_table_features *dst, const struct ofp_table_features *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->length ) != 0 );

  struct ofp_table_features *tf = xcalloc( 1, ntohs( src->length ) );
  memcpy( tf, src, ntohs( src->length ) );

  dst->length = ntohs( tf->length );
  dst->table_id = tf->table_id;
  memset( dst->pad, 0, sizeof( dst->pad ) );
  bcopy( tf->name, dst->name, OFP_MAX_TABLE_NAME_LEN );
  dst->metadata_match = ntohll( tf->metadata_match );
  dst->metadata_write = ntohll( tf->metadata_write );
  dst->config = ntohl( tf->config );
  dst->max_entries = ntohl( tf->max_entries );

  size_t offset = ( size_t ) sizeof( struct ofp_table_features );
  if ( dst->length >= offset ) {
    uint16_t tfp_len = ( uint16_t ) ( dst->length - offset );

    struct ofp_table_feature_prop_header *act_src = ( struct ofp_table_feature_prop_header * ) ( ( char * ) tf + offset );
    struct ofp_table_feature_prop_header *act_dst = ( struct ofp_table_feature_prop_header * ) ( ( char * ) dst + offset );
    uint16_t part_len;

    while ( tfp_len >= sizeof( struct ofp_table_feature_prop_header ) ) {
      part_len = ntohs( act_src->length );
      if ( tfp_len < part_len ) {
        break;
      }

      ntoh_table_feature_prop_header( act_dst, act_src );

      offset = ( uint16_t ) ( part_len + PADLEN_TO_64( part_len ) );
      if ( tfp_len < offset ) {
        break;
      }

      tfp_len = ( uint16_t ) ( tfp_len - offset );

      act_src = ( struct ofp_table_feature_prop_header * ) ( ( char * ) act_src + offset );
      act_dst = ( struct ofp_table_feature_prop_header * ) ( ( char * ) act_dst + offset );
    }
  }

  xfree( tf );
}


void hton_table_features( struct ofp_table_features *dst, const struct ofp_table_features *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->length != 0 );

  uint16_t total_len = src->length;
  struct ofp_table_features *tf = xcalloc( 1, total_len );
  memcpy( tf, src, total_len );

  dst->length = htons( tf->length );
  dst->table_id = tf->table_id;
  memset( dst->pad, 0, sizeof( dst->pad ) );
  bcopy( tf->name, dst->name, OFP_MAX_TABLE_NAME_LEN );
  dst->metadata_match = htonll( tf->metadata_match );
  dst->metadata_write = htonll( tf->metadata_write );
  dst->config = htonl( tf->config );
  dst->max_entries = htonl( tf->max_entries );

  size_t offset = ( size_t ) sizeof( struct ofp_table_features );
  if ( total_len >= offset ) {
    uint16_t tfp_len = ( uint16_t ) ( total_len - offset );

    struct ofp_table_feature_prop_header *act_src = ( struct ofp_table_feature_prop_header * ) ( ( char * ) tf + offset );
    struct ofp_table_feature_prop_header *act_dst = ( struct ofp_table_feature_prop_header * ) ( ( char * ) dst + offset );
    uint16_t part_len;

    while ( tfp_len >= sizeof( struct ofp_table_feature_prop_header ) ) {
      part_len = act_src->length;
      if ( tfp_len < part_len ) {
        break;
      }

      hton_table_feature_prop_header( act_dst, act_src );

      offset = ( uint16_t ) ( part_len + PADLEN_TO_64( part_len ) );
      if ( tfp_len < offset ) {
        break;
      }

      tfp_len = ( uint16_t ) ( tfp_len - offset );

      act_dst = ( struct ofp_table_feature_prop_header * ) ( ( char * ) act_dst + offset );
      act_src = ( struct ofp_table_feature_prop_header * ) ( ( char * ) act_src + offset );
    }
  }

  xfree( tf );
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

  struct ofp_group_stats *fs = xcalloc( 1, ntohs( src->length ) );
  memcpy( fs, src, ntohs( src->length ) );

  dst->length = ntohs( fs->length );
  memset( dst->pad, 0, sizeof( dst->pad ) );
  dst->group_id = ntohl( fs->group_id );
  dst->ref_count = ntohl( fs->ref_count );
  memset( dst->pad2, 0, sizeof( dst->pad2 ) );
  dst->packet_count = ntohll( fs->packet_count );
  dst->byte_count = ntohll( fs->byte_count );
  dst->duration_sec = ntohl( fs->duration_sec );
  dst->duration_nsec = ntohl( fs->duration_nsec );

  size_t offset = offsetof( struct ofp_group_stats, bucket_stats );
  if ( dst->length >= offset ) {
    uint16_t stats_length = ( uint16_t ) ( dst->length - offset );

    struct ofp_bucket_counter *ah_src = ( struct ofp_bucket_counter * ) ( ( char * ) fs + offset );
    struct ofp_bucket_counter *ah_dst = ( struct ofp_bucket_counter * ) ( ( char * ) dst + offset );
    offset = sizeof( struct ofp_bucket_counter );

    while ( stats_length >= offset ) {
      ntoh_bucket_counter( ah_dst, ah_src );

      stats_length = ( uint16_t ) ( stats_length - offset );

      ah_src = ( struct ofp_bucket_counter * ) ( ( char * ) ah_src + offset );
      ah_dst = ( struct ofp_bucket_counter * ) ( ( char * ) ah_dst + offset );
    }
  }

  xfree( fs );
}


void hton_group_stats( struct ofp_group_stats *dst, const struct ofp_group_stats *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->length != 0 );

  uint16_t total_len = src->length;
  struct ofp_group_stats *fs = xcalloc( 1, total_len );
  memcpy( fs, src, total_len );


  dst->length = htons( fs->length );
  memset( dst->pad, 0, sizeof( dst->pad ) );
  dst->group_id = htonl( fs->group_id );
  dst->ref_count = htonl( fs->ref_count );
  memset( dst->pad2, 0, sizeof( dst->pad2 ) );
  dst->packet_count = htonll( fs->packet_count );
  dst->byte_count = htonll( fs->byte_count );
  dst->duration_sec = htonl( fs->duration_sec );
  dst->duration_nsec = htonl( fs->duration_nsec );

  size_t offset = offsetof( struct ofp_group_stats, bucket_stats );
  if ( total_len >= offset ) {
    uint16_t stats_length = ( uint16_t ) ( total_len - offset );

    struct ofp_bucket_counter *ah_src = ( struct ofp_bucket_counter * ) ( ( char * ) fs + offset );
    struct ofp_bucket_counter *ah_dst = ( struct ofp_bucket_counter * ) ( ( char * ) dst + offset );
    offset = sizeof( struct ofp_bucket_counter );

    while ( stats_length >= offset ) {
      hton_bucket_counter( ah_dst, ah_src );

      stats_length = ( uint16_t ) ( stats_length - offset );

      ah_dst = ( struct ofp_bucket_counter * ) ( ( char * ) ah_dst + offset );
      ah_src = ( struct ofp_bucket_counter * ) ( ( char * ) ah_src + offset );
    }
  }

  xfree( fs );
}


void ntoh_group_desc_stats( struct ofp_group_desc_stats *dst, const struct ofp_group_desc_stats *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->length ) != 0 );

  struct ofp_group_desc_stats *fs = xcalloc( 1, ntohs( src->length ) );
  memcpy( fs, src, ntohs( src->length ) );

  dst->length = ntohs( fs->length );
  dst->type = fs->type;
  dst->pad = 0;
  dst->group_id = ntohl( fs->group_id );

  size_t offset = offsetof( struct ofp_group_desc_stats, buckets );
  if ( dst->length >= offset ) {
    uint16_t buckets_length = ( uint16_t ) ( dst->length - offset );

    struct ofp_bucket *ah_src = ( struct ofp_bucket * ) ( ( char * ) fs + offset );
    struct ofp_bucket *ah_dst = ( struct ofp_bucket * ) ( ( char * ) dst + offset );
    uint16_t part_len;

    while ( buckets_length >= sizeof( struct ofp_bucket ) ) {
      part_len = ntohs( ah_src->len );
      if ( buckets_length < part_len ) {
        break;
      }

      ntoh_bucket( ah_dst, ah_src );

      buckets_length = ( uint16_t ) ( buckets_length - part_len );

      ah_src = ( struct ofp_bucket * ) ( ( char * ) ah_src + part_len );
      ah_dst = ( struct ofp_bucket * ) ( ( char * ) ah_dst + part_len );
    }
  }

  xfree( fs );
}


void hton_group_desc_stats( struct ofp_group_desc_stats *dst, const struct ofp_group_desc_stats *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->length != 0 );

  uint16_t total_len = src->length;
  struct ofp_group_desc_stats *fs = xcalloc( 1, total_len );
  memcpy( fs, src, total_len );

  dst->length = htons( fs->length );
  dst->type = fs->type;
  dst->pad = 0;
  dst->group_id = htonl( fs->group_id );

  size_t offset = offsetof( struct ofp_group_desc_stats, buckets );
  if ( total_len >= offset ) {
    uint16_t buckets_length = ( uint16_t ) ( total_len - offset );

    struct ofp_bucket *ah_src = ( struct ofp_bucket * ) ( ( char * ) fs + offset );
    struct ofp_bucket *ah_dst = ( struct ofp_bucket * ) ( ( char * ) dst + offset );
    uint16_t part_len;

    while ( buckets_length >= sizeof( struct ofp_bucket ) ) {
      part_len = ah_src->len;
      if ( buckets_length < part_len ) {
        break;
      }

      hton_bucket( ah_dst, ah_src );

      buckets_length = ( uint16_t ) ( buckets_length - part_len );

      ah_dst = ( struct ofp_bucket * ) ( ( char * ) ah_dst + part_len );
      ah_src = ( struct ofp_bucket * ) ( ( char * ) ah_src + part_len );
    }
  }

  xfree( fs );
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

  struct ofp_meter_stats *fs = xcalloc( 1, ntohs( src->len ) );
  memcpy( fs, src, ntohs( src->len ) );

  dst->meter_id = ntohl( fs->meter_id );
  dst->len = ntohs( fs->len );
  memset( dst->pad, 0, sizeof( dst->pad ) );
  dst->flow_count = ntohl( fs->flow_count );
  dst->packet_in_count = ntohll( fs->packet_in_count );
  dst->byte_in_count = ntohll( fs->byte_in_count );
  dst->duration_sec = ntohl( fs->duration_sec );
  dst->duration_nsec = ntohl( fs->duration_nsec );

  size_t offset = offsetof( struct ofp_meter_stats, band_stats );
  if ( dst->len >= offset ) {
    uint16_t stats_length = ( uint16_t ) ( dst->len - offset );

    struct ofp_meter_band_stats *ah_src = ( struct ofp_meter_band_stats * ) ( ( char * ) fs + offset );
    struct ofp_meter_band_stats *ah_dst = ( struct ofp_meter_band_stats * ) ( ( char * ) dst + offset );
    offset = sizeof( struct ofp_meter_band_stats );

    while ( stats_length >= offset ) {
      ntoh_meter_band_stats( ah_dst, ah_src );

      stats_length = ( uint16_t ) ( stats_length - offset );

      ah_src = ( struct ofp_meter_band_stats * ) ( ( char * ) ah_src + offset );
      ah_dst = ( struct ofp_meter_band_stats * ) ( ( char * ) ah_dst + offset );
    }
  }

  xfree( fs );
}


void hton_meter_stats( struct ofp_meter_stats *dst, const struct ofp_meter_stats *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->len != 0 );

  uint16_t total_len = src->len;
  struct ofp_meter_stats *fs = xcalloc( 1, total_len );
  memcpy( fs, src, total_len );

  dst->meter_id = htonl( fs->meter_id );
  dst->len = htons( fs->len );
  memset( dst->pad, 0, sizeof( dst->pad ) );
  dst->flow_count = htonl( fs->flow_count );
  dst->packet_in_count = htonll( fs->packet_in_count );
  dst->byte_in_count = htonll( fs->byte_in_count );
  dst->duration_sec = htonl( fs->duration_sec );
  dst->duration_nsec = htonl( fs->duration_nsec );

  size_t offset = offsetof( struct ofp_meter_stats, band_stats );
  if ( total_len > offset ) {
    uint16_t stats_length = ( uint16_t ) ( total_len - offset );

    struct ofp_meter_band_stats *ah_src = ( struct ofp_meter_band_stats * ) ( ( char * ) fs + offset );
    struct ofp_meter_band_stats *ah_dst = ( struct ofp_meter_band_stats * ) ( ( char * ) dst + offset );
    offset = sizeof( struct ofp_meter_band_stats );

    while ( stats_length >= offset ) {
      hton_meter_band_stats( ah_dst, ah_src );

      stats_length = ( uint16_t ) ( stats_length - offset );

      ah_dst = ( struct ofp_meter_band_stats * ) ( ( char * ) ah_dst + offset );
      ah_src = ( struct ofp_meter_band_stats * ) ( ( char * ) ah_src + offset );
    }
  }

  xfree( fs );
}


void ntoh_meter_config( struct ofp_meter_config *dst, const struct ofp_meter_config *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( ntohs( src->length ) != 0 );

  struct ofp_meter_config *fs = xcalloc( 1, ntohs( src->length ) );
  memcpy( fs, src, ntohs( src->length ) );

  dst->length = ntohs( fs->length );
  dst->flags = ntohs( fs->flags );
  dst->meter_id = ntohl( fs->meter_id );

  size_t offset = offsetof( struct ofp_meter_config, bands );
  if ( dst->length >= offset ) {
    uint16_t bands_length = ( uint16_t ) ( dst->length - offset );

    struct ofp_meter_band_header *ah_src = ( struct ofp_meter_band_header * ) ( ( char * ) fs + offset );
    struct ofp_meter_band_header *ah_dst = ( struct ofp_meter_band_header * ) ( ( char * ) dst + offset );
    uint16_t part_len;

    while ( bands_length >= sizeof( struct ofp_meter_band_header ) ) {
      part_len = ntohs( ah_src->len );
      if ( bands_length < part_len ) {
        break;
      }

      ntoh_meter_band_header( ah_dst, ah_src );

      bands_length = ( uint16_t ) ( bands_length - part_len );

      ah_src = ( struct ofp_meter_band_header * ) ( ( char * ) ah_src + part_len );
      ah_dst = ( struct ofp_meter_band_header * ) ( ( char * ) ah_dst + part_len );
    }
  }

  xfree( fs );
}


void hton_meter_config( struct ofp_meter_config *dst, const struct ofp_meter_config *src ) {
  assert( src != NULL );
  assert( dst != NULL );
  assert( src->length != 0 );

  uint16_t total_len = src->length;
  struct ofp_meter_config *fs = xcalloc( 1, total_len );
  memcpy( fs, src, total_len );

  dst->length = htons( fs->length );
  dst->flags = htons( fs->flags );
  dst->meter_id = htonl( fs->meter_id );

  size_t offset = offsetof( struct ofp_meter_config, bands );
  if ( total_len >= offset ) {
    uint16_t bands_length = ( uint16_t ) ( total_len - offset );

    struct ofp_meter_band_header *ah_src = ( struct ofp_meter_band_header * ) ( ( char * ) fs + offset );
    struct ofp_meter_band_header *ah_dst = ( struct ofp_meter_band_header * ) ( ( char * ) dst + offset );
    uint16_t part_len;

    while ( bands_length >= sizeof( struct ofp_meter_band_header ) ) {
      part_len = ah_src->len;
      if ( bands_length < part_len ) {
        break;
      }

      hton_meter_band_header( ah_dst, ah_src );

      bands_length = ( uint16_t ) ( bands_length - part_len );

      ah_dst = ( struct ofp_meter_band_header * ) ( ( char * ) ah_dst + part_len );
      ah_src = ( struct ofp_meter_band_header * ) ( ( char * ) ah_src + part_len );
    }
  }

  xfree( fs );
}


void ntoh_meter_features( struct ofp_meter_features *dst, const struct ofp_meter_features *src ) {
  assert( src != NULL );
  assert( dst != NULL );

  dst->max_meter = ntohl( src->max_meter );
  dst->band_types = ntohl( src->band_types );
  dst->capabilities = ntohl( src->capabilities );
  dst->max_bands = src->max_bands;
  dst->max_color = src->max_color;
  memset( dst->pad, 0, sizeof( dst->pad ) );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
