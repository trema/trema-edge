/*
 * Utility functions for converting byteorder.
 *
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


#ifndef BYTEORDER_H
#define BYTEORDER_H


#include <endian.h>
#include <byteswap.h>
#include <openflow.h>
#include "bool.h"


#if __BYTE_ORDER == __BIG_ENDIAN
#define ntohll( _x ) ( _x )
#define htonll( _x ) ( _x )
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define ntohll( _x ) bswap_64( _x )
#define htonll( _x ) bswap_64( _x )
#endif


void ntoh_hello_elem_versionbitmap( struct ofp_hello_elem_versionbitmap *dst, const struct ofp_hello_elem_versionbitmap *src );
void hton_hello_elem_versionbitmap( struct ofp_hello_elem_versionbitmap *dst, const struct ofp_hello_elem_versionbitmap *src );

void ntoh_hello_elem( struct ofp_hello_elem_header *dst, const struct ofp_hello_elem_header *src );
void hton_hello_elem( struct ofp_hello_elem_header *dst, const struct ofp_hello_elem_header *src );

void ntoh_port( struct ofp_port *dst, const struct ofp_port *src );
#define hton_port ntoh_port

void ntoh_action_output( struct ofp_action_output *dst, const struct ofp_action_output *src );
#define hton_action_output ntoh_action_output

void ntoh_action_set_field( struct ofp_action_set_field *dst, const struct ofp_action_set_field *src );
void hton_action_set_field( struct ofp_action_set_field *dst, const struct ofp_action_set_field *src );

void ntoh_action_set_queue( struct ofp_action_set_queue *dst, const struct ofp_action_set_queue *src );
#define hton_action_set_queue ntoh_action_set_queue

void ntoh_action_experimenter( struct ofp_action_experimenter_header *dst, const struct ofp_action_experimenter_header *src );
void hton_action_experimenter( struct ofp_action_experimenter_header *dst, const struct ofp_action_experimenter_header *src );

void ntoh_action_mpls_ttl( struct ofp_action_mpls_ttl *dst, const struct ofp_action_mpls_ttl *src );
#define hton_action_mpls_ttl ntoh_action_mpls_ttl

void ntoh_action_push( struct ofp_action_push *dst, const struct ofp_action_push *src );
#define hton_action_push ntoh_action_push

void ntoh_action_pop_mpls( struct ofp_action_pop_mpls *dst, const struct ofp_action_pop_mpls *src );
#define hton_action_pop_mpls ntoh_action_pop_mpls

void ntoh_action_group( struct ofp_action_group *dst, const struct ofp_action_group *src );
#define hton_action_group ntoh_action_group

void ntoh_action_nw_ttl( struct ofp_action_nw_ttl *dst, const struct ofp_action_nw_ttl *src );
#define hton_action_nw_ttl ntoh_action_nw_ttl

void ntoh_action_header( struct ofp_action_header *dst, const struct ofp_action_header *src );
#define hton_action_header ntoh_action_header

void ntoh_action( struct ofp_action_header *dst, const struct ofp_action_header *src );
void hton_action( struct ofp_action_header *dst, const struct ofp_action_header *src );

void ntoh_flow_stats( struct ofp_flow_stats *dst, const struct ofp_flow_stats *src );
void hton_flow_stats( struct ofp_flow_stats *dst, const struct ofp_flow_stats *src );

void ntoh_aggregate_stats( struct ofp_aggregate_stats_reply *dst, const struct ofp_aggregate_stats_reply *src );
#define hton_aggregate_stats ntoh_aggregate_stats

void ntoh_table_stats( struct ofp_table_stats *dst, const struct ofp_table_stats *src );
#define hton_table_stats ntoh_table_stats

void ntoh_port_stats( struct ofp_port_stats *dst, const struct ofp_port_stats *src );
#define hton_port_stats ntoh_port_stats

void ntoh_queue_stats( struct ofp_queue_stats *dst, const struct ofp_queue_stats *src );
#define hton_queue_stats ntoh_queue_stats

void ntoh_queue_property( struct ofp_queue_prop_header *dst, const struct ofp_queue_prop_header *src );
void hton_queue_property( struct ofp_queue_prop_header *dst, const struct ofp_queue_prop_header *src );

void ntoh_packet_queue( struct ofp_packet_queue *dst, const struct ofp_packet_queue *src );
void hton_packet_queue( struct ofp_packet_queue *dst, const struct ofp_packet_queue *src );

void ntoh_instruction( struct ofp_instruction *dst, const struct ofp_instruction *src );
void hton_instruction( struct ofp_instruction *dst, const struct ofp_instruction *src );

void ntoh_instruction_goto_table( struct ofp_instruction_goto_table *dst, const struct ofp_instruction_goto_table *src );
#define hton_instruction_goto_table ntoh_instruction_goto_table

void ntoh_instruction_write_metadata( struct ofp_instruction_write_metadata *dst, const struct ofp_instruction_write_metadata *src );
#define hton_instruction_write_metadata ntoh_instruction_write_metadata

void ntoh_instruction_actions( struct ofp_instruction_actions *dst, const struct ofp_instruction_actions *src );
void hton_instruction_actions( struct ofp_instruction_actions *dst, const struct ofp_instruction_actions *src );

void ntoh_instruction_meter( struct ofp_instruction_meter *dst, const struct ofp_instruction_meter *src );
#define hton_instruction_meter ntoh_instruction_meter

void ntoh_instruction_experimenter( struct ofp_instruction_experimenter *dst, const struct ofp_instruction_experimenter *src );
void hton_instruction_experimenter( struct ofp_instruction_experimenter *dst, const struct ofp_instruction_experimenter *src );

void ntoh_bucket( struct ofp_bucket *dst, const struct ofp_bucket *src );
void hton_bucket( struct ofp_bucket *dst, const struct ofp_bucket *src );

void ntoh_meter_band_drop( struct ofp_meter_band_drop *dst, const struct ofp_meter_band_drop *src );
#define hton_meter_band_drop ntoh_meter_band_drop

void ntoh_meter_band_dscp_remark( struct ofp_meter_band_dscp_remark *dst, const struct ofp_meter_band_dscp_remark *src );
#define hton_meter_band_dscp_remark ntoh_meter_band_dscp_remark

void ntoh_meter_band_experimenter( struct ofp_meter_band_experimenter *dst, const struct ofp_meter_band_experimenter *src );
void hton_meter_band_experimenter( struct ofp_meter_band_experimenter *dst, const struct ofp_meter_band_experimenter *src );

void ntoh_meter_band_header( struct ofp_meter_band_header *dst, const struct ofp_meter_band_header *src );
void hton_meter_band_header( struct ofp_meter_band_header *dst, const struct ofp_meter_band_header *src );

void ntoh_table_feature_prop_instructions( struct ofp_table_feature_prop_instructions *dst, const struct ofp_table_feature_prop_instructions *src );
void hton_table_feature_prop_instructions( struct ofp_table_feature_prop_instructions *dst, const struct ofp_table_feature_prop_instructions *src );

void ntoh_table_feature_prop_next_tables( struct ofp_table_feature_prop_next_tables *dst, const struct ofp_table_feature_prop_next_tables *src );
void hton_table_feature_prop_next_tables( struct ofp_table_feature_prop_next_tables *dst, const struct ofp_table_feature_prop_next_tables *src );

void ntoh_table_feature_prop_actions( struct ofp_table_feature_prop_actions *dst, const struct ofp_table_feature_prop_actions *src );
void hton_table_feature_prop_actions( struct ofp_table_feature_prop_actions *dst, const struct ofp_table_feature_prop_actions *src );

void ntoh_table_feature_prop_oxm( struct ofp_table_feature_prop_oxm *dst, const struct ofp_table_feature_prop_oxm *src );
void hton_table_feature_prop_oxm( struct ofp_table_feature_prop_oxm *dst, const struct ofp_table_feature_prop_oxm *src );

void ntoh_table_feature_prop_experimenter( struct ofp_table_feature_prop_experimenter *dst, const struct ofp_table_feature_prop_experimenter *src );
void hton_table_feature_prop_experimenter( struct ofp_table_feature_prop_experimenter *dst, const struct ofp_table_feature_prop_experimenter *src );

void ntoh_table_feature_prop_header( struct ofp_table_feature_prop_header *dst, const struct ofp_table_feature_prop_header *src );
void hton_table_feature_prop_header( struct ofp_table_feature_prop_header *dst, const struct ofp_table_feature_prop_header *src );

void ntoh_table_features( struct ofp_table_features *dst, const struct ofp_table_features *src );
void hton_table_features( struct ofp_table_features *dst, const struct ofp_table_features *src );

void ntoh_bucket_counter( struct ofp_bucket_counter *dst, const struct ofp_bucket_counter *src );
#define hton_bucket_counter ntoh_bucket_counter

void ntoh_group_stats( struct ofp_group_stats *dst, const struct ofp_group_stats *src );
void hton_group_stats( struct ofp_group_stats *dst, const struct ofp_group_stats *src );

void ntoh_group_desc( struct ofp_group_desc *dst, const struct ofp_group_desc *src );
void hton_group_desc( struct ofp_group_desc *dst, const struct ofp_group_desc *src );

void ntoh_group_features_stats( struct ofp_group_features *dst, const struct ofp_group_features *src );
#define hton_group_features_stats ntoh_group_features_stats

void ntoh_meter_band_stats( struct ofp_meter_band_stats *dst, const struct ofp_meter_band_stats *src );
#define hton_meter_band_stats ntoh_meter_band_stats

void ntoh_meter_stats( struct ofp_meter_stats *dst, const struct ofp_meter_stats *src );
void hton_meter_stats( struct ofp_meter_stats *dst, const struct ofp_meter_stats *src );

void ntoh_meter_config( struct ofp_meter_config *dst, const struct ofp_meter_config *src );
void hton_meter_config( struct ofp_meter_config *dst, const struct ofp_meter_config *src );

void ntoh_meter_features( struct ofp_meter_features *dst, const struct ofp_meter_features *src );
#define hton_meter_features ntoh_meter_features


#endif // BYTEORDER_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
