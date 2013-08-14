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


#ifndef STATS_HELPER_H
#define STATS_HELPER_H


#ifdef __cplusplus
extern "C" {
#endif


#define SEND_STATS( stats_type, transaction_id, flags, list ) \
  int offset = 0; \
  do {                                                        \
    int more = 0; \
    buffer *msg = create_##stats_type##_multipart_reply( transaction_id, flags, list, &more, &offset ); \
    switch_send_openflow_message( msg ); \
    free_buffer( msg );                  \
    if ( more == 0) break; \
  } while( 1 )


void ( *handle_desc )( const uint32_t transaction_id, const char *progname );
void ( *handle_flow_stats )( const struct ofp_flow_stats_request *req, const uint32_t transaction_id, const uint32_t capabilities );
void ( *handle_aggregate_stats )( const struct ofp_aggregate_stats_request *req, const uint32_t transaction_id, const uint32_t capabilities );
void ( *handle_table_stats )( const uint32_t transaction_id, const uint32_t capabilities );
void ( *handle_port_stats )( const struct ofp_port_stats_request *req, const uint32_t transaction_id, const uint32_t capabilities );
void ( *handle_group_stats )( const struct ofp_group_stats_request *req, const uint32_t transaction_id, const uint32_t capabilities );
void ( *handle_group_desc )( const uint32_t transaction_id, const uint32_t capabilities );
void ( *handle_table_features )( uint32_t transaction_id );
void ( *handle_port_desc )( const uint32_t transaction_id );
void ( *handle_queue_stats )( const struct ofp_queue_stats_request *req, const uint32_t transaction_id, uint32_t capabilities );
void ( *handle_group_features )( const uint32_t transaction_id, const uint32_t capabilities );
void ( *handle_meter_stats )( const struct ofp_meter_multipart_request *req, const uint32_t transaction_id );
void ( *handle_meter_config )( const struct ofp_meter_multipart_request *req, const uint32_t transaction_id );
void ( *handle_meter_features )( const uint32_t transaction_id );
void ( *handle_experimenter_stats )( const struct ofp_experimenter_multipart_header *em_hdr, const uint32_t transaction_id );


#ifdef __cplusplus
}
#endif


#endif // STATS_HELPER_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
