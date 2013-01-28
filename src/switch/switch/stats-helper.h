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
  buffer *msg = create_##stats_type##_multipart_reply( transaction_id, flags, list ); \
  switch_send_openflow_message( msg ); \
  free_buffer( msg );


void ( *request_send_flow_stats)( const struct ofp_flow_stats_request *req, const uint32_t transaction_id );
struct ofp_aggregate_stats_reply * (* request_aggregate_stats)( const struct ofp_aggregate_stats_request *req );
void ( *request_send_table_stats)( const uint32_t transaction_id );
void ( *request_send_port_stats)( const struct ofp_port_stats_request *req, const uint32_t transaction_id );
void ( *request_send_group_stats)( const struct ofp_group_stats_request *req, const uint32_t transaction_id );
list_element * ( *request_group_desc_stats)( void );
void ( *request_send_table_features_stats)( uint32_t transaction_id );
list_element * ( *request_port_desc )( void );
struct ofp_group_features * ( *request_group_features )( void );
const char * ( *mfr_desc )( void );
char * ( *hw_desc )( void );
const char * ( *serial_num )( void );
const char * ( *dp_desc )( void );


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
