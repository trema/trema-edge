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


#ifndef PROTOCOL_HANDLER_H
#define PROTOCOL_HANDLER_H


#ifdef __cplusplus
extern "C" {
#endif


void ( *handle_hello )( const uint32_t transaction_id, 
        const uint8_t version, 
        const buffer *version_data, 
        void *user_data );
void ( *handle_features_request )( const uint32_t transaction_id, 
        void *user_data );
void ( *handle_set_config )( const uint32_t transaction_id, 
        const uint16_t flags, 
        uint16_t miss_send_len, 
        void *user_data );
void ( *handle_get_config_request )( const uint32_t transaction_id,
        void *user_data );
void ( *handle_echo_request )( const uint32_t transaction_id, 
        const buffer *body, 
        void *user_data );
void ( *handle_flow_mod )( const uint32_t transaction_id, 
        const uint64_t cookie,
        const uint64_t cookie_mask,
        const uint8_t table_id,
        const uint8_t command,
        const uint16_t idle_timeout,
        const uint16_t hard_timeout,
        const uint16_t priority,
        const uint32_t buffer_id,
        const uint32_t out_port,
        const uint32_t out_group,
        const uint16_t flags,
        const oxm_matches *match,
        const openflow_instructions *instructions,
        void *user_data);
void ( *handle_packet_out )( const uint32_t transaction_id,
        uint32_t buffer_id,
        uint32_t in_port,
        const openflow_actions *actions,
        const buffer *frame, 
        void *user_data );
void ( *handle_port_mod )( uint32_t transaction_id,
        uint32_t port_no,
        uint8_t hw_addr[],
        uint32_t config,
        uint32_t mask,
        uint32_t advertise,
        void *user_data );
void ( *handle_table_mod )( uint32_t transaction_id,
        uint8_t table_id,
        uint32_t config,
        void *user_data );
void ( *handle_group_mod )( const uint32_t transaction_id,
        const uint16_t command,
        const uint8_t type,
        const uint32_t group_id,
        const list_element *buckets,
        void *user_data );
void ( *handle_meter_mod )( const uint32_t transaction_id,
        const uint16_t command,
        const uint16_t flags,
        const uint32_t meter_id,
        const list_element *bands,
        void *user_data );


void ( *handle_multipart_request )( uint32_t transaction_id,
        uint16_t type,
        uint16_t flags,
        const buffer *body,
        void *user_data );
void ( *handle_barrier_request )( uint32_t transaction_id, void *user_data );


#ifdef __cplusplus
}
#endif


#endif // PROTOCOL_HANDLER_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
