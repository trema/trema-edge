/*
 * An OpenFlow message library.
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


#ifndef OPENFLOW_MESSAGE_H
#define OPENFLOW_MESSAGE_H


#include <openflow.h>
#include "bool.h"
#include "buffer.h"
#include "byteorder.h"
#include "oxm_byteorder.h"
#include "linked_list.h"
#include "packet_info.h"
#include "oxm_match.h"


// A structure for storing OpenFlow actions
typedef struct openflow_actions {
  int n_actions;
  list_element *list;
} openflow_actions;

// A structure for storing OpenFlow instructions
typedef struct openflow_instructions {
  int n_instructions;
  list_element *list;
} openflow_instructions;

// A structure for storing OpenFlow buckets
typedef struct openflow_buckets {
  int n_buckets;
  list_element *list;
} openflow_buckets;

// A structure for storing wildcards and masks
typedef struct {
  uint64_t wildcards;
  uint8_t mask_eth_dst[ OFP_ETH_ALEN ];
  uint8_t mask_eth_src[ OFP_ETH_ALEN ];
  uint16_t mask_vlan_vid;
  uint32_t mask_ipv4_src;
  uint32_t mask_ipv4_dst;
  uint32_t mask_arp_spa;
  uint32_t mask_arp_tpa;
  uint8_t mask_arp_sha[ OFP_ETH_ALEN ];
  uint8_t mask_arp_tha[ OFP_ETH_ALEN ];
  struct in6_addr mask_ipv6_src;
  struct in6_addr mask_ipv6_dst;
  uint32_t mask_flabel;
  uint32_t mask_pbb_isid;
  uint64_t mask_tunnel_id;
  uint16_t mask_ipv6_exthdr;
} mask_fields;


// Initialization
bool init_openflow_message( void );

// Functions for creating OpenFlow messages
buffer *create_hello( const uint32_t transaction_id, const buffer *elements );
buffer *create_hello_elem_versionbitmap( const uint8_t *ofp_versions, const uint16_t n_versions );
buffer *create_error( const uint32_t transaction_id, const uint16_t type,
                      const uint16_t code, const buffer *data );
buffer *create_error_experimenter( const uint32_t transaction_id, const uint16_t type,
                                   const uint16_t exp_type, uint32_t experimenter, const buffer *data );
buffer *create_echo_request( const uint32_t transaction_id, const buffer *body );
buffer *create_echo_reply( const uint32_t transaction_id, const buffer *body );
buffer *create_experimenter( const uint32_t transaction_id, const uint32_t experimenter,
                             const uint32_t exp_type, const buffer *data );
buffer *create_features_request( const uint32_t transaction_id );
buffer *create_features_reply( const uint32_t transaction_id, const uint64_t datapath_id,
                               const uint32_t n_buffers, const uint8_t n_tables,
                               const uint8_t auxiliary_id, const uint32_t capabilities );
buffer *create_get_config_request( const uint32_t transaction_id );
buffer *create_get_config_reply( const uint32_t transaction_id, const uint16_t flags,
                                 const uint16_t miss_send_len );
buffer *create_set_config( const uint32_t transaction_id, const uint16_t flags,
                           const uint16_t miss_send_len );
buffer *create_packet_in( const uint32_t transaction_id, const uint32_t buffer_id,
                          const uint16_t total_len, const uint8_t reason,
                          const uint8_t table_id, const uint64_t cookie,
                          const oxm_matches *match, const buffer *data );
buffer *create_flow_removed( const uint32_t transaction_id, const uint64_t cookie,
                             const uint16_t priority, const uint8_t reason, const uint8_t table_id,
                             const uint32_t duration_sec, const uint32_t duration_nsec,
                             const uint16_t idle_timeout, const uint16_t hard_timeout,
                             const uint64_t packet_count, const uint64_t byte_count,
                             const oxm_matches *match );
buffer *create_port_status( const uint32_t transaction_id, const uint8_t reason,
                            const struct ofp_port desc);
buffer *create_packet_out( const uint32_t transaction_id, const uint32_t buffer_id,
                           const uint32_t in_port, const openflow_actions *actions,
                           const buffer *data );
buffer *create_flow_mod( const uint32_t transaction_id, const uint64_t cookie, const uint64_t cookie_mask,
                         const uint8_t table_id, const uint8_t command, const uint16_t idle_timeout,
                         const uint16_t hard_timeout, const uint16_t priority,
                         const uint32_t buffer_id, const uint32_t out_port, const uint32_t out_group,
                         const uint16_t flags, const oxm_matches *match,
                         const openflow_instructions *instructions );
buffer *create_group_mod( const uint32_t transaction_id, const uint16_t command,
                          const uint8_t type, const uint32_t group_id, const openflow_buckets *buckets );
buffer *create_port_mod( const uint32_t transaction_id, const uint32_t port_no,
                         const uint8_t hw_addr[ OFP_ETH_ALEN ], const uint32_t config,
                         const uint32_t mask, const uint32_t advertise );
buffer *create_table_mod( const uint32_t transaction_id, const uint8_t table_id,
                          const uint32_t config );
buffer *create_desc_multipart_request( const uint32_t transaction_id, const uint16_t flags );
buffer *create_flow_multipart_request( const uint32_t transaction_id, const uint16_t flags,
                                       const uint8_t table_id, const uint32_t out_port,
                                       const uint32_t out_group, const uint64_t cookie,
                                       const uint64_t cookie_mask, const oxm_matches *match );
buffer *create_aggregate_multipart_request( const uint32_t transaction_id,
                                            const uint16_t flags, const uint8_t table_id,
                                            const uint32_t out_port, const uint32_t out_group,
                                            const uint64_t cookie, const uint64_t cookie_mask,
                                            const oxm_matches *match );
buffer *create_table_multipart_request( const uint32_t transaction_id, const uint16_t flags );
buffer *create_port_multipart_request( const uint32_t transaction_id, const uint16_t flags,
                                       const uint32_t port_no );
buffer *create_queue_multipart_request( const uint32_t transaction_id, const uint16_t flags,
                                        const uint32_t port_no, const uint32_t queue_id );
buffer *create_group_multipart_request( const uint32_t transaction_id, const uint16_t flags,
                                        const uint32_t group_id );
buffer *create_group_desc_multipart_request( const uint32_t transaction_id, const uint16_t flags );
buffer *create_group_features_multipart_request( const uint32_t transaction_id, const uint16_t flags );
buffer *create_meter_multipart_request( const uint32_t transaction_id, const uint16_t flags,
                                        const uint32_t meter_id );
buffer *create_meter_config_multipart_request( const uint32_t transaction_id, const uint16_t flags,
                                               const uint32_t meter_id );
buffer *create_meter_features_multipart_request( const uint32_t transaction_id, const uint16_t flags );
buffer *create_table_features_multipart_request( const uint32_t transaction_id, const uint16_t flags,
                                                 const list_element *table_features_head );
buffer *create_port_desc_multipart_request( const uint32_t transaction_id, const uint16_t flags );
buffer *create_experimenter_multipart_request( const uint32_t transaction_id, const uint16_t flags,
                                               const uint32_t experimenter, const uint32_t exp_type, const buffer *data );
buffer *create_desc_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                                     const char mfr_desc[ DESC_STR_LEN ],
                                     const char hw_desc[ DESC_STR_LEN ],
                                     const char sw_desc[ DESC_STR_LEN ],
                                     const char serial_num[ SERIAL_NUM_LEN ],
                                     const char dp_desc[ DESC_STR_LEN ] );
buffer *create_flow_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                                     const list_element *flow_multipart_head,
                                     int *more, int *offset );
buffer *create_aggregate_multipart_reply( const uint32_t transaction_id,
                                          const uint16_t flags,
                                          const uint64_t packet_count, const uint64_t byte_count,
                                          const uint32_t flow_count );
buffer *create_table_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                                      const list_element *table_multipart_head,
                                      int *more, int *offset );
buffer *create_port_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                                     const list_element *port_multipart_head,
                                     int *more, int *offset );
buffer *create_queue_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                                      const list_element *queue_multipart_head,
                                      int *more, int *offset );
buffer *create_group_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                                      const list_element *group_multipart_head,
                                      int *more, int *offset );
buffer *create_group_desc_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                                           const list_element *group_desc_multipart_head,
                                           int *more, int *offset );
buffer *create_group_features_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                                               const uint32_t types, const uint32_t capabilities,
                                               const uint32_t max_groups[ 4 ], const uint32_t actions[ 4 ] );
buffer *create_meter_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                                      const list_element *meter_multipart_head,
                                      int *more, int *offset );
buffer *create_meter_config_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                                             const list_element *meter_config_multipart_head,
                                             int *more, int *offset );
buffer *create_meter_features_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                                               const uint32_t max_meter, const uint32_t band_types,
                                               const uint32_t capabilities, const uint8_t max_bands,
                                               const uint8_t max_color );
buffer *create_table_features_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                                               const list_element *table_features_multipart_head,
                                               int *more, int *offset );
buffer *create_port_desc_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                                          const list_element *port_desc_multipart_head,
                                          int *more, int *offset );
buffer *create_experimenter_multipart_reply( const uint32_t transaction_id, const uint16_t flags,
                                             const uint32_t experimenter, const uint32_t exp_type, const buffer *body );
buffer *create_barrier_request( const uint32_t transaction_id );
buffer *create_barrier_reply( const uint32_t transaction_id );
buffer *create_queue_get_config_request( const uint32_t transaction_id, const uint32_t port );
buffer *create_queue_get_config_reply( const uint32_t transaction_id, const uint32_t port,
                                       const list_element *queues );
buffer *create_role_request( const uint32_t transaction_id, const uint32_t role,
                             const uint64_t generation_id );
buffer *create_role_reply( const uint32_t transaction_id, const uint32_t role,
                           const uint64_t generation_id );
buffer *create_get_async_request( const uint32_t transaction_id );
buffer *create_get_async_reply( const uint32_t transaction_id, const uint32_t packet_in_mask[ 2 ],
                                const uint32_t port_status_mask[ 2 ], const uint32_t flow_removed_mask[ 2 ] );
buffer *create_set_async( const uint32_t transaction_id, const uint32_t packet_in_mask[ 2 ],
                          const uint32_t port_status_mask[ 2 ], const uint32_t flow_removed_mask[ 2 ] );
buffer *create_meter_mod( const uint32_t transaction_id, const uint16_t command,
                          const uint16_t flags, const uint32_t meter_id, const list_element *bands );

uint32_t get_transaction_id( void );
uint64_t get_cookie( void );
openflow_actions *create_actions( void );
bool delete_actions( openflow_actions *actions );
uint16_t get_actions_length( const openflow_actions *actions );
bool append_action_output( openflow_actions *actions, const uint32_t port, const uint16_t max_len );
bool append_action_copy_ttl_out( openflow_actions *actions );
bool append_action_copy_ttl_in( openflow_actions *actions );
bool append_action_set_mpls_ttl( openflow_actions *actions, const uint8_t mpls_ttl );
bool append_action_dec_mpls_ttl( openflow_actions *actions );
bool append_action_push_vlan( openflow_actions *actions, const uint16_t ethertype );
bool append_action_pop_vlan( openflow_actions *actions );
bool append_action_push_mpls( openflow_actions *actions, const uint16_t ethertype );
bool append_action_pop_mpls( openflow_actions *actions, const uint16_t ethertype );
bool append_action_set_queue( openflow_actions *actions, const uint32_t queue_id );
bool append_action_group( openflow_actions *actions, const uint32_t group_id );
bool append_action_set_nw_ttl( openflow_actions *actions, const uint8_t nw_ttl );
bool append_action_dec_nw_ttl( openflow_actions *actions );
bool append_action_push_pbb( openflow_actions *actions, const uint16_t ethertype );
bool append_action_pop_pbb( openflow_actions *actions );
bool append_action_experimenter( openflow_actions *actions, const uint32_t experimenter, const buffer *data );
bool append_action_set_field_in_port( openflow_actions *actions, const uint32_t in_port );
bool append_action_set_field_in_phy_port( openflow_actions *actions, const uint32_t in_phy_port );
bool append_action_set_field_metadata( openflow_actions *actions, const uint64_t metadata );
bool append_action_set_field_eth_dst( openflow_actions *actions, const uint8_t eth_dst[ OFP_ETH_ALEN ] );
bool append_action_set_field_eth_src( openflow_actions *actions, const uint8_t eth_src[ OFP_ETH_ALEN ] );
bool append_action_set_field_eth_type( openflow_actions *actions, const uint16_t eth_type );
bool append_action_set_field_vlan_vid( openflow_actions *actions, const uint16_t vlan_vid );
bool append_action_set_field_vlan_pcp( openflow_actions *actions, const uint8_t vlan_pcp );
bool append_action_set_field_ip_dscp( openflow_actions *actions, const uint8_t ip_dscp );
bool append_action_set_field_ip_ecn( openflow_actions *actions, const uint8_t ip_ecn );
bool append_action_set_field_ip_proto( openflow_actions *actions, const uint8_t ip_proto );
bool append_action_set_field_ipv4_src( openflow_actions *actions, const uint32_t ipv4_src );
bool append_action_set_field_ipv4_dst( openflow_actions *actions, const uint32_t ipv4_dst );
bool append_action_set_field_tcp_src( openflow_actions *actions, const uint16_t tcp_src );
bool append_action_set_field_tcp_dst( openflow_actions *actions, const uint16_t tcp_dst );
bool append_action_set_field_udp_src( openflow_actions *actions, const uint16_t udp_src );
bool append_action_set_field_udp_dst( openflow_actions *actions, const uint16_t udp_dst );
bool append_action_set_field_sctp_src( openflow_actions *actions, const uint16_t sctp_src );
bool append_action_set_field_sctp_dst( openflow_actions *actions, const uint16_t sctp_dst );
bool append_action_set_field_icmpv4_type( openflow_actions *actions, const uint8_t icmpv4_type );
bool append_action_set_field_icmpv4_code( openflow_actions *actions, const uint8_t icmpv4_code );
bool append_action_set_field_arp_op( openflow_actions *actions, const uint16_t arp_opcode );
bool append_action_set_field_arp_spa( openflow_actions *actions, const uint32_t arp_spa );
bool append_action_set_field_arp_tpa( openflow_actions *actions, const uint32_t arp_tpa );
bool append_action_set_field_arp_sha( openflow_actions *actions, const uint8_t arp_sha[ OFP_ETH_ALEN ] );
bool append_action_set_field_arp_tha( openflow_actions *actions, const uint8_t arp_tha[ OFP_ETH_ALEN ] );
bool append_action_set_field_ipv6_src( openflow_actions *actions, const struct in6_addr ipv6_src );
bool append_action_set_field_ipv6_dst( openflow_actions *actions, const struct in6_addr ipv6_dst );
bool append_action_set_field_ipv6_flabel( openflow_actions *actions, const uint32_t ipv6_flabel );
bool append_action_set_field_icmpv6_type( openflow_actions *actions, const uint8_t icmpv6_type );
bool append_action_set_field_icmpv6_code( openflow_actions *actions, const uint8_t icmpv6_code );
bool append_action_set_field_ipv6_nd_target( openflow_actions *actions, const struct in6_addr ipv6_nd_target );
bool append_action_set_field_ipv6_nd_sll( openflow_actions *actions, const uint8_t ipv6_nd_sll[ OFP_ETH_ALEN ] );
bool append_action_set_field_ipv6_nd_tll( openflow_actions *actions, const uint8_t ipv6_nd_tll[ OFP_ETH_ALEN ] );
bool append_action_set_field_mpls_label( openflow_actions *actions, const uint32_t mpls_label );
bool append_action_set_field_mpls_tc( openflow_actions *actions, const uint8_t mpls_tc );
bool append_action_set_field_mpls_bos( openflow_actions *actions, const uint8_t mpls_bos );
bool append_action_set_field_pbb_isid( openflow_actions *actions, const uint32_t pbb_isid );
bool append_action_set_field_tunnel_id( openflow_actions *actions, const uint64_t tunnel_id );
bool append_action_set_field_ipv6_exthdr( openflow_actions *actions, const uint16_t ipv6_exthdr );

openflow_instructions *create_instructions( void );
bool delete_instructions( openflow_instructions *instructions );
uint16_t get_instructions_length( const openflow_instructions *instructions );
bool append_instructions_goto_table( openflow_instructions *instructions, uint8_t table_id );
bool append_instructions_write_metadata( openflow_instructions *instructions, uint64_t metadata, uint64_t metadata_mask );
bool append_instructions_write_actions( openflow_instructions *instructions, openflow_actions *actions );
bool append_instructions_apply_actions( openflow_instructions *instructions, openflow_actions *actions );
bool append_instructions_clear_actions( openflow_instructions *instructions );
bool append_instructions_meter( openflow_instructions *instructions, uint32_t meter_id );
bool append_instructions_experimenter( openflow_instructions *instructions, uint32_t experimenter, const buffer *data );

openflow_buckets *create_buckets( void );
bool delete_buckets( openflow_buckets *buckets );
uint16_t get_buckets_length( const openflow_buckets *buckets );
bool append_bucket( openflow_buckets *buckets, uint16_t weight, uint32_t watch_port, uint32_t watch_group, openflow_actions *actions );

// Return code definitions indicating the result of OpenFlow message validation.
enum {
  SUCCESS = 0,
  ERROR_UNSUPPORTED_VERSION = -105,
  ERROR_INVALID_LENGTH,
  ERROR_TOO_SHORT_MESSAGE,
  ERROR_TOO_LONG_MESSAGE,
  ERROR_INVALID_TYPE,
  ERROR_UNDEFINED_TYPE,
  ERROR_UNSUPPORTED_TYPE,
  ERROR_NO_TABLE_AVAILABLE,
  ERROR_INVALID_GROUP_COMMAND,
  ERROR_INVALID_GROUP_TYPE,
  ERROR_INVALID_METER_COMMAND,
  ERROR_INVALID_METER_BAND_TYPE,
  ERROR_INVALID_METER_FLAGS,
  ERROR_INVALID_PORT_NO,
  ERROR_INVALID_PORT_CONFIG,
  ERROR_INVALID_PORT_STATE,
  ERROR_INVALID_PORT_FEATURES,
  ERROR_INVALID_SWITCH_CONFIG,
  ERROR_INVALID_PACKET_IN_REASON,
  ERROR_INVALID_FLOW_REMOVED_REASON,
  ERROR_INVALID_VLAN_VID,
  ERROR_INVALID_VLAN_PCP,
  ERROR_INVALID_IP_DSCP,
  ERROR_INVALID_IP_ECN,
  ERROR_INVALID_IPV6_FLABEL,
  ERROR_INVALID_MPLS_LABEL,
  ERROR_INVALID_MPLS_TC,
  ERROR_INVALID_MPLS_BOS,
  ERROR_INVALID_PBB_ISID,
  ERROR_INVALID_IPV6_EXTHDR,
  ERROR_INVALID_MATCH_TYPE,
  ERROR_BAD_MATCH_PREREQ,
  ERROR_INVALID_CONTROLLER_ROLE,
  ERROR_INVALID_PORT_STATUS_REASON,
  ERROR_TOO_SHORT_QUEUE_DESCRIPTION,
  ERROR_TOO_SHORT_QUEUE_PROPERTY,
  ERROR_TOO_LONG_QUEUE_PROPERTY,
  ERROR_UNDEFINED_QUEUE_PROPERTY,
  ERROR_TOO_SHORT_ACTION,
  ERROR_UNDEFINED_ACTION_TYPE,
  ERROR_INVALID_ACTION_TYPE,
  ERROR_TOO_SHORT_ACTION_OUTPUT,
  ERROR_TOO_LONG_ACTION_OUTPUT,
  ERROR_TOO_SHORT_ACTION_COPY_TTL_OUT,
  ERROR_TOO_LONG_ACTION_COPY_TTL_OUT,
  ERROR_TOO_SHORT_ACTION_COPY_TTL_IN,
  ERROR_TOO_LONG_ACTION_COPY_TTL_IN,
  ERROR_TOO_SHORT_ACTION_SET_MPLS_TTL,
  ERROR_TOO_LONG_ACTION_SET_MPLS_TTL,
  ERROR_TOO_SHORT_ACTION_DEC_MPLS_TTL,
  ERROR_TOO_LONG_ACTION_DEC_MPLS_TTL,
  ERROR_TOO_SHORT_ACTION_PUSH_VLAN,
  ERROR_TOO_LONG_ACTION_PUSH_VLAN,
  ERROR_TOO_SHORT_ACTION_POP_VLAN,
  ERROR_TOO_LONG_ACTION_POP_VLAN,
  ERROR_TOO_SHORT_ACTION_PUSH_MPLS,
  ERROR_TOO_LONG_ACTION_PUSH_MPLS,
  ERROR_TOO_SHORT_ACTION_POP_MPLS,
  ERROR_TOO_LONG_ACTION_POP_MPLS,
  ERROR_TOO_SHORT_ACTION_SET_QUEUE,
  ERROR_TOO_LONG_ACTION_SET_QUEUE,
  ERROR_TOO_SHORT_ACTION_GROUP,
  ERROR_TOO_LONG_ACTION_GROUP,
  ERROR_TOO_SHORT_ACTION_SET_NW_TTL,
  ERROR_TOO_LONG_ACTION_SET_NW_TTL,
  ERROR_TOO_SHORT_ACTION_DEC_NW_TTL,
  ERROR_TOO_LONG_ACTION_DEC_NW_TTL,
  ERROR_TOO_SHORT_ACTION_SET_FIELD,
  ERROR_TOO_LONG_ACTION_SET_FIELD,
  ERROR_TOO_SHORT_ACTION_PUSH_PBB,
  ERROR_TOO_LONG_ACTION_PUSH_PBB,
  ERROR_TOO_SHORT_ACTION_POP_PBB,
  ERROR_TOO_LONG_ACTION_POP_PBB,
  ERROR_TOO_SHORT_ACTION_EXPERIMENTER,
  ERROR_TOO_SHORT_INSTRUCTION,
  ERROR_UNDEFINED_INSTRUCTION_TYPE,
  ERROR_INVALID_INSTRUCTION_TYPE,
  ERROR_TOO_SHORT_INSTRUCTION_GOTO_TABLE,
  ERROR_TOO_LONG_INSTRUCTION_GOTO_TABLE,
  ERROR_TOO_SHORT_INSTRUCTION_WRITE_METADATA,
  ERROR_TOO_LONG_INSTRUCTION_WRITE_METADATA,
  ERROR_TOO_SHORT_INSTRUCTION_WRITE_ACTIONS,
  ERROR_TOO_LONG_INSTRUCTION_WRITE_ACTIONS,
  ERROR_TOO_SHORT_INSTRUCTION_APPLY_ACTIONS,
  ERROR_TOO_LONG_INSTRUCTION_APPLY_ACTIONS,
  ERROR_TOO_SHORT_INSTRUCTION_CLEAR_ACTIONS,
  ERROR_TOO_LONG_INSTRUCTION_CLEAR_ACTIONS,
  ERROR_TOO_SHORT_INSTRUCTION_METER,
  ERROR_TOO_LONG_INSTRUCTION_METER,
  ERROR_TOO_SHORT_INSTRUCTION_EXPERIMENTER,
  ERROR_TOO_LONG_INSTRUCTION_EXPERIMENTER,
  ERROR_UNSUPPORTED_STATS_TYPE,
  ERROR_INVALID_STATS_REPLY_FLAGS,
  ERROR_INVALID_FLOW_PRIORITY,
  ERROR_INVALID_FLOW_MOD_FLAGS,
  ERROR_INVALID_PACKET_IN_MASK,
  ERROR_INVALID_PORT_STATUS_MASK,
  ERROR_INVALID_PORT_MASK,
  ERROR_INVALID_FLOW_REMOVED_MASK,
  ERROR_INVALID_STATS_TYPE,
  ERROR_INVALID_STATS_REQUEST_FLAGS,
  ERROR_UNDEFINED_FLOW_MOD_COMMAND,
  ERROR_TOO_SHORT_HELLO_ELEMENT,
  ERROR_INVALID_HELLO_ELEMENT_LENGTH,
  ERROR_UNDEFINED_HELLO_ELEMENT_TYPE,
  ERROR_UNEXPECTED_ERROR = -255
};


// Functions for validating OpenFlow messages
int validate_hello( const buffer *message );
int validate_error( const buffer *message );
int validate_echo_request( const buffer *message );
int validate_echo_reply( const buffer *message );
int validate_experimenter( const buffer *message );
int validate_features_request( const buffer *message );
int validate_features_reply( const buffer *message );
int validate_get_config_request( const buffer *message );
int validate_get_config_reply( const buffer *message );
int validate_set_config( const buffer *message );
int validate_packet_in( const buffer *message );
int validate_flow_removed( const buffer *message );
int validate_port_status( const buffer *message );
int validate_packet_out( const buffer *message );
int validate_flow_mod( const buffer *message );
int validate_group_mod( const buffer *message );
int validate_port_mod( const buffer *message );
int validate_table_mod( const buffer *message );
int validate_desc_multipart_request( const buffer *message );
int validate_flow_multipart_request( const buffer *message );
int validate_aggregate_multipart_request( const buffer *message );
int validate_table_multipart_request( const buffer *message );
int validate_port_multipart_request( const buffer *message );
int validate_queue_multipart_request( const buffer *message );
int validate_group_multipart_request( const buffer *message );
int validate_group_desc_multipart_request( const buffer *message );
int validate_group_features_multipart_request( const buffer *message );
int validate_meter_multipart_request( const buffer *message );
int validate_meter_config_multipart_request( const buffer *message );
int validate_meter_features_multipart_request( const buffer *message );
int validate_table_features_multipart_request( const buffer *message );
int validate_port_desc_multipart_request( const buffer *message );
int validate_experimenter_multipart_request( const buffer *message );
int validate_desc_multipart_reply( const buffer *message );
int validate_flow_multipart_reply( const buffer *message );
int validate_aggregate_multipart_reply( const buffer *message );
int validate_table_multipart_reply( const buffer *message );
int validate_port_multipart_reply( const buffer *message );
int validate_queue_multipart_reply( const buffer *message );
int validate_group_multipart_reply( const buffer *message );
int validate_group_desc_multipart_reply( const buffer *message );
int validate_group_features_multipart_reply( const buffer *message );
int validate_meter_multipart_reply( const buffer *message );
int validate_meter_config_multipart_reply( const buffer *message );
int validate_meter_features_multipart_reply( const buffer *message );
int validate_table_features_multipart_reply( const buffer *message );
int validate_port_desc_multipart_reply( const buffer *message );
int validate_experimenter_multipart_reply( const buffer *message );
int validate_barrier_request( const buffer *message );
int validate_barrier_reply( const buffer *message );
int validate_queue_get_config_request( const buffer *message );
int validate_queue_get_config_reply( const buffer *message );
int validate_role_request( const buffer *message );
int validate_role_reply( const buffer *message );
int validate_get_async_request( const buffer *message );
int validate_get_async_reply( const buffer *message );
int validate_set_async( const buffer *message );
int validate_meter_mod( const buffer *message );
int validate_actions( struct ofp_action_header *actions_head, const uint16_t length );
int validate_action_output( const struct ofp_action_output *action );
int validate_action_copy_ttl_out( const struct ofp_action_header *action );
int validate_action_copy_ttl_in( const struct ofp_action_header *action );
int validate_action_set_mpls_ttl( const struct ofp_action_mpls_ttl *action );
int validate_action_dec_mpls_ttl( const struct ofp_action_header *action );
int validate_action_push_vlan( const struct ofp_action_push *action );
int validate_action_pop_vlan( const struct ofp_action_header *action );
int validate_action_push_mpls( const struct ofp_action_push *action );
int validate_action_pop_mpls( const struct ofp_action_pop_mpls *action );
int validate_action_set_queue( const struct ofp_action_set_queue *action );
int validate_action_group( const struct ofp_action_group *action );
int validate_action_set_nw_ttl( const struct ofp_action_nw_ttl *action );
int validate_action_dec_nw_ttl( const struct ofp_action_header *action );
int validate_action_set_field( const struct ofp_action_set_field *action );
int validate_action_push_pbb( const struct ofp_action_push *action );
int validate_action_pop_pbb( const struct ofp_action_header *action );
int validate_action_experimenter( const struct ofp_action_experimenter_header *action );
int validate_instructions( struct ofp_instruction *instructions_head, const uint16_t length );
int validate_instructions_goto_table( const struct ofp_instruction_goto_table *instruction );
int validate_instructions_write_metadata( const struct ofp_instruction_write_metadata *instruction );
int validate_instructions_write_actions( struct ofp_instruction_actions *instruction );
int validate_instructions_apply_actions( struct ofp_instruction_actions *instruction );
int validate_instructions_clear_actions( const struct ofp_instruction_actions *instruction );
int validate_instructions_meter( const struct ofp_instruction_meter *instruction );
int validate_instructions_experimenter( const struct ofp_instruction_experimenter *instruction );
int validate_openflow_message( const buffer *message );
bool valid_openflow_message( const buffer *message );

// OFPXMT_OFB_* wildcards specification macro ( for set_match_from_packet() wildcards )
#define WILDCARD_OFB_BIT( OFB_TYPE ) ( ( uint64_t ) 1 << ( OFB_TYPE ) )

// Utility functions
bool get_error_type_and_code( const uint8_t type, const int error_no,
                              uint16_t *error_type, uint16_t *error_code );
void set_match_from_packet( oxm_matches *match, const uint32_t in_port,
                            const mask_fields *mask, const buffer *packet );


#endif // OPENFLOW_MESSAGE_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
