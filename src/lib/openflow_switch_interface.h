/*
 * An OpenFlow switch interface library.
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


#ifndef OPENFLOW_SWITCH_INTERFACE_H
#define OPENFLOW_SWITCH_INTERFACE_H


#include "bool.h"
#include "buffer.h"
#include "openflow.h"
#include "openflow_message.h"


/********************************************************************************
 * Functions for initializing/finalizing the OpenFlow switch interface.
 ********************************************************************************/

bool init_openflow_switch_interface( const uint64_t datapath_id, uint32_t controller_ip, uint16_t controller_port );
bool finalize_openflow_switch_interface( void );
bool openflow_switch_interface_is_initialized( void );


/********************************************************************************
 * Event handler definitions.
 ********************************************************************************/

typedef void ( *controller_connected_handler )(
  void *user_data
);


typedef void ( *controller_disconnected_handler )(
  void *user_data
);


typedef void ( *hello_handler )(
  uint32_t transaction_id,
  uint8_t version,
  const buffer *data,
  void *user_data
);


typedef void ( *switch_error_handler )(
  uint32_t transaction_id,
  uint16_t type,
  uint16_t code,
  const buffer *data,
  void *user_data
);


typedef void ( *switch_experimenter_error_handler )(
  uint32_t transaction_id,
  uint16_t type,
  uint16_t exp_type,
  uint32_t experimenter,
  const buffer *data,
  void *user_data
);


typedef void ( *echo_request_handler )(
  uint32_t transaction_id,
  const buffer *body,
  void *user_data
);


typedef void ( *switch_echo_reply_handler )(
  uint32_t transaction_id,
  const buffer *body,
  void *user_data
);


typedef void ( *switch_experimenter_handler )(
  uint32_t transaction_id,
  uint32_t experimenter,
  uint32_t exp_type,
  const buffer *data,
  void *user_data
);


typedef void ( *features_request_handler )(
  uint32_t transaction_id,
  void *user_data
);


typedef void ( *get_config_request_handler )(
  uint32_t transaction_id,
  void *user_data
);


typedef void ( *set_config_handler )(
  uint32_t transaction_id,
  uint16_t flags,
  uint16_t miss_send_len,
  void *user_data
);


typedef void ( *packet_out_handler )(
  uint32_t transaction_id,
  uint32_t buffer_id,
  uint32_t in_port,
  const openflow_actions *actions,
  const buffer *data,
  void *user_data
);


typedef void ( *flow_mod_handler )(
  uint32_t transaction_id,
  uint64_t cookie,
  uint64_t cookie_mask,
  uint8_t table_id,
  uint8_t command,
  uint16_t idle_timeout,
  uint16_t hard_timeout,
  uint16_t priority,
  uint32_t buffer_id,
  uint32_t out_port,
  uint32_t out_group,
  uint16_t flags,
  const oxm_matches *match,
  const openflow_instructions *instructions,
  void *user_data
);


typedef void ( *group_mod_handler )(
  uint32_t transaction_id,
  uint16_t command,
  uint8_t type,
  uint32_t group_id,
  const list_element *buckets,
  void *user_data
);


typedef void ( *port_mod_handler )(
  uint32_t transaction_id,
  uint32_t port_no,
  uint8_t hw_addr[ OFP_ETH_ALEN ],
  uint32_t config,
  uint32_t mask,
  uint32_t advertise,
  void *user_data
);


typedef void ( *table_mod_handler )(
  uint32_t transaction_id,
  uint8_t table_id,
  uint32_t config,
  void *user_data
);


typedef void ( *multipart_request_handler )(
  uint32_t transaction_id,
  uint16_t type,
  uint16_t flags,
  const buffer *body,
  void *user_data
);


typedef void ( *barrier_request_handler )(
  uint32_t transaction_id,
  void *user_data
);


typedef void ( *queue_get_config_request_handler )(
  uint32_t transaction_id,
  uint32_t port,
  void *user_data
);


typedef void ( *role_request_handler )(
  uint32_t transaction_id,
  uint32_t role,
  uint64_t generation_id,
  void *user_data
);


typedef void ( *get_async_request_handler )(
  uint32_t transaction_id,
  void *user_data
);


typedef void ( *set_async_handler )(
  uint32_t transaction_id,
  uint32_t packet_in_mask[ 2 ],
  uint32_t port_status_mask[ 2 ],
  uint32_t flow_removed_mask[ 2 ],
  void *user_data
);


typedef void ( *meter_mod_handler )(
  uint32_t transaction_id,
  uint16_t command,
  uint16_t flags,
  uint32_t meter_id,
  const list_element *bands,
  void *user_data
);


typedef struct {
  controller_connected_handler controller_connected_callback;
  void *controller_connected_user_data;

  controller_disconnected_handler controller_disconnected_callback;
  void *controller_disconnected_user_data;

  hello_handler hello_callback;
  void *hello_user_data;

  switch_error_handler error_callback;
  void *error_user_data;

  switch_experimenter_error_handler experimenter_error_callback;
  void *experimenter_error_user_data;

  echo_request_handler echo_request_callback;
  void *echo_request_user_data;

  switch_echo_reply_handler echo_reply_callback;
  void *echo_reply_user_data;

  switch_experimenter_handler experimenter_callback;
  void *experimenter_user_data;

  features_request_handler features_request_callback;
  void *features_request_user_data;

  get_config_request_handler get_config_request_callback;
  void *get_config_request_user_data;

  set_config_handler set_config_callback;
  void *set_config_user_data;

  packet_out_handler packet_out_callback;
  void *packet_out_user_data;

  flow_mod_handler flow_mod_callback;
  void *flow_mod_user_data;

  group_mod_handler group_mod_callback;
  void *group_mod_user_data;
  
  port_mod_handler port_mod_callback;
  void *port_mod_user_data;

  table_mod_handler table_mod_callback;
  void *table_mod_user_data;

  multipart_request_handler multipart_request_callback;
  void *multipart_request_user_data;

  barrier_request_handler barrier_request_callback;
  void *barrier_request_user_data;

  queue_get_config_request_handler queue_get_config_request_callback;
  void *queue_get_config_request_user_data;
  
  role_request_handler role_request_callback;
  void *role_request_user_data;
  
  get_async_request_handler get_async_request_callback;
  void *get_async_request_user_data;
  
  set_async_handler set_async_callback;
  void *set_async_user_data;
  
  meter_mod_handler meter_mod_callback;
  void *meter_mod_user_data;
} openflow_switch_event_handlers;


/********************************************************************************
 * Functions for setting callback functions for OpenFlow related events.
 ********************************************************************************/

bool set_openflow_switch_event_handlers( const openflow_switch_event_handlers handlers );
bool set_controller_connected_handler( controller_connected_handler callback, void *user_data );
bool set_controller_disconnected_handler( controller_disconnected_handler callback, void *user_data );
bool set_hello_handler( hello_handler callback, void *user_data );
bool switch_set_error_handler( switch_error_handler callback, void *user_data );
bool switch_set_experimenter_error_handler( switch_experimenter_error_handler callback, void *user_data );
bool set_echo_request_handler( echo_request_handler callback, void *user_data );
bool switch_set_echo_reply_handler( switch_echo_reply_handler callback, void *user_data );
bool switch_set_experimenter_handler( switch_experimenter_handler callback, void *user_data );
bool set_features_request_handler( features_request_handler callback, void *user_data );
bool set_get_config_request_handler( get_config_request_handler callback, void *user_data );
bool set_set_config_handler( set_config_handler callback, void *user_data );
bool set_packet_out_handler( packet_out_handler callback, void *user_data );
bool set_flow_mod_handler( flow_mod_handler callback, void *user_data );
bool set_group_mod_handler( group_mod_handler callback, void *user_data );
bool set_port_mod_handler( port_mod_handler callback, void *user_data );
bool set_table_mod_handler( table_mod_handler callback, void *user_data );
bool set_multipart_request_handler( multipart_request_handler callback, void *user_data );
bool set_barrier_request_handler( barrier_request_handler callback, void *user_data );
bool set_queue_get_config_request_handler( queue_get_config_request_handler callback, void *user_data );
bool set_role_request_handler( role_request_handler callback, void *user_data );
bool set_get_async_request_handler( get_async_request_handler callback, void *user_data );
bool set_set_async_handler( set_async_handler callback, void *user_data );
bool set_meter_mod_handler( meter_mod_handler callback, void *user_data );

/********************************************************************************
 * Function for sending/receiving OpenFlow messages.
 ********************************************************************************/

bool switch_send_openflow_message( buffer *message );
bool handle_secure_channel_message( buffer *message );
bool send_error_message( uint32_t transaction_id, uint16_t type, uint16_t code );


#endif // OPENFLOW_SWITCH_INTERFACE_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
