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
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include "trema.h"
#include "ofdp.h"
#include "action-helper.h"
#include "group-helper.h"
#include "meter-helper.h"
#include "instruction-helper.h"
#include "oxm-helper.h"
#include "parse-options.h"
#include "protocol.h"
#include "stats-helper.h"


#ifdef UNIT_TESTING

// Allow static functions to be called from unit tests.
#define static
#define switch_send_openflow_message mock_switch_send_openflow_message
bool mock_switch_send_openflow_message( buffer *message );


#endif // UNIT_TESTING


static void
_handle_hello( const uint32_t transaction_id, const uint8_t version, const buffer *elements, void *user_data ) {
  UNUSED( elements );

  assert( user_data != NULL );

  struct protocol *protocol = user_data;

  debug( "Hello received ( transaction_id = %#x, version = %#x ).", transaction_id, version );

  uint8_t supported_versions[ 1 ] = { OFP_VERSION };
  buffer *element = create_hello_elem_versionbitmap( supported_versions, sizeof( supported_versions ) / sizeof( supported_versions[ 0 ] ) );
  buffer *buf = create_hello( transaction_id, element );
  free_buffer( element );
  bool ret = switch_send_openflow_message( buf );
  if ( ret ) {
    switch_features features;
    memset( &features, 0, sizeof( switch_features ) );
    get_switch_features( &features );
    protocol->ctrl.controller_connected = true;
    protocol->ctrl.capabilities = features.capabilities;
  }
  free_buffer( buf );
}
void ( *handle_hello )( const uint32_t transaction_id,
        const uint8_t version,
        const buffer *version_data,
        void *user_data ) = _handle_hello;


static void
_handle_features_request( const uint32_t transaction_id, void *user_data ) {
  UNUSED( user_data );

  switch_features features;
  memset( &features, 0, sizeof( switch_features ) );
  get_switch_features( &features );
  /*
   * The n_buffers field specifies the maximum number of packets the switch can
   * buffer when sending packets to the controller using packet-in messages.
   */
  buffer *features_reply = create_features_reply( transaction_id, features.datapath_id, features.n_buffers,
                                                  features.n_tables, features.auxiliary_id, features.capabilities );
  switch_send_openflow_message( features_reply );
  free_buffer( features_reply );
}
void ( *handle_features_request )( const uint32_t transaction_id, void *user_data ) = _handle_features_request;


// protocol to datapath message.
static void
_handle_set_config( const uint32_t transaction_id, const uint16_t flags, uint16_t miss_send_len, void *user_data ) {
  UNUSED( user_data );

  switch_config config;
  memset( &config, 0, sizeof( switch_config ) );
  config.flags = flags;
  config.miss_send_len = miss_send_len;
  OFDPE ret = set_switch_config( &config );
  if ( ret != OFDPE_SUCCESS ) {
    uint16_t type = OFPET_SWITCH_CONFIG_FAILED;
    uint16_t code = OFPSCFC_EPERM;
    get_ofp_error( ret, &type, &code );
    send_error_message( transaction_id, type, code );
  }
}
void ( *handle_set_config )( const uint32_t transaction_id, const uint16_t flags, uint16_t miss_send_len, void *user_data ) = _handle_set_config;


static void
_handle_get_config_request( const uint32_t transaction_id, void * user_data ) {
  UNUSED( user_data );
  
  switch_config config;
  memset( &config, 0, sizeof( switch_config ) );

  OFDPE ret = get_switch_config( &config );
  if ( ret != OFDPE_SUCCESS ) {
    uint16_t type = OFPET_BAD_REQUEST;
    uint16_t code = OFPBRC_EPERM;
    get_ofp_error( ret, &type, &code );
    send_error_message( transaction_id, type, code );
  }

  buffer *get_config_reply = create_get_config_reply( transaction_id, config.flags, config.miss_send_len );
  switch_send_openflow_message( get_config_reply );
  free_buffer( get_config_reply );
}
void ( *handle_get_config_request )( const uint32_t transaction_id, void *user_data ) = _handle_get_config_request;


static void
_handle_echo_request( const uint32_t transaction_id, const buffer *body, void *user_data ) {
  UNUSED( user_data );
  buffer *echo_reply = create_echo_reply( transaction_id, body );
  switch_send_openflow_message( echo_reply );
  free_buffer( echo_reply );
}
void ( *handle_echo_request )( const uint32_t transaction_id, const buffer *body, void *user_data ) = _handle_echo_request;


static void
handle_flow_mod_add( const uint32_t transaction_id, const uint64_t cookie, 
                     const uint64_t cookie_mask, const uint8_t table_id,
                     const uint16_t idle_timeout, const uint16_t hard_timeout,
                     const uint16_t priority, const uint32_t buffer_id,
                     const uint16_t flags, const oxm_matches *oxm,
                     const openflow_instructions *instructions,
                     struct protocol *protocol ) {
  UNUSED( cookie_mask );
  /*
   * currently if flags set OFPFF_SEND_FLOW_REM and OFPFF_RESET_COUNTS are the only allowed value.
   */
  if ( ( flags & ~( OFPFF_SEND_FLOW_REM | OFPFF_RESET_COUNTS ) ) != 0 ) {
    send_error_message( transaction_id, OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_FLAGS );
    return;
  }
  /*
   * The use of OFPTT_ALL is only valid for delete requests.
   */
  if ( table_id == OFPTT_ALL ) {
    send_error_message( transaction_id, OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_TABLE_ID );
    return;
  }

  /*
   * If no buffered packet is associated with a flow mod it must be set
   * to OFP_NO_BUFFER otherwise it must be equal to the buffer_id sent to
   * controller by a packet-in message.
   */

  match *match = create_match();
  if ( oxm != NULL && oxm->n_matches > 0 ) {
    
#ifdef DEBUG    
    char oxm_str[ 2048 ];
    match_to_string( oxm, oxm_str, sizeof( oxm_str ) );
    printf( "%s\n", oxm_str );
#endif
    
    for ( list_element *e = oxm->list; e != NULL; e = e->next ) {
      oxm_match_header *hdr = e->data;
      assign_match( match, hdr );
    }
  }

  instruction_set *instruction_set = create_instruction_set();
  if ( instructions != NULL ) {
    OFDPE ret = assign_instructions( instruction_set, instructions->list );
    if ( ret != OFDPE_SUCCESS ) {
      send_error_message( transaction_id, OFPET_FLOW_MOD_FAILED, OFPBIC_UNSUP_INST );
      delete_instruction_set( instruction_set );
      delete_match( match );
      return;
    }
  }

  /*
   * When a flow entry is inserted in a table, its flags field is set with the
   * values from the message.
   * When a flow entry is inserted in a table, its idle_timeout and
   * hard_timeout fields are set with the values from the message.
   * When a flow entry is inserted in a table through an OFPFC_ADD message,
   * its cookie field is set to the provided value
   */
  flow_entry *new_entry = alloc_flow_entry( match, instruction_set, priority,
                                            idle_timeout, hard_timeout, flags, cookie );
  if ( new_entry == NULL ) {
    /*
     * TODO we should send a more appropriate error once we worked out the
     * datapath errors.
     */
    delete_instruction_set( instruction_set );
    delete_match( match );
    send_error_message( transaction_id, OFPET_FLOW_MOD_FAILED, OFPFMFC_UNKNOWN );
    return;
  }

  OFDPE ret = add_flow_entry( table_id, new_entry, flags );
  if ( ret != OFDPE_SUCCESS ) {
    error( "Failed to add a flow entry ( ret = %d ).", ret );
    delete_instruction_set( instruction_set );
    delete_match( match );

    uint16_t type = OFPET_FLOW_MOD_FAILED;
    uint16_t code = OFPFMFC_UNKNOWN;
    get_ofp_error( ret, &type, &code );
    send_error_message( transaction_id, type, code );
    return;
  }

  if ( buffer_id != OFP_NO_BUFFER ) {
    action_list *actions = create_action_list();
    action *action = create_action_output( OFPP_TABLE, UINT16_MAX );
    append_action( actions, action );
    ret = execute_packet_out( buffer_id, 0, actions, NULL );
    delete_action_list( actions );
    if ( ret != OFDPE_SUCCESS ) {
      uint16_t type = OFPET_FLOW_MOD_FAILED;
      uint16_t code = OFPFMFC_UNKNOWN;
      get_ofp_error( ret, &type, &code );
      send_error_message( transaction_id, type, code );
      return;
    }
    wakeup_datapath( protocol );
  }
}


static void
handle_flow_mod_delete( const uint32_t transaction_id, const uint64_t cookie,
                        const uint64_t cookie_mask, const uint8_t table_id,
                        const uint16_t idle_timeout, const uint16_t hard_timeout,
                        const uint16_t priority, const uint32_t buffer_id,
                        const uint32_t out_port, const uint32_t out_group,
                        const uint16_t flags, const oxm_matches *oxm_match,
                        const openflow_instructions *instructions,
                        const bool strict ) {

  UNUSED( idle_timeout );
  UNUSED( hard_timeout );
  UNUSED( priority );
  UNUSED( buffer_id );
  UNUSED( flags );
  UNUSED( instructions );
  
  match *match = create_match();
  if ( oxm_match != NULL && oxm_match->n_matches > 0 ) {
    for ( list_element *e = oxm_match->list; e != NULL; e = e->next ) {
      oxm_match_header *hdr = e->data;
      assign_match( match, hdr );
    }
  }

  OFDPE ret = OFDPE_FAILED;
  if ( strict ) {
    ret = delete_flow_entry_strict( table_id, match, cookie, cookie_mask, priority, out_port, out_group );
  }
  else {
    ret = delete_flow_entries( table_id, match, cookie, cookie_mask, out_port, out_group );
  }

  if ( ret != OFDPE_SUCCESS ) {
    uint16_t type = OFPET_FLOW_MOD_FAILED;
    uint16_t code = OFPFMFC_UNKNOWN;
    get_ofp_error( ret, &type, &code );
    send_error_message( transaction_id, type, code );
  }

  delete_match( match );
}


static void
handle_flow_mod_mod( const uint32_t transaction_id, const uint64_t cookie, 
                     const uint64_t cookie_mask, const uint8_t table_id,
                     const uint16_t idle_timeout, const uint16_t hard_timeout,
                     const uint16_t priority, const uint32_t buffer_id,
                     const uint16_t flags, const oxm_matches *oxm,
                     const openflow_instructions *instructions,
                     const bool strict, struct protocol *protocol ) {

  match *match = create_match( );
  if ( oxm != NULL && oxm->n_matches > 0 ) {
    for ( list_element *e = oxm->list; e != NULL; e = e->next ) {
      oxm_match_header *hdr = e->data;
      assign_match( match, hdr );
    }
  }

  instruction_set *ins_set = create_instruction_set();
  if ( instructions != NULL ) {
    OFDPE ret = assign_instructions( ins_set, instructions->list );
    if ( ret != OFDPE_SUCCESS ) {
      send_error_message( transaction_id, OFPET_FLOW_MOD_FAILED, OFPBIC_UNSUP_INST );
      delete_instruction_set( ins_set );
      delete_match( match );
      return;
    }
  }

  OFDPE ret = update_or_add_flow_entry( table_id, match, cookie, cookie_mask, priority, idle_timeout, hard_timeout,
                                        flags, strict, ins_set );
  delete_instruction_set( ins_set );
  delete_match( match );
  if ( ret != OFDPE_SUCCESS ) {
    uint16_t type = OFPET_FLOW_MOD_FAILED;
    uint16_t code = OFPFMFC_UNKNOWN;
    get_ofp_error( ret, &type, &code );
    send_error_message( transaction_id, type, code );
    return;
  }

  if ( buffer_id != OFP_NO_BUFFER ) {
    action_list *actions = create_action_list();
    action *action = create_action_output( OFPP_TABLE, UINT16_MAX );
    append_action( actions, action );
    ret = execute_packet_out( buffer_id, 0, actions, NULL );
    delete_action_list( actions );
    if ( ret != OFDPE_SUCCESS ) {
      uint16_t type = OFPET_FLOW_MOD_FAILED;
      uint16_t code = OFPFMFC_UNKNOWN;
      get_ofp_error( ret, &type, &code );
      send_error_message( transaction_id, type, code );
      return;
    }
    wakeup_datapath( protocol );
  }
}


static void
_handle_flow_mod( const uint32_t transaction_id,
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
                  const oxm_matches *oxm,
                  const openflow_instructions *instructions,
                  void *user_data
  ) {
  assert( user_data );
  struct protocol *protocol = user_data;
  bool strict = false;

  switch ( command ) {
    case OFPFC_ADD:
      /*
       * The cookie_mask field is ignored for this command.
       * TODO the datapath flow entry contains no buffer_id field to set.
       * From observation datapath buffers every packet regardless of buffer_id
       */
      handle_flow_mod_add( transaction_id, cookie, cookie_mask,
                           table_id, idle_timeout, hard_timeout,
                           priority, buffer_id, flags, oxm,
                           instructions, protocol );
    break;
    case OFPFC_MODIFY:
      /*
       * The idle_timeout and hard_timeout fields are ignored.
       * Also the out_port and out_group fields are ignored.
       * When a flow entry is matched or modified the flags field is ignored.
       * When a flow entry is modified its cookie field is unchanged.
       */
      handle_flow_mod_mod( transaction_id, cookie, cookie_mask, table_id,
                           idle_timeout, hard_timeout, priority, buffer_id,
                           flags, oxm, instructions, strict, protocol );
    break;
    case OFPFC_MODIFY_STRICT:
      strict = true;
      handle_flow_mod_mod( transaction_id, cookie, cookie_mask, table_id,
                           idle_timeout, hard_timeout, priority, buffer_id,
                           flags, oxm, instructions, strict, protocol );
    break;
    case OFPFC_DELETE:
      /*
       * The out_port and out_group introduce a constraint when matching
       * flow entries.
       */
      handle_flow_mod_delete( transaction_id, cookie, cookie_mask,
                              table_id, idle_timeout, hard_timeout,
                              priority, buffer_id, out_port,
                              out_group, flags, oxm,
                              instructions, strict );
    break;
    case OFPFC_DELETE_STRICT:
      strict = true;
      handle_flow_mod_delete( transaction_id, cookie, cookie_mask, table_id,
                              idle_timeout, hard_timeout, priority, buffer_id,
                              out_port, out_group, flags, oxm,
                              instructions, strict );
    break;
    default:
      warn( "Undefined flow mod command type %d", command );
      send_error_message( transaction_id, OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_COMMAND );
    break;
  }
}
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
        void *user_data) = _handle_flow_mod;


static void
_handle_packet_out( const uint32_t transaction_id, uint32_t buffer_id, 
                    uint32_t in_port, const openflow_actions *actions,
                    const buffer *frame, void *user_data ) {
  UNUSED( transaction_id );

  struct protocol *protocol = user_data;

  action_list *ac_list = create_action_list();
  if ( actions != NULL ) {
    for ( list_element *e = actions->list; e != NULL; e = e->next ) {
      struct ofp_action_header *ac_hdr = e->data;
      ac_list = assign_actions( ac_list, ac_hdr, ac_hdr->len );
    }
  }
  buffer *duplicated = NULL;
  if ( frame != NULL && frame->length > 0 ) {
    duplicated = duplicate_buffer( frame );
  }
  execute_packet_out( buffer_id, in_port, ac_list, duplicated );
  wakeup_datapath( protocol );
  delete_action_list( ac_list );
  if ( duplicated != NULL ) {
    free_buffer( duplicated );
  }
}
void ( *handle_packet_out )( uint32_t transaction_id, uint32_t buffer_id,
                           uint32_t in_port, const openflow_actions *actions,
                           const buffer *frame, void *user_data ) = _handle_packet_out;


static void
_handle_port_mod( uint32_t transaction_id, uint32_t port_no, uint8_t hw_addr[],
                  uint32_t config, uint32_t mask, uint32_t advertise, void *user_data ) {
  UNUSED( hw_addr );
  UNUSED( advertise );
  UNUSED( user_data );
  
  /*
   * the update_port_config() performs a port lookup.
   */
  OFDPE ret = update_port( port_no, config, mask );
  if ( ret != OFDPE_SUCCESS ) {
    uint16_t type = OFPET_PORT_MOD_FAILED;
    uint16_t code = OFPPMFC_EPERM;
    get_ofp_error( ret, &type, &code );
    send_error_message( transaction_id, type, code );
  }
}
void ( *handle_port_mod )( uint32_t transaction_id, uint32_t port_no, uint8_t hw_addr[],
  uint32_t config, uint32_t mask, uint32_t advertise, void *user_data ) = _handle_port_mod;


static void
_handle_table_mod( uint32_t transaction_id, uint8_t table_id, uint32_t config,
  void *user_data ) {
  UNUSED( user_data );
  
  if ( set_flow_table_config( table_id, config ) != OFDPE_SUCCESS ) {
    send_error_message( transaction_id, OFPET_TABLE_MOD_FAILED, OFPTMFC_EPERM );    
  }
}
void ( *handle_table_mod )( uint32_t transaction_id, uint8_t table_id, uint32_t config,
  void *user_data ) = _handle_table_mod;


static void
_handle_group_mod( const uint32_t transaction_id,
        const uint16_t command,
        const uint8_t type,
        const uint32_t group_id,
        const list_element *buckets,
        void *user_data ) {
  UNUSED( user_data );
  switch( command ) {
    case OFPGC_ADD:
      handle_group_add( transaction_id, type, group_id, buckets );
    break;
    case OFPGC_MODIFY:
      handle_group_mod_mod( transaction_id, type, group_id, buckets );
    break;
    case OFPGC_DELETE:
      handle_group_mod_delete( transaction_id, group_id );
    break;
    default:
      send_error_message( transaction_id, OFPET_GROUP_MOD_FAILED, OFPGMFC_BAD_COMMAND );
    break;
  }
}
void ( *handle_group_mod )( const uint32_t transaction_id, const uint16_t command, const uint8_t type, const uint32_t group_id, const list_element *buckets, void *user_data ) = _handle_group_mod;


static void
_handle_meter_mod( const uint32_t transaction_id,
        const uint16_t command,
        const uint16_t flags,
        const uint32_t meter_id,
        const list_element *bands,
        void *user_data ) {
  UNUSED( user_data );
  switch( command ) {
    case OFPMC_ADD:
      handle_meter_mod_add( transaction_id, flags, meter_id, bands );
    break;
    case OFPMC_MODIFY:
      handle_meter_mod_mod( transaction_id, flags, meter_id, bands );
    break;
    case OFPMC_DELETE:
      handle_meter_mod_delete( transaction_id, meter_id );
    break;
    default:
      send_error_message( transaction_id, OFPET_METER_MOD_FAILED, OFPMMFC_BAD_COMMAND );
    break;
  }
}
void ( *handle_meter_mod)( const uint32_t transaction_id, const uint16_t command, const uint16_t flags, const uint32_t meter_id, const list_element *bands, void *user_data ) = _handle_meter_mod;


static void
shrink_array( struct outstanding_request outstanding_requests[], int pos ) {
  memset( &outstanding_requests[ pos ], 0, sizeof( struct outstanding_request ) );

  for ( int i = pos; i < MAX_OUTSTANDING_REQUESTS  - 1; i++ ) {
    outstanding_requests[ i ] = outstanding_requests[ i + 1 ];
  }
}


static int
save_outstanding_request( struct protocol_ctrl *ctrl, const uint32_t transaction_id, const uint16_t type, const uint16_t flags ) {
  int i;
  int error = 0;

  // search for an request entry
  for ( i = 0; i < MAX_OUTSTANDING_REQUESTS; i++ ) {
    if ( ctrl->outstanding_requests[ i ].transaction_id == transaction_id && 
      ctrl->outstanding_requests[ i ].type == type ) {
      break;
    }
  }
  /*
   * a request entry is found and the flags is not set to OFPMPF_REQ_MORE.
   * remove the entry from the array.
   */
  if ( i < MAX_OUTSTANDING_REQUESTS  ) {
    if ( ( flags & OFPMPF_REQ_MORE ) == 0 ) {
      shrink_array( ctrl->outstanding_requests, i );
      ctrl->nr_requests--;
    }
  } else {
    /*
     * a request entry is not found but there is to store it and the flags
     * is set to OFPMPF_REQ_MORE
     */
    if ( ctrl->nr_requests < MAX_OUTSTANDING_REQUESTS ) {
      if ( ( flags & OFPMPF_REQ_MORE ) == OFPMPF_REQ_MORE ) {
        i = MAX_OUTSTANDING_REQUESTS - 1; // overwrite the last one
        ctrl->outstanding_requests[ i ].transaction_id = transaction_id;
        ctrl->outstanding_requests[ i ].type = type;
        ctrl->outstanding_requests[ i ].flags = flags;
        ctrl->nr_requests++;
      }
    } else {
      /*
       * the only error condition to flag no more room to accept further
       * requests
       */
      error = -1;
    }
  }

  return error;
}


static void
_handle_multipart_request( uint32_t transaction_id, uint16_t type, uint16_t flags, const buffer *body, void *user_data ) {

  struct protocol *protocol = user_data;
  assert( protocol );
  if ( save_outstanding_request( &protocol->ctrl, transaction_id, type, flags ) == -1 ) {
    send_error_message( transaction_id, OFPET_BAD_REQUEST, OFPBRC_MULTIPART_BUFFER_OVERFLOW );
    return;
  }
  const uint32_t capabilities = protocol->ctrl.capabilities;
  switch( type ) {
    case OFPMP_DESC: {
      // the request body is empty
      handle_desc( transaction_id, protocol->args->progname );
    }
    break;
    case OFPMP_FLOW: {
      const struct ofp_flow_stats_request *req = ( const struct ofp_flow_stats_request * ) body->data;
      handle_flow_stats( req, transaction_id, capabilities );
    }
    break;
    case OFPMP_AGGREGATE: {
      const struct ofp_aggregate_stats_request *req = ( const struct ofp_aggregate_stats_request * ) body->data;
      handle_aggregate_stats( req, transaction_id, capabilities );
    }
    break;
    case OFPMP_TABLE: {
      // no request body is included with this type.
      handle_table_stats( transaction_id, capabilities );
    }
    break;
    case OFPMP_PORT_STATS: {
      const struct ofp_port_stats_request *req = ( const struct ofp_port_stats_request * ) body->data;
      handle_port_stats( req, transaction_id, capabilities );
    }
    break;
    case OFPMP_PORT_DESC: {
      // no request body is included with this type.
      handle_port_desc( transaction_id );
    }
    break;
    case OFPMP_QUEUE: {
      const struct ofp_queue_stats_request *req = ( const struct ofp_queue_stats_request * ) body->data;
      handle_queue_stats( req, transaction_id, capabilities );
    }
    break;
    case OFPMP_GROUP: {
      const struct ofp_group_stats_request *req = ( const struct ofp_group_stats_request * ) body->data;
      handle_group_stats( req, transaction_id, capabilities );
    }
    break;
    case OFPMP_GROUP_DESC: {
      // the request body is empty.
      handle_group_desc( transaction_id, capabilities );
    }
    break;
    case OFPMP_GROUP_FEATURES: {
      handle_group_features( transaction_id, capabilities );
    }
    break;
    case OFPMP_METER: {
      const struct ofp_meter_multipart_request *req = ( const struct ofp_meter_multipart_request * ) body->data;
      handle_meter_stats( req, transaction_id );
    }
    break;
    case OFPMP_METER_CONFIG: {
      const struct ofp_meter_multipart_request *req = ( const struct ofp_meter_multipart_request * ) body->data;
      handle_meter_config( req, transaction_id );
    }
    break;
    case OFPMP_METER_FEATURES: {
      handle_meter_features( transaction_id );
    }
    break;
    case OFPMP_TABLE_FEATURES: {
      /*
       * TODO Currently the setting of table features not supported by datapath
       */
      handle_table_features( transaction_id );
    }
    break;
    case OFPMP_EXPERIMENTER: {
      const struct ofp_experimenter_multipart_header *em_hdr = ( const struct ofp_experimenter_multipart_header * ) body->data;
      handle_experimenter_stats( em_hdr, transaction_id );
    }
    break;
    default:
      send_error_message( transaction_id, OFPET_BAD_REQUEST, OFPBRC_BAD_MULTIPART );
    break;
  }
}
void ( *handle_multipart_request )( uint32_t transaction_id, uint16_t type, uint16_t flags, const buffer *body, void *user_data ) = _handle_multipart_request;


static void
_handle_barrier_request( uint32_t transaction_id, void *user_data ) {
  UNUSED( user_data );
  buffer *barrier_reply = create_barrier_reply( transaction_id ); 
  switch_send_openflow_message( barrier_reply );
  free_buffer( barrier_reply );
}
void ( *handle_barrier_request )( uint32_t transaction_id, void *user_data ) = _handle_barrier_request;


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
