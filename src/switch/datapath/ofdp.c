/*
 * Copyright (C) 2012-2013 NEC Corporation
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


#include <stdint.h>
#include "async_event_notifier.h"
#include "ofdp.h"
#include "pipeline.h"


enum {
  NOT_INITIALIZED = 0,
  SAFE_EVENT_HANDLER_INITIALIZED = 1 << 0,
  SAFE_TIMER_INITIALIZED = 1 << 1,
  TABLE_MANAGER_INITIALIZED = 1 << 2,
  PORT_MANAGER_INITIALIZED = 1 << 3,
  ASYNC_EVENT_NOTIFIER_INITIALIZED = 1 << 4,
  PIPELINE_INITIALIZED = 1 << 5,
  INITIALIZED = 1 << 6,
  RUNNING = 1 << 7,
};


typedef struct {
  uint64_t datapath_id;
  unsigned int n_packet_buffers;
  size_t max_send_queue;
  size_t max_recv_queue;
  uint32_t max_flow_entries;
  switch_features features;
  switch_config config;
} ofdp_config;


uint16_t MISS_SEND_LEN = OFP_DEFAULT_MISS_SEND_LEN;
static ofdp_config config = { 0, 0, 0, 0, 0, { 0, 0, 0, 0, 0 }, { 0, 0 } };
static uint32_t state = NOT_INITIALIZED;


static void
cleanup() {
  if ( ( state & TABLE_MANAGER_INITIALIZED ) != 0 ) {
    finalize_table_manager();
    state &= ~( ( uint32_t ) TABLE_MANAGER_INITIALIZED );
  }
  if ( ( state & PORT_MANAGER_INITIALIZED ) != 0 ) {
    finalize_port_manager();
    state &= ~( ( uint32_t ) PORT_MANAGER_INITIALIZED );
  }
  if ( ( state & ASYNC_EVENT_NOTIFIER_INITIALIZED ) != 0 ) {
    finalize_async_event_notifier();
    state &= ~( ( uint32_t ) ASYNC_EVENT_NOTIFIER_INITIALIZED );
  }
  if ( ( state & PIPELINE_INITIALIZED ) != 0 ) {
    finalize_pipeline();
    state &= ~( ( uint32_t ) PIPELINE_INITIALIZED );
  }
  if ( ( state & SAFE_TIMER_INITIALIZED ) != 0 ) {
    finalize_timer_safe();
    state &= ~( ( uint32_t ) SAFE_TIMER_INITIALIZED );
  }
  if ( ( state & SAFE_EVENT_HANDLER_INITIALIZED ) != 0 ) {
    finalize_event_handler_safe();
    state &= ~( ( uint32_t ) SAFE_EVENT_HANDLER_INITIALIZED );
  }
  if ( ( state & INITIALIZED ) != 0 ) {
    memset( &config, 0, sizeof( ofdp_config ) );
    state &= ~( ( uint32_t ) INITIALIZED );
  }
}


OFDPE
init_datapath( uint64_t datapath_id, unsigned int n_packet_buffers,
               size_t max_send_queue, size_t max_recv_queue, uint32_t max_flow_entries ) {
  if ( max_send_queue == 0 || max_recv_queue == 0 || max_flow_entries == 0 ) {
    return ERROR_INVALID_PARAMETER;
  }

  state = NOT_INITIALIZED;

  add_thread();

  init_event_handler_safe();
  state |= SAFE_EVENT_HANDLER_INITIALIZED;

  init_timer_safe();
  state |= SAFE_TIMER_INITIALIZED;

  OFDPE ret = init_table_manager( max_flow_entries );
  if ( ret != OFDPE_SUCCESS ) {
    error( "Failed to initialize table manager ( %d ).", ret );
    return ret;
  }
  state |= TABLE_MANAGER_INITIALIZED;

  ret = init_port_manager( max_send_queue, max_recv_queue ); 
  if ( ret != OFDPE_SUCCESS ) {
    error( "Failed to initialize port manager ( %d ).", ret );
    cleanup();
    return ret;
  }
  state |= PORT_MANAGER_INITIALIZED;

  ret = init_async_event_notifier( n_packet_buffers ); 
  if ( ret != OFDPE_SUCCESS ) {
    error( "Failed to initialize controller manager ( %d ).", ret );
    cleanup();
    return ret;
  }
  state |= ASYNC_EVENT_NOTIFIER_INITIALIZED;

  ret = init_pipeline(); 
  if ( ret != OFDPE_SUCCESS ) {
    error( "Failed to initialize pipeline ( %d ).", ret );
    cleanup();
    return ret;
  }
  state |= PIPELINE_INITIALIZED;

  memset( &config.features, 0, sizeof( switch_features ) );
  config.features.datapath_id = datapath_id;
  config.features.n_buffers = n_packet_buffers;
  config.features.n_tables = N_FLOW_TABLES;
  config.features.auxiliary_id = 0;
  config.features.capabilities = OFPC_FLOW_STATS | OFPC_TABLE_STATS | OFPC_PORT_STATS | OFPC_GROUP_STATS;

  memset( &config.config, 0, sizeof( switch_config ) );
  config.config.miss_send_len = MISS_SEND_LEN;
  config.config.flags = OFPC_FRAG_NORMAL;

  state |= INITIALIZED;

  return OFDPE_SUCCESS;
}


OFDPE
finalize_datapath() {
  if ( ( state & RUNNING ) == 0 ) {
    return OFDPE_FAILED;
  }

  cleanup();

  return OFDPE_SUCCESS;
}


OFDPE
start_datapath() {
  if ( ( state & INITIALIZED ) == 0 ) {
    error( "Datapath is not initialized yet." );
    return OFDPE_FAILED;
  }

  state |= RUNNING;
  bool ret = start_event_handler_safe();

  return ret ? OFDPE_SUCCESS : OFDPE_FAILED;
}


OFDPE
stop_datapath() {
  if ( !datapath_is_running() ) {
    error( "Datapath is not running." );
    return OFDPE_FAILED;
  }

  stop_event_handler_safe();

  return OFDPE_SUCCESS;
}


OFDPE
get_switch_features( switch_features *features ) {
  assert( features != NULL );

  if ( ( state & INITIALIZED ) == 0 ) {
    error( "Datapath is not initialized yet." );
    return OFDPE_FAILED;
  }

  memcpy( features, &config.features, sizeof( switch_features ) );

  return OFDPE_SUCCESS;
}


OFDPE
get_switch_config( switch_config *conf ) {
  assert( conf != NULL );

  if ( ( state & INITIALIZED ) == 0 ) {
    error( "Datapath is not initialized yet." );
    return OFDPE_FAILED;
  }

  memcpy( conf, &config.config, sizeof( switch_config ) );

  return OFDPE_SUCCESS;
}


OFDPE
set_switch_config( switch_config *conf ) {
  assert( conf != NULL );

  if ( ( state & INITIALIZED ) == 0 ) {
    error( "Datapath is not initialized yet." );
    return OFDPE_FAILED;
  }

  MISS_SEND_LEN = conf->miss_send_len;

  // TODO: implement here.

  memcpy( &config.config, conf, sizeof( switch_config ) );

  return OFDPE_SUCCESS;
}


bool
datapath_is_running() {
  return ( state & RUNNING ) != 0 ? true : false;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/
