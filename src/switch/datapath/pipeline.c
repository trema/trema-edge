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


#include "action_executor.h"
#include "meter_executor.h"
#include "async_event_notifier.h"
#include "flow_table.h"
#include "pipeline.h"
#include "port_manager.h"
#include "table_manager.h"


OFDPE
init_pipeline() {
  return init_action_executor();
}


OFDPE
finalize_pipeline() {
  return finalize_action_executor();
}


static OFDPE
apply_instructions( const uint8_t table_id, const instruction_set *instructions, buffer *frame, action_set *set, uint8_t *next_table_id ) {
  assert( valid_table_id( table_id ) );
  assert( frame != NULL );
  assert( set != NULL );
  assert( next_table_id != NULL );

  if ( instructions == NULL ) {
    return OFDPE_SUCCESS;
  }

  OFDPE ret = OFDPE_SUCCESS;
  if ( instructions->meter != NULL ) {
    ret = execute_meter( instructions->meter->meter_id, frame );
    if ( ret != OFDPE_SUCCESS && ret != ERROR_DROP_PACKET ) {
      error( "Failed to apply meter ( ret = %d ).", ret );
    }
  }
  if ( ret == OFDPE_SUCCESS && instructions->apply_actions != NULL ) {
    ret = execute_action_list( instructions->apply_actions->actions, frame );
    if ( ret != OFDPE_SUCCESS ) {
      error( "Failed to apply actions ( ret = %d ).", ret );
    }
  }
  if ( ret == OFDPE_SUCCESS && instructions->clear_actions != NULL ) {
    clear_action_set( set );
  }
  if ( ret == OFDPE_SUCCESS && instructions->write_actions != NULL ) {
    ret = write_action_set( instructions->write_actions->actions, set );
    if ( ret != OFDPE_SUCCESS ) {
      error( "Failed to write actions ( ret = %d ).", ret );
    }
  }
  if ( ret == OFDPE_SUCCESS && instructions->write_metadata != NULL ) {
    uint64_t metadata = ( instructions->write_metadata->metadata & instructions->write_metadata->metadata_mask );
    assert(  frame->user_data != NULL );
    ( ( packet_info * ) frame->user_data )->metadata = metadata;
  }
  if ( ret == OFDPE_SUCCESS && instructions->goto_table != NULL ) {
    if ( table_id == FLOW_TABLE_ID_MAX ) {
      error( "Goto table is not allowed in table %#x.", table_id );
      ret = OFDPE_FAILED;
    }
    else if ( instructions->goto_table->table_id <= table_id ) {
      error( "Goto table from %#x to %#x is not allowed.", table_id, instructions->goto_table->table_id );
      ret = OFDPE_FAILED;
    }
    else {
      *next_table_id = instructions->goto_table->table_id;
    }
  }

  return ret;
}


static void
process_received_frame( const switch_port *port, buffer *frame ) {
  assert( port != NULL );
  assert( frame != NULL );
  assert( frame->user_data != NULL );

  action_set set = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
  clear_action_set( &set );

  bool completed = false;
  OFDPE ret = OFDPE_SUCCESS;
  uint8_t table_id = 0;

  debug( "Processing received frame ( port_no = %u, frame = %p, user_data = %p ).", port->port_no, frame, frame->user_data );

  while ( 1 ) {
    packet_info *info = ( packet_info * ) frame->user_data;
    static match match;
    build_match_from_packet_info( &match, info ); 

    flow_entry *entry = lookup_flow_entry( table_id, &match );
    if ( entry == NULL ) {
      debug( "No matching flow entry found." );
      break;
    }

    entry->packet_count++;
    entry->byte_count += frame->length;
    time_now( &( entry->last_seen ) );

    uint8_t next_table_id = FLOW_TABLE_ALL;
    ret = apply_instructions( table_id, entry->instructions, frame, &set, &next_table_id );
    if ( ret != OFDPE_SUCCESS ) {
      if ( ret != ERROR_DROP_PACKET ) {
        error( "Failed to apply instructions ( ret = %d ).", ret );
      }
      break;
    }

    if ( next_table_id == FLOW_TABLE_ALL ) {
      completed = true;
      break;
    }

    table_id = next_table_id;
  }

  if ( completed ) {
    ret = execute_action_set( &set, frame );
    if ( ret != OFDPE_SUCCESS ) {
      error( "Failed to execute action set ( set = %p, frame = %p ).", &set, frame );
    }
  }
  clear_action_set( &set );
}


OFDPE
handle_received_frame( const switch_port *port, buffer *frame ) {
  assert( port != NULL );
  assert( frame != NULL );

  debug( "Handling received frame ( port_no = %u, frame = %p, user_data = %p ).", port->port_no, frame, frame->user_data );

  if ( frame->user_data == NULL ) {
    bool ret = parse_packet( frame );
    if ( !ret ) {
      warn( "Failed to parse a received frame ( port_no = %u, frame = %p ).", port->port_no, frame );
      return OFDPE_FAILED;
    }
  }

  assert( frame->user_data != NULL );
  ( ( packet_info * ) frame->user_data )->eth_in_port = port->port_no;
  ( ( packet_info * ) frame->user_data )->eth_in_phy_port = port->port_no;

  if ( !trylock_pipeline() ) {
    return ERROR_LOCK;
  }

  process_received_frame( port, frame );

  if ( !unlock_pipeline() ) {
    return ERROR_UNLOCK;
  }

  return OFDPE_SUCCESS;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/
