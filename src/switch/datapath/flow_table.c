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
#include "async_event_notifier.h"
#include "flow_table.h"
#include "group_entry.h"
#include "table_manager.h"


typedef void ( *flow_entry_handler )( flow_entry *entry, void *user_data );


static flow_table flow_tables[ N_FLOW_TABLES ];
static const time_t AGING_INTERVAL = 1;


void
init_flow_tables( const uint32_t max_flow_entries ) {
  memset( &flow_tables, 0, sizeof( flow_table ) * N_FLOW_TABLES );
  for ( uint8_t i = 0; i <= FLOW_TABLE_ID_MAX; i++ ) {
    init_flow_table( i, max_flow_entries );
  }
}


void
finalize_flow_tables() {
  for ( uint8_t i = 0; i <= FLOW_TABLE_ID_MAX; i++ ) {
    finalize_flow_table( i );
  }
  memset( &flow_tables, 0, sizeof( flow_table ) * N_FLOW_TABLES );
}


bool
valid_table_id( const uint8_t id ) {
  if ( id > FLOW_TABLE_ID_MAX ) {
    return false;
  }

  return true;
}


static flow_table *
get_flow_table( const uint8_t table_id ) {
  if ( !valid_table_id( table_id ) ) {
    error( "Invalid flow table id ( %#x ).", table_id );
    return NULL;
  }

  if ( !flow_tables[ table_id ].initialized ) {
    warn( "Flow table ( table_id = %#x ) is not initialized yet.", table_id );
    return NULL;
  }

  return &( flow_tables[ table_id ] );
}


static void
set_default_flow_table_features( const uint8_t table_id, flow_table_features *features ) {
  assert( valid_table_id( table_id ) );
  assert( features != NULL );

  features->table_id = table_id;
  memset( features->name, '\0', sizeof( features->name ) );
  snprintf( features->name, sizeof( features->name ), "table%d", table_id );
  features->metadata_match = UINT64_MAX;
  features->metadata_write = UINT64_MAX;
  features->config = 0;
  features->max_entries = UINT32_MAX;
  features->instructions = SUPPORTED_INSTRUCTIONS;
  features->instructions_miss = SUPPORTED_INSTRUCTIONS;
  for ( uint8_t id = 0; id <= FLOW_TABLE_ID_MAX; id++ ) {
    if ( id > table_id ) {
      features->next_table_ids[ id ] = true;
      features->next_table_ids_miss[ id ] = true;
    }
    else {
      features->next_table_ids[ id ] = false;
      features->next_table_ids_miss[ id ] = false;
    }
  }
  features->write_actions = SUPPORTED_ACTIONS;
  features->write_actions_miss = SUPPORTED_ACTIONS;
  features->apply_actions = SUPPORTED_ACTIONS;
  features->apply_actions_miss = SUPPORTED_ACTIONS;
  features->matches = SUPPORTED_MATCH;
  features->wildcards = SUPPORTED_MATCH;
  features->write_setfield = SUPPORTED_SET_FIELDS;
  features->write_setfield_miss = SUPPORTED_SET_FIELDS;
  features->apply_setfield = SUPPORTED_SET_FIELDS;
  features->apply_setfield_miss = SUPPORTED_SET_FIELDS;
}


static uint32_t
increment_active_count( const uint8_t table_id ) {
  assert( valid_table_id( table_id ) );

  flow_table *table = get_flow_table( table_id );
  if ( table == NULL ) {
    return 0;
  }

  return ++table->counters.active_count;
}


static uint32_t
decrement_active_count( const uint8_t table_id ) {
  assert( valid_table_id( table_id ) );

  flow_table *table = get_flow_table( table_id );
  if ( table == NULL ) {
    return 0;
  }

  return --table->counters.active_count;
}


static uint32_t
get_active_count( const uint8_t table_id ) {
  assert( valid_table_id( table_id ) );

  flow_table *table = get_flow_table( table_id );
  if ( table == NULL ) {
    return 0;
  }

  return table->counters.active_count;
}


static uint64_t
increment_lookup_count( const uint8_t table_id ) {
  assert( valid_table_id( table_id ) );

  flow_table *table = get_flow_table( table_id );
  if ( table == NULL ) {
    return 0;
  }

  return ++table->counters.lookup_count;
}


static uint64_t
get_lookup_count( const uint8_t table_id ) {
  assert( valid_table_id( table_id ) );

  flow_table *table = get_flow_table( table_id );
  if ( table == NULL ) {
    return 0;
  }

  return table->counters.lookup_count;
}


static uint64_t
increment_matched_count( const uint8_t table_id ) {
  assert( valid_table_id( table_id ) );

  flow_table *table = get_flow_table( table_id );
  if ( table == NULL ) {
    return 0;
  }

  return ++table->counters.matched_count;
}


static uint64_t
get_matched_count( const uint8_t table_id ) {
  assert( valid_table_id( table_id ) );

  flow_table *table = get_flow_table( table_id );
  if ( table == NULL ) {
    return 0;
  }

  return table->counters.matched_count;
}


static void
flow_deleted( flow_entry *entry, uint8_t reason ) {
  assert( entry != NULL );

  if ( ( entry->flags & OFPFF_SEND_FLOW_REM ) == 0 ) {
    return;
  }

  notify_flow_removed( reason, entry );
}


static void
delete_flow_entry_from_table( flow_table *table, flow_entry *entry, uint8_t reason, bool notify ) {
  assert( table != NULL );
  assert( entry != NULL );

  bool ret = delete_element( &table->entries, entry );
  if ( ret ) {
    decrement_active_count( table->features.table_id );
    if ( notify ) {
      flow_deleted( entry, reason );
    }
    decrement_reference_counters_in_groups( entry->instructions );
    free_flow_entry( entry );
  }
}


static void
foreach_flow_entry( const uint8_t table_id, flow_entry_handler callback, void *user_data ) {
  assert( valid_table_id( table_id ) );
  assert( callback != NULL );

  flow_table *table = get_flow_table( table_id );
  assert( table != NULL );

  list_element *e = table->entries;
  while ( e != NULL ) {
    list_element *next = e->next; // Current element may be deleted inside the callback function.
    flow_entry *entry = e->data;
    assert( entry != NULL );
    callback( entry, user_data );
    e = next;
  }
}


static void
age_flow_entries_walker( flow_entry *entry, void *user_data ) {
  assert( entry != NULL );
  assert( user_data != NULL );

  struct timespec *now = user_data;
  struct timespec diff = { 0, 0 };

  timespec_diff( entry->created_at, *now, &diff );
  entry->duration_sec = ( uint32_t ) diff.tv_sec;
  entry->duration_nsec = ( uint32_t ) diff.tv_nsec;

  if ( entry->hard_timeout > 0 ) {
    if ( diff.tv_sec >= entry->hard_timeout ) {
      flow_table *table = get_flow_table( entry->table_id );
      delete_flow_entry_from_table( table, entry, OFPRR_HARD_TIMEOUT, true );
      return;
    }
  }

  if ( entry->idle_timeout > 0 ) {
    timespec_diff( entry->last_seen, *now, &diff );
    if ( diff.tv_sec >= entry->idle_timeout ) {
      flow_table *table = get_flow_table( entry->table_id );
      delete_flow_entry_from_table( table, entry, OFPRR_IDLE_TIMEOUT, true );
    }
  }

}


static void
age_flow_entries( void *user_data ) {
  const uint8_t table_id = *( uint8_t * ) user_data;

  assert( valid_table_id( table_id ) );

  if ( !lock_pipeline() ) {
    return;
  }

  struct timespec now = { 0, 0 };
  time_now( &now );

  foreach_flow_entry( table_id, age_flow_entries_walker, &now );

  if ( !unlock_pipeline() ) {
    return;
  }
}


OFDPE
init_flow_table( const uint8_t table_id, const uint32_t max_flow_entries ) {
  if ( !valid_table_id( table_id ) ) {
    error( "Invalid flow table id ( %#x ).", table_id );
    return OFDPE_FAILED;
  }

  flow_table *table = &flow_tables[ table_id ];
  if ( table->initialized ) {
    error( "Flow table ( table_id = %#x ) is already initialized.", table_id );
    return OFDPE_FAILED;
  }

  memset( table, 0, sizeof( flow_table ) );

  table->counters.active_count = 0;
  table->counters.lookup_count = 0;
  table->counters.matched_count = 0;
  create_list( &table->entries );
  table->initialized = true;

  set_default_flow_table_features( table_id, &table->features );

  table->features.max_entries = max_flow_entries;

  add_periodic_event_callback_safe( AGING_INTERVAL, age_flow_entries, ( void * ) &table->features.table_id );

  return OFDPE_SUCCESS;
}


OFDPE
finalize_flow_table( const uint8_t table_id ) {
  if ( !valid_table_id( table_id ) ) {
    error( "Invalid flow table id ( %#x ).", table_id );
    return OFDPE_FAILED;
  }

  flow_table *table = get_flow_table( table_id );
  if ( table == NULL ) {
    return OFDPE_FAILED;
  }

  delete_timer_event_safe( age_flow_entries, &table->features.table_id );

  for ( list_element *e = table->entries; e != NULL; e = e->next ) {
    flow_entry *entry = e->data;
    if ( entry != NULL ) {
      free_flow_entry( entry );
    }
  }
  delete_list( table->entries );

  memset( table, 0, sizeof( flow_table ) );
  table->initialized = false;
  
  return OFDPE_SUCCESS;
}


static list_element *
lookup_flow_entries_with_table_id( const uint8_t table_id, const match *match_key, const uint16_t priority,
                                   const bool strict, const bool update_counters ) {
  assert( valid_table_id( table_id ) );

  if ( get_logging_level() >= LOG_DEBUG ) {
    debug( "Looking up flow entries ( table_id = %#x, match = %p, priority = %u, strict = %s, update_counters = %s ).",
           table_id, match_key, priority, strict ? "true" : "false", update_counters ? "true" : "false" );
    if ( match_key != NULL ) {
      dump_match( match_key, debug );
    }
  }

  flow_table *table = get_flow_table( table_id );
  if ( table == NULL ) {
    return NULL;
  }

  if ( update_counters ) {
    increment_lookup_count( table_id );
  }

  list_element *head = NULL;
  create_list( &head );

  for ( list_element *e = table->entries; e != NULL; e = e->next ) {
    flow_entry *entry = e->data;
    assert( entry != NULL );
    
    const match *narrow, *wide;
    if ( update_counters ) {
      narrow = match_key;
      wide = entry->match;
    } else {
      narrow = entry->match;
      wide = match_key;
    }
    
    if ( strict ) {
      if ( entry->priority < priority ) {
        break;
      }
      if ( priority == entry->priority && compare_match_strict( narrow, wide ) ) {
        if ( update_counters ) {
          increment_matched_count( table_id );
        }
        append_to_tail( &head, entry );
        break;
      }
    }
    else {
      if ( compare_match( narrow, wide ) ) {
        if ( update_counters ) {
          increment_matched_count( table_id );
        }
        append_to_tail( &head, entry );
      }
    }
  }

  return head;
}


static list_element *
lookup_flow_entries_from_all_tables( const match *match, const uint16_t priority, const bool strict, const bool update_counters ) {
  list_element *head = NULL;
  list_element *last = NULL;

  for ( uint8_t i = 0; i <= FLOW_TABLE_ID_MAX; i++ ) {
    list_element *append = lookup_flow_entries_with_table_id( i, match, priority, strict, update_counters );
    if ( append == NULL ) {
      continue;
    }

    if ( head == NULL ) {
      head = append;
    }

    if ( strict ) {
      break;
    }

    if ( last != NULL ) {
      last->next = append;
    }
    while ( append->next != NULL ) {
      append = append->next;
    }
    last = append;
  }

  return head;
}


list_element *
lookup_flow_entries( const uint8_t table_id, const match *match ) {
  assert( valid_table_id( table_id ) || table_id == FLOW_TABLE_ALL );

  if ( !lock_pipeline() ) {
    return NULL;
  }

  list_element *list = NULL;
  if ( table_id != FLOW_TABLE_ALL ) {
    list = lookup_flow_entries_with_table_id( table_id, match, 0, false, true );
  }
  else {
    list = lookup_flow_entries_from_all_tables( match, 0, false, true );
  }

  if ( !unlock_pipeline() ) {
    delete_list( list );
    return NULL;
  }

  return list;
}


flow_entry *
lookup_flow_entry( const uint8_t table_id, const match *match ) {
  assert( valid_table_id( table_id ) || table_id == FLOW_TABLE_ALL );

  if ( !lock_pipeline() ) {
    return NULL;
  }

  // FIXME: allocating/freeing linked list elements may cost.

  list_element *list = NULL;
  if ( table_id != FLOW_TABLE_ALL ) {
    list = lookup_flow_entries_with_table_id( table_id, match, 0, false, true );
  }
  else {
    list = lookup_flow_entries_from_all_tables( match, 0, false, true );
  }

  if ( !unlock_pipeline() ) {
    delete_list( list );
    return NULL;
  }

  flow_entry *entry = NULL;
  if ( list != NULL ) {
    entry = list->data;
    delete_list( list );
  }

  return entry;
}


flow_entry *
lookup_flow_entry_strict( const uint8_t table_id, const match *match, const uint16_t priority ) {
  assert( valid_table_id( table_id ) || table_id == FLOW_TABLE_ALL );

  if ( !lock_pipeline() ) {
    return NULL;
  }

  // FIXME: allocating/freeing linked list elements may cost.

  list_element *list = NULL;
  if ( table_id != FLOW_TABLE_ALL ) {
    list = lookup_flow_entries_with_table_id( table_id, match, priority, true, true );
  }
  else {
    list = lookup_flow_entries_from_all_tables( match, priority, true, true );
  }

  flow_entry *entry = NULL;
  if ( list != NULL ) {
    entry = list->data;
    delete_list( list );
  }

  if ( !unlock_pipeline() ) {
    return NULL;
  }

  return entry;
}


static OFDPE
insert_flow_entry( flow_table *table, flow_entry *entry, const uint16_t flags ) {
  assert( table != NULL );
  assert( entry != NULL );

  list_element *element = table->entries;
  while( element != NULL ) {
    list_element *next = element->next;
    flow_entry *e = element->data;
    assert( e != NULL );
    if ( e->priority < entry->priority ) {
      break;
    }
    if ( e->priority == entry->priority ) {
      if ( e->table_miss && !entry->table_miss ) {
        break;
      }
      if ( ( flags & OFPFF_CHECK_OVERLAP ) != 0 && compare_match( e->match, entry->match ) ) {
        return ERROR_OFDPE_FLOW_MOD_FAILED_OVERLAP;
      }
      if ( compare_match_strict( e->match, entry->match ) ) {
        if ( ( flags & OFPFF_RESET_COUNTS ) != 0 ) {
          entry->byte_count = e->byte_count;
          entry->packet_count = e->packet_count;
        }
        flow_table *table = get_flow_table( e->table_id );
        assert( table != NULL );
        delete_flow_entry_from_table( table, e, 0, false );
      }
    }
    element = next;
  }

  if ( element == NULL ) {
    // tail
    append_to_tail( &table->entries, entry );
  }
  else if ( element == table->entries ) {
    // head
    insert_in_front( &table->entries, entry );
  }
  else {
    // insert before
    insert_before( &table->entries, element->data, entry );
  }

  increment_active_count( table->features.table_id );

  return OFDPE_SUCCESS;
}


OFDPE
add_flow_entry( const uint8_t table_id, flow_entry *entry, const uint16_t flags ) {
  if ( !valid_table_id( table_id ) ) {
    return ERROR_OFDPE_FLOW_MOD_FAILED_BAD_TABLE_ID;
  }
  if ( entry == NULL ) {
    return ERROR_INVALID_PARAMETER;
  }

  if ( !lock_pipeline() ) {
    return ERROR_LOCK;
  }

  flow_table *table = get_flow_table( table_id );
  if ( table == NULL ) {
    if ( !unlock_pipeline() ) {
      return ERROR_UNLOCK;
    }
    return ERROR_OFDPE_FLOW_MOD_FAILED_BAD_TABLE_ID;
  }

  if ( table->features.max_entries <= get_active_count( table_id ) ) {
    if ( !unlock_pipeline() ) {
      return ERROR_UNLOCK;
    }
    return ERROR_OFDPE_FLOW_MOD_FAILED_TABLE_FULL;
  }

  OFDPE ret = validate_instruction_set( entry->instructions, table->features.metadata_write );
  if ( ret == OFDPE_SUCCESS ) {
    entry->table_id = table_id;
    ret = insert_flow_entry( table, entry, flags );
    if ( ret == OFDPE_SUCCESS ) {
      increment_reference_counters_in_groups( entry->instructions );
    }
  }

  if ( !unlock_pipeline() ) {
    return ERROR_UNLOCK;
  }

  return ret;
}


static void
update_instructions( flow_entry *entry, instruction_set *instructions ) {
  assert( entry != NULL );

  decrement_reference_counters_in_groups( entry->instructions );
  if ( entry->instructions != instructions ) {
    delete_instruction_set( entry->instructions );
  }
  entry->instructions = duplicate_instruction_set( instructions );
  increment_reference_counters_in_groups( entry->instructions );
}


static void
update_flow_entries_in_list( list_element *entries, const uint64_t cookie, const uint64_t cookie_mask,
                             const uint16_t flags, instruction_set *instructions ) {
  for ( list_element *e = entries; e != NULL; e = e->next ) {
    flow_entry *entry = e->data;
    assert( entry != NULL );

    bool update = false;
    if ( cookie_mask != 0 ) {
      if ( ( entry->cookie & cookie_mask ) == ( cookie & cookie_mask ) ) {
        update = true;
      }
    }
    else {
      update = true;
    }

    if ( !update ) {
      continue;
    }

    update_instructions( entry, instructions );

    if ( flags == OFPFF_RESET_COUNTS ) {
      entry->packet_count = 0;
      entry->byte_count = 0;
    }
  }
}



OFDPE
update_flow_entries( const uint8_t table_id, const match *match, const uint64_t cookie, const uint64_t cookie_mask,
                     const uint16_t flags, instruction_set *instructions ) {
  /*
   * FLOW_TABLE_ALL (=OFPTT_ALL) is not allowed in the protocol specification.
   * But we allow it for internal use.
   */
  if ( !valid_table_id( table_id ) && table_id != FLOW_TABLE_ALL ) {
    return ERROR_OFDPE_FLOW_MOD_FAILED_BAD_TABLE_ID;
  }

  if ( match == NULL ) {
    error( "Invalid match ( %p ).", match );
    return ERROR_INVALID_PARAMETER;
  }
  if ( instructions == NULL ) {
    error( "Invalid instruction list ( %p ).", instructions );
    return ERROR_INVALID_PARAMETER;
  }

  if ( !lock_pipeline() ) {
    return ERROR_LOCK;
  }

  flow_table *table = get_flow_table( table_id );
  assert( table != NULL );

  OFDPE ret = validate_instruction_set( instructions, table->features.metadata_write );
  if ( ret != OFDPE_SUCCESS ) {
    error( "Invalid instruction set ( ret = %#x, instructions = %p ).", ret, instructions );
    if ( !unlock_pipeline() ) {
      return ERROR_UNLOCK;
    }
    return ret;
  }

  list_element *list = NULL;
  if ( table_id != FLOW_TABLE_ALL ) {
    list = lookup_flow_entries_with_table_id( table_id, match, 0, false, false );
  }
  else {
    list = lookup_flow_entries_from_all_tables( match, 0, false, false );
  }

  update_flow_entries_in_list( list, cookie, cookie_mask, flags, instructions );

  if ( list != NULL ) {
    delete_list( list );
  }

  if ( !unlock_pipeline() ) {
    return ERROR_UNLOCK;
  }

  return OFDPE_SUCCESS;
}


OFDPE
update_flow_entry_strict( const uint8_t table_id, const match *match, const uint64_t cookie, const uint64_t cookie_mask,
                          const uint16_t priority, const uint16_t flags, instruction_set *instructions ) {
  /*
   * FLOW_TABLE_ALL (=OFPTT_ALL) is not allowed in the protocol specification.
   * But we allow it for internal use.
   */
  if ( !valid_table_id( table_id ) && table_id != FLOW_TABLE_ALL ) {
    return ERROR_OFDPE_FLOW_MOD_FAILED_BAD_TABLE_ID;
  }

  if ( match == NULL ) {
    error( "Invalid match ( %p ).", match );
    return ERROR_INVALID_PARAMETER;
  }
  if ( instructions == NULL ) {
    error( "Invalid instruction set ( %p ).", instructions );
    return ERROR_INVALID_PARAMETER;
  }

  if ( !lock_pipeline() ) {
    return ERROR_LOCK;
  }

  flow_table *table = get_flow_table( table_id );
  assert( table != NULL );

  OFDPE ret = validate_instruction_set( instructions, table->features.metadata_write );
  if ( ret != OFDPE_SUCCESS ) {
    error( "Invalid instruction set ( ret = %#x, instructions = %p ).", ret, instructions );
    if ( !unlock_pipeline() ) {
      return ERROR_UNLOCK;
    }
    return ret;
  }

  list_element *list = NULL;
  if ( table_id != FLOW_TABLE_ALL ) {
    list = lookup_flow_entries_with_table_id( table_id, match, priority, true, false );
  }
  else {
    list = lookup_flow_entries_from_all_tables( match, priority, true, false );
  }

  update_flow_entries_in_list( list, cookie, cookie_mask, flags, instructions );

  if ( list != NULL ) {
    delete_list( list );
  }

  if ( !unlock_pipeline() ) {
    return ERROR_UNLOCK;
  }

  return OFDPE_SUCCESS;
}


OFDPE
update_or_add_flow_entry( const uint8_t table_id, const match *key,
                          const uint64_t cookie, const uint64_t cookie_mask,
                          const uint16_t priority, const uint16_t idle_timeout, const uint16_t hard_timeout,
                          const uint16_t flags, const bool strict, instruction_set *instructions ) {
  if ( !valid_table_id( table_id ) ) {
    return ERROR_OFDPE_FLOW_MOD_FAILED_BAD_TABLE_ID;
  }

  if ( key == NULL ) {
    error( "Invalid match ( %p ).", key );
    return ERROR_INVALID_PARAMETER;
  }
  if ( instructions == NULL ) {
    error( "Invalid instruction set ( %p ).", instructions );
    return ERROR_INVALID_PARAMETER;
  }

  if ( !lock_pipeline() ) {
    return ERROR_LOCK;
  }

  flow_table *table = get_flow_table( table_id );
  assert( table != NULL );

  OFDPE ret = validate_instruction_set( instructions, table->features.metadata_write );
  if ( ret != OFDPE_SUCCESS ) {
    error( "Invalid instruction set ( ret = %#x, instructions = %p ).", ret, instructions );
    if ( !unlock_pipeline() ) {
      return ERROR_UNLOCK;
    }
    return ret;
  }

  list_element *list = lookup_flow_entries_with_table_id( table_id, key, priority, strict, false );
  if ( list != NULL ) {
    update_flow_entries_in_list( list, cookie, cookie_mask, flags, instructions );
    delete_list( list );
  }
  else {
    match *duplicated_match = duplicate_match( key );
    instruction_set *duplicated_instructions = duplicate_instructions( instructions );
    flow_entry *entry = alloc_flow_entry( duplicated_match, duplicated_instructions,
                                          priority, idle_timeout, hard_timeout, flags, cookie );
    if ( entry != NULL ) {
      ret = add_flow_entry( table_id, entry, flags );
      if ( ret != OFDPE_SUCCESS ) {
        error( "Failed to add flow entry ( table_id = %#x, entry = %p, flags = %#x ).", table_id, entry, flags );
      }
    }
    else { 
      delete_match( duplicated_match );
      delete_instructions( duplicated_instructions );
      ret = OFDPE_FAILED;
    }
  }

  if ( !unlock_pipeline() ) {
    return ERROR_UNLOCK;
  }

  return ret;
}


static bool
instruction_has_output_port( const instruction *instruction, const uint32_t out_port ) {
  assert( instruction != NULL );

  if ( instruction->actions == NULL ) {
    return false;
  }

  bool found = false;
  for ( dlist_element *e = get_first_element( instruction->actions ); e != NULL; e = e->next ) {
    action *action = e->data;
    if ( action == NULL ) {
      continue;
    }
    if ( action->type == OFPAT_OUTPUT && out_port == action->port ) {
      found = true;
      break;
    }
  }

  return found;
}


static bool
instructions_have_output_port( instruction_set *instructions, const uint32_t out_port ) {
  assert( out_port <= OFPP_MAX );

  bool found = false;
  if ( instructions->write_actions != NULL ) {
    found = instruction_has_output_port( instructions->write_actions, out_port );
  }
  if ( instructions->apply_actions != NULL ) {
    found = instruction_has_output_port( instructions->apply_actions, out_port );
  }

  return found;
}


static bool
instruction_has_output_group( const instruction *instruction, const uint32_t out_group ) {
  assert( instruction != NULL );

  if ( instruction->actions == NULL ) {
    return false;
  }

  bool found = false;
  for ( dlist_element *e = get_first_element( instruction->actions ); e != NULL; e = e->next ) {
    action *action = e->data;
    if ( action == NULL ) {
      continue;
    }
    if ( action->type == OFPAT_GROUP && out_group == action->group_id ) {
      found = true;
      break;
    }
  }

  return found;
}


static bool
instructions_have_output_group( instruction_set *instructions, const uint32_t out_group ) {
  assert( out_group <= OFPG_MAX );

  bool found = false;
  if ( instructions->write_actions != NULL ) {
    found = instruction_has_output_group( instructions->write_actions, out_group );
  }
  if ( instructions->apply_actions != NULL ) {
    found = instruction_has_output_group( instructions->apply_actions, out_group );
  }

  return found;
}


static void
delete_flow_entries_in_list( list_element *entries, const uint64_t cookie, const uint64_t cookie_mask,
                             const uint32_t out_port, const uint32_t out_group, const uint8_t reason ) {
  for ( list_element *e = entries; e != NULL; e = e->next ) {
    flow_entry *entry = e->data;
    assert( entry != NULL );

    bool to_be_deleted = true;
    if ( cookie_mask != 0 ) {
      if ( ( entry->cookie & cookie_mask ) != ( cookie & cookie_mask ) ) {
        to_be_deleted = false;
      }
    }

    if ( to_be_deleted && out_port != OFPP_ANY ) {
      if ( !instructions_have_output_port( entry->instructions, out_port ) ) {
        to_be_deleted = false;
      }
    }
    if ( to_be_deleted && out_group != OFPG_ANY ) {
      if ( !instructions_have_output_group( entry->instructions, out_group ) ) {
        to_be_deleted = false;
      }
    }

    if ( !to_be_deleted ) {
      continue;
    }

    flow_table *table = get_flow_table( entry->table_id );
    assert( table != NULL );
    delete_flow_entry_from_table( table, entry, reason, true );
  }
}


OFDPE
delete_flow_entries( const uint8_t table_id, const match *match, const uint64_t cookie, const uint64_t cookie_mask,
                     uint32_t out_port, uint32_t out_group ) {
  if ( !valid_table_id( table_id ) && table_id != FLOW_TABLE_ALL ) {
    return ERROR_OFDPE_FLOW_MOD_FAILED_BAD_TABLE_ID;
  }

  if ( !lock_pipeline() ) {
    return ERROR_LOCK;
  }

  list_element *delete_us = NULL;
  if ( table_id != FLOW_TABLE_ALL ) {
    delete_us = lookup_flow_entries_with_table_id( table_id, match, 0, false, false );
  }
  else {
    delete_us = lookup_flow_entries_from_all_tables( match, 0, false, false );
  }

  delete_flow_entries_in_list( delete_us, cookie, cookie_mask, out_port, out_group, OFPRR_DELETE );

  if ( delete_us != NULL ) {
    delete_list( delete_us );
  }

  if ( !unlock_pipeline() ) {
    return ERROR_UNLOCK;
  }

  return OFDPE_SUCCESS;
}


OFDPE
delete_flow_entry_strict( const uint8_t table_id, const match *match, const uint64_t cookie, const uint64_t cookie_mask,
                          const uint16_t priority, uint32_t out_port, uint32_t out_group ) {
  if ( !valid_table_id( table_id ) && table_id != FLOW_TABLE_ALL ) {
    return ERROR_OFDPE_FLOW_MOD_FAILED_BAD_TABLE_ID;
  }

  if ( !lock_pipeline() ) {
    return ERROR_LOCK;
  }

  list_element *delete_us = NULL;
  if ( table_id != FLOW_TABLE_ALL ) {
    delete_us = lookup_flow_entries_with_table_id( table_id, match, priority, true, false );
  }
  else {
    delete_us = lookup_flow_entries_from_all_tables( match, priority, true, false );
  }

  delete_flow_entries_in_list( delete_us, cookie, cookie_mask, out_port, out_group, OFPRR_DELETE );

  if ( delete_us != NULL ) {
    delete_list( delete_us );
  }

  if ( !unlock_pipeline() ) {
    return ERROR_UNLOCK;
  }

  return OFDPE_SUCCESS;
}


OFDPE
delete_flow_entries_by_group_id( const uint32_t group_id ) {
  assert( valid_group_id( group_id ) );

  if ( !lock_pipeline() ) {
    return ERROR_LOCK;
  }

  list_element *delete_us = NULL;
  create_list( &delete_us );

  for ( uint8_t table_id = 0; table_id <= FLOW_TABLE_ID_MAX; table_id++ ) {
    flow_table *table = get_flow_table( table_id );
    assert( table != NULL );
    for ( list_element *e = table->entries; e != NULL; e = e->next ) {
      assert( e->data != NULL );
      flow_entry *entry = e->data;
      if ( instructions_have_output_group( entry->instructions, group_id ) ) {
        append_to_tail( &delete_us, e->data );
      }
    }
  }

  delete_flow_entries_in_list( delete_us, 0, 0, OFPP_ANY, OFPG_ANY, OFPRR_GROUP_DELETE );

  if ( delete_us != NULL ) {
    delete_list( delete_us );
  }

  if ( !unlock_pipeline() ) {
    return ERROR_UNLOCK;
  }

  return OFDPE_SUCCESS;
}


OFDPE
delete_flow_entries_by_meter_id( const uint32_t meter_id ) {

  if ( !lock_pipeline() ) {
    return ERROR_LOCK;
  }

  list_element *delete_us = NULL;
  create_list( &delete_us );

  for ( uint8_t table_id = 0; table_id <= FLOW_TABLE_ID_MAX; table_id++ ) {
    flow_table *table = get_flow_table( table_id );
    assert( table != NULL );
    for ( list_element *e = table->entries; e != NULL; e = e->next ) {
      assert( e->data != NULL );
      flow_entry *entry = e->data;
      if ( entry->instructions->meter != NULL ) {
        if ( meter_id == OFPM_ALL || meter_id == entry->instructions->meter->meter_id ) {
          append_to_tail( &delete_us, e->data );
        }
      }
    }
  }

  delete_flow_entries_in_list( delete_us, 0, 0, OFPP_ANY, OFPG_ANY, OFPRR_GROUP_DELETE );

  if ( delete_us != NULL ) {
    delete_list( delete_us );
  }

  if ( !unlock_pipeline() ) {
    return ERROR_UNLOCK;
  }

  return OFDPE_SUCCESS;
}


OFDPE
get_table_stats( table_stats **stats, uint8_t *n_tables ) {
  assert( stats != NULL );
  assert( n_tables != NULL );

  if ( !lock_pipeline() ) {
    return ERROR_LOCK;
  }

  *stats = xmalloc( sizeof( table_stats ) * N_FLOW_TABLES );
  memset( *stats, 0, sizeof( table_stats ) * N_FLOW_TABLES );
  *n_tables = 0;

  table_stats *stat = *stats;
  for ( uint8_t i = 0; i <= FLOW_TABLE_ID_MAX; i++ ) {
    stat->table_id = i;
    stat->active_count = get_active_count( i );
    stat->lookup_count = get_lookup_count( i );
    stat->matched_count = get_matched_count( i );
    stat++;
    ( *n_tables )++;
  }

  if ( !unlock_pipeline() ) {
    return ERROR_UNLOCK;
  }

  return OFDPE_SUCCESS;
}


OFDPE
get_flow_stats( const uint8_t table_id, const match *match, const uint64_t cookie, const uint64_t cookie_mask,
                const uint32_t out_port, const uint32_t out_group, flow_stats **stats, uint32_t *n_entries ) {
  assert( valid_table_id( table_id ) || table_id == FLOW_TABLE_ALL );
  assert( stats != NULL );
  assert( n_entries != NULL );

  if ( !lock_pipeline() ) {
    return ERROR_LOCK;
  }

  list_element *list = NULL;
  if ( table_id != FLOW_TABLE_ALL ) {
    list = lookup_flow_entries_with_table_id( table_id, match, 0, false, false );
  }
  else {
    list = lookup_flow_entries_from_all_tables( match, 0, false, false );
  }

  *n_entries = 0;
  list_element *entries = NULL;
  create_list( &entries );

  for ( list_element *e = list; e != NULL; e = e->next ) {
    flow_entry *entry = e->data;
    assert( entry != NULL );

    bool matched = true;

    if ( out_port != OFPP_ANY ) {
      if ( !instructions_have_output_port( entry->instructions, out_port ) ) {
        matched = false;
      }
    }
    if ( out_group != OFPG_ANY ) {
      if ( !instructions_have_output_group( entry->instructions, out_group ) ) {
        matched = false;
      }
    }

    if ( matched && cookie_mask != 0 ) {
      if ( ( entry->cookie & cookie_mask ) != ( cookie & cookie_mask ) ) {
        matched = false;
      }
    }

    if ( matched ) {
      ( *n_entries )++;
      append_to_tail( &entries, entry );
    }
  }

  if ( list != NULL ) {
    delete_list( list );
  }

  *stats = NULL;
  if ( *n_entries > 0 ) {
    *stats = xmalloc( sizeof( flow_stats ) * ( *n_entries ) );
    memset( *stats, 0, sizeof( flow_stats ) * ( *n_entries ) );
  }

  struct timespec now = { 0, 0 };
  time_now( &now );
  struct timespec diff = { 0, 0 };
  flow_stats *stat = *stats;

  for ( list_element *e = entries; e != NULL; e = e->next ) {
    flow_entry *entry = e->data;
    stat->table_id = entry->table_id;
    timespec_diff( entry->created_at, now, &diff );
    stat->duration_sec = ( uint32_t ) diff.tv_sec;
    stat->duration_nsec = ( uint32_t ) diff.tv_nsec;
    stat->priority = entry->priority;
    stat->idle_timeout = entry->idle_timeout;
    stat->hard_timeout = entry->hard_timeout;
    stat->flags = entry->flags;
    stat->cookie = entry->cookie;
    stat->packet_count = entry->packet_count;
    stat->byte_count = entry->byte_count;
    stat->match = *entry->match;
    stat->instructions = *entry->instructions;

    stat++;
  }

  if ( entries != NULL ) {
    delete_list( entries );
  }

  if ( !unlock_pipeline() ) {
    return ERROR_UNLOCK;
  }

  return OFDPE_SUCCESS;
}


OFDPE
set_flow_table_features( const uint8_t table_id, const flow_table_features *features ) {
  warn( "Chaning flow table features is not supported ( table_id = %#x ).", table_id );

  if ( features == NULL ) {
    return ERROR_INVALID_PARAMETER;
  }

  return ERROR_NOT_SUPPORTED;
}


OFDPE
get_flow_table_features( const uint8_t table_id, flow_table_features *stats ) {
  if ( stats == NULL ) {
    return ERROR_INVALID_PARAMETER;
  }

  flow_table *table = get_flow_table( table_id );
  if ( table == NULL ) {
    return ERROR_OFDPE_BAD_REQUEST_BAD_TABLE_ID;
  }

  memcpy( stats, &( table->features ), sizeof( flow_table_features ) );

  return OFDPE_SUCCESS;
}


OFDPE
set_flow_table_config( const uint8_t table_id, const uint32_t config ) {
  warn( "Chaning flow table config is not supported ( table_id = %#x, config = %#x ).",
        table_id, config );

  return ERROR_NOT_SUPPORTED;
}


OFDPE
get_flow_table_config( const uint8_t table_id, uint32_t *config ) {
  assert( valid_table_id( table_id ) );
  assert( config != NULL );

  flow_table *table = get_flow_table( table_id );
  if ( table == NULL ) {
    return OFDPE_FAILED;
  }

  *config = table->features.config;

  return OFDPE_SUCCESS;
}


static void
dump_next_table_ids( const bool *next_table_ids, const char *name, void dump_function( const char *format, ... ) ) {
  char ids[ 1024 ], *cur = ids, *end = &ids[ sizeof( ids ) - 1 ];
  ids[ 0 ] = '\0';
  bool id_not_found = true;
  for ( uint8_t i = 0; i < N_FLOW_TABLES; i++ ) {
    if ( ( i % 32 ) == 0 ) {
      if ( ids[ 0 ] != 0 ) {
        ( *dump_function )( "%s:%s", name, ids );
        ids[ 0 ] = 0, cur = ids;
      }
    }
    else if ( next_table_ids[ i ] ) {
      id_not_found = false;
      snprintf( cur, ( size_t ) ( end - cur ), " %#x", i );
      cur += strlen( cur );
    }
  }
  if ( ids[ 0 ] != 0 ) {
    ( *dump_function )( "%s:%s", name, ids );
  }
  if ( id_not_found ) {
    ( *dump_function )( "%s: not found", name );
  }
}


void
dump_flow_table( const uint8_t table_id, void dump_function( const char *format, ... ) ) {
  assert( valid_table_id( table_id ) );
  assert( dump_function != NULL );

  if ( !lock_pipeline() ) {
    ( *dump_function )( "Cannot lock table %#x", table_id );
    return;
  }

  flow_table *table = get_flow_table( table_id );
  assert( table != NULL );

  ( *dump_function )( "#### TABLE %#x (%s) ####", table_id, table->initialized ? "initialized" : "not initialized yet" );
  ( *dump_function )( "[Features]" );
  ( *dump_function )( "table_id: %#x", table->features.table_id );
  ( *dump_function )( "name: %s", table->features.name );
  ( *dump_function )( "metadata_match: %#" PRIx64, table->features.metadata_match );
  ( *dump_function )( "metadata_write: %#" PRIx64, table->features.metadata_write );
  ( *dump_function )( "config: %#x", table->features.config );
  ( *dump_function )( "max_entries: %u", table->features.max_entries );
  ( *dump_function )( "instructions: %#" PRIx64, table->features.instructions );
  ( *dump_function )( "instructions_miss: %#" PRIx64, table->features.instructions_miss );
  ( *dump_function )( "write_actions: %#" PRIx64, table->features.write_actions );
  ( *dump_function )( "write_actions_miss: %#" PRIx64, table->features.write_actions_miss );
  ( *dump_function )( "apply_actions: %#" PRIx64, table->features.apply_actions );
  ( *dump_function )( "apply_actions_miss: %#" PRIx64, table->features.apply_actions_miss );
  ( *dump_function )( "matches: %#" PRIx64, table->features.matches );
  ( *dump_function )( "wildcards: %#" PRIx64, table->features.wildcards );
  ( *dump_function )( "write_setfield: %#" PRIx64, table->features.write_setfield );
  ( *dump_function )( "write_setfield_miss: %#" PRIx64, table->features.write_setfield_miss );
  ( *dump_function )( "apply_setfield: %#" PRIx64, table->features.apply_setfield );
  ( *dump_function )( "apply_setfield_miss: %#" PRIx64, table->features.apply_setfield_miss );
  dump_next_table_ids( table->features.next_table_ids, "next_table_ids", dump_function );
  dump_next_table_ids( table->features.next_table_ids_miss, "next_table_ids_miss", dump_function );
  ( *dump_function )( "[Stats]" );
  ( *dump_function )( "active_count: %u", table->counters.active_count );
  ( *dump_function )( "lookup_count: %" PRIu64, table->counters.lookup_count );
  ( *dump_function )( "matched_count: %" PRIu64, table->counters.matched_count );

  ( *dump_function )( "[Entries]" );

  for ( list_element *e = table->entries; e != NULL; e = e->next ) {
    flow_entry *entry = e->data;
    assert( entry != NULL );
    dump_flow_entry( entry, dump_function );
  }

  unlock_pipeline();
}


void
dump_flow_tables( void dump_function( const char *format, ... ) ) {
  assert( dump_function != NULL );

  for ( uint8_t id = 0; id <= FLOW_TABLE_ID_MAX; id++ ) {
    dump_flow_table( id, dump_function );
  }
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
