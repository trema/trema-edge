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
#include "flow_table.h"
#include "group_table.h"
#include "port_manager.h"
#include "table_manager.h"


static group_table *table = NULL;


static void
set_default_group_features( group_table_features *features ) {
  assert( features != NULL );

  features->types = ( GROUP_TYPE_ALL | GROUP_TYPE_SELECT | GROUP_TYPE_INDIRECT );
  features->capabilities = ( OFPGFC_SELECT_LIVENESS | OFPGFC_CHAINING );
  features->max_groups[ OFPGT_ALL ] = UINT32_MAX;
  features->max_groups[ OFPGT_SELECT ] = UINT32_MAX;
  features->max_groups[ OFPGT_INDIRECT ] = UINT32_MAX;
  features->max_groups[ OFPGT_FF ] = 0;
  features->actions[ OFPGT_ALL ] = SUPPORTED_ACTIONS;
  features->actions[ OFPGT_SELECT ] = SUPPORTED_ACTIONS;
  features->actions[ OFPGT_INDIRECT ] = SUPPORTED_ACTIONS;
  features->actions[ 3 ] = 0;
}


void
init_group_table( void ) {
  assert( table == NULL );

  table = xmalloc( sizeof( group_table ) );
  memset( table, 0, sizeof( group_table ) );

  create_list( &table->entries );
  set_default_group_features( &table->features );
  table->initialized = true;
}


void
finalize_group_table() {
  assert( table != NULL );
  assert( table->initialized );

  for ( list_element *element = table->entries; element != NULL; element = element->next ) {
    if ( element->data == NULL ) {
      continue;
    }
    group_entry *entry = element->data;
    if ( entry != NULL ) {
      free_group_entry( entry );
    }
  }
  if ( table->entries != NULL ) {
    delete_list( table->entries );
  }
  xfree( table );
  table = NULL;
}


group_entry *
lookup_group_entry( const uint32_t group_id ) {
  assert( table != NULL );
  assert( valid_group_id( group_id ) );

  if ( !lock_pipeline() ) {
    return NULL;
  }

  group_entry *entry = NULL;
  bool found = false;
  for ( list_element *element = table->entries; element != NULL; element = element->next ) {
    if ( element->data == NULL ) {
      continue;
    }
    entry = element->data;
    if ( entry->group_id == group_id ) {
      found = true;
      break;
    }
  }

  if ( !unlock_pipeline() ) {
    return NULL;
  }

  return found == true ? entry : NULL;
}


static OFDPE
validate_buckets( uint8_t type, bucket_list *buckets ) {
  assert( table != NULL );
  assert( buckets != NULL );

  OFDPE ret = OFDPE_SUCCESS;
  for ( dlist_element *element = get_first_element( buckets ); element != NULL; element = element->next ) {
    if ( element->data == NULL ) {
      continue;
    }
    bucket *bucket = element->data;
    if ( ( table->features.types & GROUP_TYPE_FF ) != 0 && type == OFPGT_FF ) {
      if ( !switch_port_exists( bucket->watch_port ) ) {
        ret = ERROR_OFDPE_GROUP_MOD_FAILED_BAD_WATCH;
        break;
      }
      if ( !group_exists( bucket->watch_group ) ) {
        ret = ERROR_OFDPE_GROUP_MOD_FAILED_BAD_WATCH;
        break;
      }
    }
    ret = validate_action_bucket( bucket );
    if ( ret != OFDPE_SUCCESS ) {
      break;
    }
  }

  return ret;
}


static OFDPE
validate_group_entry( group_entry *entry ) {
  assert( entry != NULL );

  if ( !valid_group_type( entry->type ) ) {
    return ERROR_OFDPE_GROUP_MOD_FAILED_INVALID_GROUP;
  }

  return validate_buckets( entry->type, entry->buckets );
}


OFDPE
add_group_entry( group_entry *entry ) {
  assert( table != NULL );

  if ( entry == NULL ) {
    return ERROR_INVALID_PARAMETER;
  }

  if ( !valid_group_id( entry->group_id ) ) {
    return ERROR_OFDPE_GROUP_MOD_FAILED_INVALID_GROUP;
  }

  if ( group_exists( entry->group_id ) ) {
    return ERROR_OFDPE_GROUP_MOD_FAILED_GROUP_EXISTS;
  }

  if ( !lock_pipeline() ) {
    return ERROR_LOCK;
  }

  OFDPE ret = validate_group_entry( entry );
  if ( ret == OFDPE_SUCCESS ) {
    append_to_tail( &table->entries, entry );
  }

  if ( !unlock_pipeline() ) {
    return ERROR_UNLOCK;
  }

  return ret;
}


OFDPE
update_group_entry( const uint32_t group_id, const uint8_t type, bucket_list *buckets ) {
  assert( table != NULL );

  if ( !valid_group_id( group_id ) ) {
    return ERROR_OFDPE_GROUP_MOD_FAILED_INVALID_GROUP;
  }

  if ( !valid_group_type( type ) ) {
    return ERROR_OFDPE_GROUP_MOD_FAILED_INVALID_GROUP;
  }

  if ( !lock_pipeline() ) {
    return ERROR_LOCK;
  }

  OFDPE ret = OFDPE_SUCCESS;
  group_entry *entry = lookup_group_entry( group_id );
  if ( entry == NULL ) {
    ret = ERROR_OFDPE_GROUP_MOD_FAILED_UNKNOWN_GROUP;
  }

  if ( ret == OFDPE_SUCCESS ) {
    ret = validate_buckets( entry->type, buckets );
  }

  if ( ret == OFDPE_SUCCESS ) {
    if ( entry->buckets != NULL ) {
      delete_action_bucket_list( entry->buckets );
    }
    entry->type = type;
    entry->buckets = buckets;
  }

  if ( !unlock_pipeline() ) {
    return ERROR_UNLOCK;
  }

  return ret;
}


OFDPE
delete_group_entry( const uint32_t group_id ) {
  assert( table != NULL );

  if ( !valid_group_id( group_id ) ) {
    return ERROR_OFDPE_GROUP_MOD_FAILED_INVALID_GROUP;
  }

  if ( !lock_pipeline() ) {
    return ERROR_LOCK;
  }

  if ( group_id != OFPG_ALL ) {
    group_entry *entry = lookup_group_entry( group_id );
    if ( entry != NULL ) {
      delete_element( &table->entries, entry );
      delete_flow_entries_by_group_id( entry->group_id );
      free_group_entry( entry );
    }
  }
  else {
    for ( list_element *element = table->entries; element != NULL; element = element->next ) {
      if ( element->data == NULL ) {
        continue;
      }
      group_entry *entry = element->data;
      delete_flow_entries_by_group_id( entry->group_id );
      free_group_entry( entry );
    }
    delete_list( table->entries );
    create_list( &table->entries );
  }

  if ( !unlock_pipeline() ) {
    return ERROR_UNLOCK;
  }

  return OFDPE_SUCCESS;
}


bool
group_exists( const uint32_t group_id ) {
  assert( table != NULL );

  return lookup_group_entry( group_id ) != NULL ? true : false;
}


OFDPE
get_group_stats( const uint32_t group_id, group_stats **stats, uint32_t *n_groups ) {
  assert( table != NULL );
  assert( stats != NULL );
  assert( n_groups != NULL );

  if ( !valid_group_id( group_id ) && group_id != OFPG_ALL ) {
    return ERROR_OFDPE_BAD_REQUEST_BAD_TABLE_ID;
  }

  if ( !lock_pipeline() ) {
    return ERROR_LOCK;
  }

  OFDPE ret = OFDPE_SUCCESS;

  list_element *groups = NULL;
  create_list( &groups );
  *n_groups = 0;
  if ( group_id != OFPG_ALL ) {
    group_entry *entry = lookup_group_entry( group_id );
    if ( entry == NULL ) {
      if ( !unlock_pipeline() ) {
        return ERROR_UNLOCK;
      }
      return ERROR_OFDPE_BAD_REQUEST_BAD_TABLE_ID;
    }
    append_to_tail( &groups, entry );
    ( *n_groups )++;
  }
  else {
    for ( list_element *e = table->entries; e != NULL; e = e->next ) {
      if ( e->data == NULL ) {
        continue;
      }
      group_entry *entry = e->data;
      append_to_tail( &groups, entry );
      ( *n_groups )++;
    }
  }

  *stats = NULL;
  if ( *n_groups > 0 ) {
    *stats = xmalloc( sizeof( group_stats ) * ( *n_groups ) );
    memset( *stats, 0, sizeof( group_stats ) * ( *n_groups ) );
  }

  group_stats *stat = *stats;
  for ( list_element *e = groups; e != NULL; e = e->next ) {
    assert( e->data != NULL );
    group_entry *entry = e->data;
    stat->group_id = entry->group_id;
    stat->ref_count = entry->ref_count;
    stat->packet_count = entry->packet_count;
    stat->byte_count = entry->byte_count;
    struct timespec now = { 0, 0 };
    time_now( &now );
    struct timespec diff = { 0, 0 };
    timespec_diff( entry->created_at, now, &diff );
    stat->duration_sec = ( uint32_t ) diff.tv_sec;
    stat->duration_nsec = ( uint32_t ) diff.tv_nsec;
    create_list( &stat->bucket_stats );
    for ( dlist_element *b = get_first_element( entry->buckets ); b != NULL; b = b->next ) {
      if ( b->data == NULL ) {
        continue;
      }
      bucket *bucket = b->data;
      bucket_counter *counter = xmalloc( sizeof( bucket_counter ) );
      memset( counter, 0, sizeof( bucket_counter ) );
      counter->packet_count = bucket->packet_count;
      counter->byte_count = bucket->byte_count;
      append_to_tail( &stat->bucket_stats, counter );
    }
    stat++;
  }

  if ( groups != NULL ) {
    delete_list( groups );
  }

  if ( !unlock_pipeline() ) {
    return ERROR_UNLOCK;
  }

  return ret;
}


OFDPE
get_group_desc( group_desc **stats, uint16_t *n_groups ) {
  assert( table != NULL );
  assert( n_groups != NULL );

  if ( !lock_pipeline() ) {
    return ERROR_LOCK;
  }

  *n_groups = 0;
  for ( list_element *element = table->entries; element != NULL; element = element->next ) {
    if ( element->data == NULL ) {
      continue;
    }
    ( *n_groups )++;
  }

  size_t length = sizeof( group_desc ) * ( *n_groups );
  *stats = NULL;
  if ( *n_groups > 0 ) {
    *stats = xmalloc( length );
    memset( *stats, 0, length );
  }

  group_desc *stat = *stats;
  for ( list_element *element = table->entries; element != NULL; element = element->next ) {
    if ( element->data == NULL ) {
      continue;
    }
    group_entry *entry = element->data;
    stat->type = entry->type;
    stat->group_id = entry->group_id;
    stat->buckets = duplicate_buckets( entry->buckets );
    stat++;
  }

  if ( !unlock_pipeline() ) {
    return ERROR_UNLOCK;
  }

  return OFDPE_SUCCESS;
}


OFDPE
get_group_features( group_table_features *features ) {
  assert( table != NULL );
  assert( features != NULL );

  memcpy( features, &table->features, sizeof( group_table_features ) );

  return OFDPE_SUCCESS;
}


OFDPE
set_group_features( group_table_features *features ) {
  assert( table != NULL );
  assert( features != NULL );

  // TODO: implement this function properly to reflect changes to actual behaviors.

  warn( "set_group_features() is not implemented yet." );

  memcpy( &table->features, features, sizeof( group_table_features ) );

  return OFDPE_SUCCESS;
}


void
increment_reference_count( const uint32_t group_id ) {
  assert( table != NULL );
  assert( valid_group_id( group_id ) );

  if ( !lock_pipeline() ) {
    error( "Failed to lock pipeline." );
    return;
  }

  group_entry *entry = lookup_group_entry( group_id );
  if ( entry != NULL ) {
    entry->ref_count++;
  }

  if ( !unlock_pipeline() ) {
    error( "Failed to unlock pipeline." );
  }
}


void
decrement_reference_count( const uint32_t group_id ) {
  assert( table != NULL );
  assert( valid_group_id( group_id ) );

  if ( !lock_pipeline() ) {
    error( "Failed to lock pipeline." );
    return;
  }

  group_entry *entry = lookup_group_entry( group_id );
  if ( entry != NULL ) {
    entry->ref_count--;
  }

  if ( !unlock_pipeline() ) {
    error( "Failed to unlock pipeline." );
  }
}


void
dump_group_table( void dump_function( const char *format, ... ) ) {
  assert( table != NULL );
  assert( dump_function != NULL );

  for ( list_element *element = table->entries; element != NULL; element = element->next ) {
    if ( element->data == NULL ) {
      continue;
    }
    group_entry *entry = element->data;
    dump_group_entry( entry, dump_function );
  }
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
