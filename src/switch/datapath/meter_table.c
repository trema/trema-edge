#include "ofdp_common.h"
#include "flow_table.h"
#include "meter_table.h"
#include "table_manager.h"

static meter_table *table = NULL;

void
init_meter_table( void ) {
  assert( table == NULL );

  table = xmalloc( sizeof( meter_table ) );
  memset( table, 0, sizeof( meter_table ) );

  create_list( &table->entries );
  table->initialized = true;
}

void finalize_meter_table( void ) {
  assert( table != NULL );
  assert( table->initialized );
  
  for ( list_element *element = table->entries; element != NULL; element = element->next ) {
    if ( element->data == NULL ) {
      continue;
    }
    meter_entry *entry = element->data;
    if ( entry != NULL ) {
      free_meter_entry( entry );
    }
  }
  if ( table->entries != NULL ) {
    delete_list( table->entries );
  }
  xfree( table );
  table = NULL;
}


OFDPE
add_meter_entry( const uint16_t flags, const uint32_t meter_id, const list_element *bands ) {
  assert( table != NULL );

  if ( meter_id == 0 || ( meter_id > OFPM_MAX && meter_id != OFPM_CONTROLLER )) {
    return ERROR_OFDPE_METER_MOD_FAILED_INVALID_METER;
  }

  meter_entry *entry = alloc_meter_entry( flags, meter_id, bands );
  if ( entry == NULL ) {
    return ERROR_INVALID_PARAMETER;
  }

  OFDPE ret = OFDPE_SUCCESS;
  if ( !lock_pipeline() ) {
    free_meter_entry( entry );
    return ERROR_LOCK;
  }
  if ( NULL != lookup_meter_entry( entry->meter_id ) ) {
    ret = ERROR_OFDPE_METER_MOD_FAILED_METER_EXISTS;
    free_meter_entry( entry );
  } else {
    append_to_tail( &table->entries, entry );
  }
  if ( !unlock_pipeline() ) {
    free_meter_entry( entry );
    return ERROR_UNLOCK;
  }
  return ret;
}


OFDPE
replace_meter_entry( const uint16_t flags, const uint32_t meter_id, const list_element *bands ) {
  assert( table != NULL );

  if ( meter_id == 0 || ( meter_id > OFPM_MAX && meter_id != OFPM_CONTROLLER )) {
    return ERROR_OFDPE_METER_MOD_FAILED_INVALID_METER;
  }

  meter_entry *entry = alloc_meter_entry( flags, meter_id, bands );
  if ( entry == NULL ) {
    return ERROR_INVALID_PARAMETER;
  }

  OFDPE ret = OFDPE_SUCCESS;
  if ( !lock_pipeline() ) {
    free_meter_entry( entry );
    return ERROR_LOCK;
  }
  meter_entry *old_entry = lookup_meter_entry( entry->meter_id );
  if ( NULL == old_entry ) {
    ret = ERROR_OFDPE_METER_MOD_FAILED_UNKNOWN_METER;
    free_meter_entry( entry );
  } else {
    entry->ref_count = old_entry->ref_count;
    entry->packet_count = old_entry->packet_count;
    entry->byte_count = old_entry->byte_count;
    entry->estimated_rate = old_entry->estimated_rate;
    entry->created_at = old_entry->created_at;
    entry->meter_at = old_entry->meter_at;
    
    delete_element( &table->entries, old_entry );
    append_to_tail( &table->entries, entry );
    free_meter_entry( old_entry );
  }
  if ( !unlock_pipeline() ) {
    free_meter_entry( entry );
    return ERROR_UNLOCK;
  }
  return ret;
}


OFDPE
delete_meter_entry( const uint32_t meter_id ) {
  assert( table != NULL );

  if ( meter_id == 0 && meter_id <= OFPM_MAX && meter_id != OFPM_CONTROLLER && meter_id != OFPM_ALL ) {
    return ERROR_OFDPE_METER_MOD_FAILED_INVALID_METER;
  }

  OFDPE ret = OFDPE_SUCCESS;
  if ( !lock_pipeline() ) {
    return ERROR_LOCK;
  }
  if ( meter_id == OFPM_ALL ) {
    delete_flow_entries_by_meter_id( meter_id );
    for ( list_element *e = table->entries; e != NULL; ) {
      list_element *next = e->next;
      meter_entry *entry = e->data;
      if ( entry->meter_id > 0 && entry->meter_id <= OFPM_MAX ) { // virtual meters won't be deleted by OFPM_ALL
        delete_element( &table->entries, entry );
        free_meter_entry( entry );
      }
      e = next;
    }
  } else {
    meter_entry *old_entry = lookup_meter_entry( meter_id );
    if ( NULL == old_entry ) {
      ret = ERROR_OFDPE_METER_MOD_FAILED_UNKNOWN_METER;
    } else {
      if ( old_entry->ref_count > 0 ) {
        delete_flow_entries_by_meter_id( meter_id );
      }
      delete_element( &table->entries, old_entry );
      free_meter_entry( old_entry );
    }
  }
  if ( !unlock_pipeline() ) {
    return ERROR_UNLOCK;
  }
  return ret;
}


meter_entry*
lookup_meter_entry( const uint32_t meter_id ){
  for ( list_element *element = table->entries; element != NULL; element = element->next ) {
    if ( element->data == NULL ) {
      continue;
    }
    meter_entry *entry = element->data;
    if ( entry != NULL && entry->meter_id == meter_id ) {
      return entry;
    }
  }
  return NULL;
}


OFDPE
ref_meter_id( const uint32_t meter_id ) {
  if ( meter_id == 0 || meter_id > OFPM_MAX ) {
    return ERROR_OFDPE_METER_MOD_FAILED_INVALID_METER;
  }
  if ( !lock_pipeline() ) {
    return ERROR_UNLOCK;
  }
  meter_entry *entry = lookup_meter_entry( meter_id );
  if ( entry == NULL ) {
    return ERROR_OFDPE_METER_MOD_FAILED_UNKNOWN_METER;
  }
  entry->ref_count++;
  if ( !unlock_pipeline() ) {
    return ERROR_UNLOCK;
  }
  return OFDPE_SUCCESS;
}


OFDPE
unref_meter_id( const uint32_t meter_id ) {
  if ( meter_id == 0 || meter_id > OFPM_MAX ) {
    return ERROR_OFDPE_METER_MOD_FAILED_INVALID_METER;
  }
  if ( !lock_pipeline() ) {
    return ERROR_UNLOCK;
  }
  meter_entry *entry = lookup_meter_entry( meter_id );
  if ( entry == NULL ) {
    return ERROR_OFDPE_METER_MOD_FAILED_UNKNOWN_METER;
  }
  entry->ref_count--;
  if ( !unlock_pipeline() ) {
    return ERROR_UNLOCK;
  }
  return OFDPE_SUCCESS;
}


OFDPE
get_meter_stats( const uint32_t meter_id, meter_entry** entries, uint32_t *count ) {
  OFDPE ret = OFDPE_SUCCESS;
  if ( !lock_pipeline() ) {
    return ERROR_UNLOCK;
  }

  *entries = NULL;
  *count = 0;
  if ( meter_id == OFPM_ALL ) {
    *count = list_length_of(table->entries);
    meter_entry *head = xcalloc(*count, sizeof(meter_entry));
    int i=0;
    for ( list_element *e = table->entries; e != NULL; e=e->next,i++ ) {
      clone_meter_entry( head+i, e->data );
    }
    *entries = head;
  } else {
    meter_entry *entry = lookup_meter_entry( meter_id );
    if ( entry == NULL ) {
      ret = ERROR_OFDPE_METER_MOD_FAILED_UNKNOWN_METER;
    } else {
      *count = 1;
      *entries = clone_meter_entry( NULL, entry );
    }
  }

  if ( !unlock_pipeline() ) {
    return ERROR_UNLOCK;
  }
  return ret;
}
