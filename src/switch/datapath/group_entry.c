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


#include "group_entry.h"


bool
valid_group_id( const uint32_t id ) {
  if ( id > OFPG_MAX ) {
    return false;
  }

  return true;
}


group_entry *
alloc_group_entry( const uint8_t type, const uint32_t group_id, bucket_list *buckets ) {
  if ( !valid_group_id( group_id ) ) {
    error( "Invalid group id ( %#x ).", group_id );
    return NULL;
  }
  if ( !valid_group_type( type ) ) {
    error( "Unsupported or undefined group type ( %#x ).", type );
    return NULL;
  }

  group_entry *entry = xmalloc( sizeof( group_entry ) );
  memset( entry, 0, sizeof( group_entry ) );

  entry->type = type;
  entry->group_id = group_id;
  entry->ref_count = 0;
  entry->packet_count = 0;
  entry->byte_count = 0;
  entry->duration_sec = 0;
  entry->duration_nsec = 0;
  entry->buckets = buckets;
  time_now( &entry->created_at );

  return entry;
}


void
free_group_entry( group_entry *entry ) {
  assert( entry != NULL );

  if ( entry->buckets != NULL ) {
    delete_action_bucket_list( entry->buckets );
  }
  xfree( entry );
}


bool
valid_group_type( const uint8_t type ) {
  bool ret = false;

  switch ( type ) {
    case OFPGT_ALL:
    case OFPGT_SELECT:
    case OFPGT_INDIRECT:
    {
      ret = true;
    }
    break;

    case OFPGT_FF:
    {
      warn( "OFPGT_FF is not supported." );
      ret = false;
    }
    break;

    default:
    {
      ret = false;
    }
    break;
  }

  return ret;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
