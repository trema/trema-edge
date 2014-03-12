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


#include "action_bucket.h"
#include "port_manager.h"


bucket *
create_action_bucket( const uint16_t weight, const uint32_t watch_port, const uint32_t watch_group, action_list *actions ) {
  bucket *new_bucket = xmalloc( sizeof( bucket ) );
  memset( new_bucket, 0, sizeof( bucket ) );

  new_bucket->weight = weight;
  new_bucket->watch_port = watch_port;
  new_bucket->watch_group = watch_group;
  new_bucket->actions = actions;
  new_bucket->packet_count = 0;
  new_bucket->byte_count = 0;

  return new_bucket;
}


void
delete_action_bucket( bucket *bucket ) {
  assert( bucket != NULL );

  delete_action_list( bucket->actions );
  xfree( bucket );
}


bucket_list *
create_action_bucket_list() {
  return create_dlist();
}


void
delete_action_bucket_list( bucket_list *list ) {
  assert( list != NULL );

  dlist_element *element = get_first_element( list );
  while ( element != NULL ) {
    bucket *b = element->data;
    if ( b != NULL ) {
      delete_action_bucket( b );
    }
    element = element->next;
  }
  delete_dlist( list );
}


OFDPE
append_action_bucket( bucket_list *list, bucket *bucket ) {
  assert( list != NULL );
  assert( bucket != NULL );

  list = insert_before_dlist( list, ( void * ) bucket );
  if ( list == NULL ) {
    return ERROR_NO_MEMORY;
  }

  return OFDPE_SUCCESS;
}


OFDPE
remove_action_bucket( bucket_list *list, bucket *bucket ) {
  assert( list != NULL );
  assert( bucket != NULL );

  dlist_element *elemenet = find_element( list, bucket );
  if ( elemenet == NULL ) {
    return ERROR_NOT_FOUND;
  }
  delete_action_bucket( bucket );
  delete_dlist_element( elemenet );

  return OFDPE_SUCCESS;
}


OFDPE
validate_action_bucket( const bucket *bucket ) {
  assert( bucket != NULL );

  return validate_action_list( bucket->actions );
}


OFDPE
validate_action_bucket_list( bucket_list *buckets ) {
  assert( buckets != NULL );

  OFDPE ret = OFDPE_SUCCESS;
  dlist_element *element = get_first_element( buckets );
  while ( element != NULL ) {
    bucket *b = element->data;
    if ( b != NULL ) {
      ret = validate_action_bucket( b );
      if ( ret != OFDPE_SUCCESS ) {
        break;
      }
    }
    element = element->next;
  }

  return ret;
}


uint32_t
get_bucket_count( bucket_list *list ) {
  assert( list != NULL );

  uint32_t count = 0;

  dlist_element *element = get_first_element ( list );
  while ( element != NULL ) {
    if ( element->data != NULL ) {
      count++;
    }
    element = element->next;
  }

  return count;
}


bucket *
duplicate_bucket( const bucket *src ) {
  if ( src == NULL ) {
    return NULL;
  }

  bucket *duplicated = xmalloc( sizeof( bucket ) );
  memcpy( duplicated, src, sizeof( bucket ) );
  duplicated->actions = duplicate_actions( src->actions );

  return duplicated;
}


bucket_list *
duplicate_bucket_list( bucket_list *buckets ) {
  if ( buckets == NULL ) {
    return NULL;
  }

  bucket_list *duplicated = create_action_bucket_list();
  for ( dlist_element *e = get_first_element( buckets ); e != NULL; e = e->next ) {
    if ( e->data == NULL ) {
      continue;
    }
    append_action_bucket( duplicated, duplicate_bucket( e->data ) );
  }

  return duplicated;
}


static void
dump_bucket( const bucket *bucket, void dump_function( const char *format, ... ) ) {
  assert( bucket != NULL );
  assert( dump_function != NULL );

  ( *dump_function )( "weight: %u", bucket->weight );
  ( *dump_function )( "watch_port: %u", bucket->watch_port );
  ( *dump_function )( "watch_group: %u", bucket->watch_group );
  ( *dump_function )( "packet_count: %" PRIu64, bucket->packet_count );
  ( *dump_function )( "byte_count: %" PRIu64, bucket->byte_count );
  ( *dump_function )( "actions: %p", bucket->actions );
  if ( bucket->actions != NULL ) {
    dump_action_list( bucket->actions, dump_function );
  }
}


void
dump_buckets( bucket_list *buckets, void dump_function( const char *format, ... ) ) {
  assert( buckets != NULL );
  assert( dump_function != NULL );

  for ( dlist_element *element = get_first_element( buckets ); element != NULL; element = element->next ) {
    if ( element->data == NULL ) {
      continue;
    }
    bucket *bucket = element->data;
    dump_bucket( bucket, dump_function );
  }
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/
