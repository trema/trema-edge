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


#include "action.h"
#include "flow_entry.h"


static bool
table_miss_flow_entry( const flow_entry *entry ) {
  assert( entry != NULL );

  if ( entry->priority == 0 && all_wildcarded_match( entry->match ) ) {
    return true;
  }

  return false;
}


flow_entry *
alloc_flow_entry( match *match, instruction_set *instructions,
                  const uint16_t priority, const uint16_t idle_timeout, const uint16_t hard_timeout,
                  const uint16_t flags, const uint64_t cookie ) {
  if ( validate_match( match ) != OFDPE_SUCCESS ) {
    return NULL;
  }

  flow_entry *entry = xmalloc( sizeof( flow_entry ) );
  memset( entry, 0, sizeof( flow_entry ) );

  entry->cookie = cookie;
  entry->duration_nsec = 0;
  entry->duration_sec = 0;
  entry->flags = flags;
  entry->priority = priority;
  entry->idle_timeout = idle_timeout;
  entry->hard_timeout = hard_timeout;
  entry->instructions = instructions;
  entry->match = match;
  entry->byte_count = 0;
  entry->packet_count = 0;
  time_now( &entry->created_at );
  entry->last_seen = entry->created_at;
  entry->table_miss = table_miss_flow_entry( entry );

  if ( instructions->write_actions != NULL && instructions->write_actions->actions != NULL ) {
    action_list *actions = instructions->write_actions->actions;
    for ( dlist_element *e = get_first_element( actions ); e != NULL; e = e->next ) {
      action *action = e->data;
      if ( action != NULL ) {
        action->entry = entry;
      }
    }
  }
  if ( instructions->apply_actions != NULL && instructions->apply_actions->actions != NULL ) {
    action_list *actions = instructions->apply_actions->actions;
    for ( dlist_element *e = get_first_element( actions ); e != NULL; e = e->next ) {
      action *action = e->data;
      if ( action != NULL ) {
        action->entry = entry;
      }
    }
  }

  return entry;
}


void
free_flow_entry( flow_entry *entry ) {
  assert( entry != NULL );

  if ( entry->instructions != NULL ) {
    delete_instruction_set( entry->instructions );
  }
  if ( entry->match != NULL ) {
    delete_match( entry->match );
  }

  xfree( entry );
}


void
dump_flow_entry( const flow_entry *entry, void dump_function( const char *format, ... ) ) {
  assert( entry != NULL );
  assert( dump_function != NULL );

  ( *dump_function )( "[flow entry ( %p )]", entry );
  ( *dump_function )( "table_id: %#x", entry->table_id );
  ( *dump_function )( "duration: %u.%09u", entry->duration_sec, entry->duration_nsec );
  ( *dump_function )( "priority: %u", entry->priority );
  ( *dump_function )( "idle_timeout: %u", entry->idle_timeout );
  ( *dump_function )( "hard_timeout: %u", entry->hard_timeout );
  ( *dump_function )( "flags: %#x", entry->flags );
  ( *dump_function )( "cookie: %#" PRIx64, entry->cookie );
  ( *dump_function )( "packet_count: %" PRIu64, entry->packet_count );
  ( *dump_function )( "byte_count: %" PRIu64, entry->byte_count );
  ( *dump_function )( "match: %p", entry->match );
  if ( entry->match != NULL ) {
    dump_match( entry->match, dump_function );
  }
  else {
    ( *dump_function )( "NULL" );
  }
  ( *dump_function )( "instructions: %p", entry->instructions );
  if ( entry->instructions != NULL ) {
    dump_instruction_set( entry->instructions, dump_function );
  }
  else {
    ( *dump_function )( "NULL" );
  }
  ( *dump_function )( "created_at: %d.%09d", ( int ) entry->created_at.tv_sec, ( int ) entry->created_at.tv_nsec );
  ( *dump_function )( "last_seen: %d.%09d", ( int ) entry->last_seen.tv_sec, ( int ) entry->last_seen.tv_nsec );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
