/*
 * Author: Yasunobu Chiba
 *
 * Copyright (C) 2008-2012 NEC Corporation
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


#include <string.h>
#include "trema.h"
#include "utils.h"


void
timeout( void *user_data ) {
  handler_data *data = user_data;
  char match_string[ MATCH_STRING_LENGTH ];
  match_to_string( data->match, match_string, sizeof( match_string ) );

  error( "Timeout ( match = [%s], service_name = %s, strict = %s ).",
         match_string, data->service_name, data->strict ? "true" : "false" );

  delete_oxm_matches( data->match );
  stop_trema();
}


void
add_filter_completed( int status, void *user_data ) {
  handler_data *data = user_data;
  char match_string[ MATCH_STRING_LENGTH ];
  match_to_string( data->match, match_string, sizeof( match_string ) );

  if ( status != PACKETIN_FILTER_OPERATION_SUCCEEDED ) {
    error( "Failed to add a packetin filter ( match = [%s], service_name = %s ).",
           match_string, data->service_name );
  }
  info( "A packetin filter was added ( match = [%s], service_name = %s ).",
        match_string, data->service_name );

  delete_oxm_matches( data->match );
  stop_trema();
}


void
delete_filter_completed( int status, int n_deleted, void *user_data ) {
  handler_data *data = user_data;
  char match_string[ MATCH_STRING_LENGTH ];
  match_to_string( data->match, match_string, sizeof( match_string ) );

  if ( status != PACKETIN_FILTER_OPERATION_SUCCEEDED ) {
    error( "Failed to delete packetin filters ( match = [%s], service_name = %s, strict = %s ).",
           match_string, data->service_name, data->strict ? "true" : "false" );
  }
  info( "%d packetin filter%s deleted ( match = [%s], service_name = %s, strict = %s ).",
        n_deleted, n_deleted > 1 ? "s were" : " was", match_string,
        data->service_name, data->strict ? "true" : "false" );

  delete_oxm_matches( data->match );
  stop_trema();
}


void
dump_filters( int status, int n_entries, packetin_filter_entry *entries, void *user_data ) {
  handler_data *data = user_data;
  char match_string[ MATCH_STRING_LENGTH ];
  match_to_string( data->match, match_string, sizeof( match_string ) );

  if ( status != PACKETIN_FILTER_OPERATION_SUCCEEDED ) {
    error( "Failed to dump packetin filters ( match = [%s], service_name = %s, strict = %s ).",
           match_string, data->service_name, data->strict ? "true" : "false" );
  }
  info( "%d packetin filter%s found ( match = [%s], service_name = %s, strict = %s ).",
        n_entries, n_entries > 1 ? "s" : "", match_string, data->service_name,
        data->strict ? "true" : "false" );

  packetin_filter_entry *entry = entries;
  oxm_matches *match;
  for ( int i = 0; i < n_entries; i++ ) {
    uint16_t match_len = ( uint16_t ) ( entry->match.length + PADLEN_TO_64( entry->match.length ) );
    struct ofp_match *tmp_match = xcalloc( 1, match_len );
    hton_match( tmp_match, &entry->match );
    match = parse_ofp_match( tmp_match );
    match_to_string( match, match_string, sizeof( match_string ) );
    info( "[#%d] match = [%s], priority = %u, service_name = %s.",
          i, match_string, entry->priority, entry->service_name );
    entry = ( packetin_filter_entry * ) ( ( char * ) entry + entry->length );
    xfree( tmp_match );
    delete_oxm_matches( match );
  }

  delete_oxm_matches( data->match );
  stop_trema();
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
