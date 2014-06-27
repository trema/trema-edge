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


#include "flow_table.h"
#include "group_table.h"
#include "meter_table.h"
#include "table_manager.h"


static pthread_mutex_t pipeline_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;


OFDPE
init_table_manager( const uint32_t max_flow_entries ) {
  init_flow_tables( max_flow_entries );
  init_group_table();
  init_meter_table();

  return OFDPE_SUCCESS;
}


OFDPE
finalize_table_manager( void ) {
  finalize_meter_table();
  finalize_group_table();
  finalize_flow_tables();

  return OFDPE_SUCCESS;
}


bool
lock_pipeline( void ) {
  int retval = pthread_mutex_lock( &pipeline_mutex );
  if ( retval != 0 ) {
    error( "Failed to lock pipeline." );
    return false;
  }

  return true;
}


bool
unlock_pipeline( void ) {
  int retval = pthread_mutex_unlock( &pipeline_mutex );
  if ( retval != 0 ) {
    error( "Failed to unlock pipeline." );
    return false;
  }

  return true;
}


bool
trylock_pipeline( void ) {
  int retval = pthread_mutex_trylock( &pipeline_mutex );
  if ( retval != 0 ) {
    return false;
  }

  return true;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/
