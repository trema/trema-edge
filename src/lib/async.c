/*
 * Copyright (C) 2008-2013 NEC Corporation
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


#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "array_util.h"
#include "async.h"
#include "log.h"


static int main_thread_set = 0;
static pthread_t main_thread = 0;
static pthread_key_t async_key = 0;


int
finish_async( struct async *async ) {
  assert( async != NULL );

  void *thread_ret = ( void * ) ( intptr_t ) ( -1 );
  int ret = pthread_join( async->tid, &thread_ret );
  if ( ret != 0 ) {
    char buf[ 256 ];
    char *error_string = strerror_r( ret, buf, sizeof( buf ) );
    error( "Failed to join a thread ( %s [%d] ).", error_string, ret );
  }

  return ( int ) ( intptr_t ) thread_ret;
}


static void *
run_thread( void *data ) {
  assert( data != NULL );

  struct async *async = data;

  pthread_setspecific( async_key, data );
  intptr_t ret = async->proc( async->data );

  return ( void * ) ret;
}


int 
start_async( struct async *async ) {
  assert( async != NULL );

  if ( !main_thread_set ) {
    main_thread_set = 1;
    main_thread = pthread_self();
    pthread_key_create( &async_key, NULL );
  }

  int ret = pthread_create( &async->tid, NULL, run_thread, async );
  if ( ret != 0 ) {
    char buf[ 256 ];
    char *error_string = strerror_r( ret, buf, sizeof( buf ) );
    error( "Failed to create a thread ( %s [%d] ).", error_string, ret );
  }

  return 0;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
