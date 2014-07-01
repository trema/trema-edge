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

#include <assert.h>
#include <errno.h>
#include "mutex.h"
#include "wrapper.h"
#include "log.h"

#define ERROR_STRING_SIZE 256

bool
init_mutex( pthread_mutex_t *mutex ) {
  assert( mutex != NULL );

  pthread_mutexattr_t attr;
  pthread_mutexattr_init( &attr );
  pthread_mutexattr_settype( &attr, PTHREAD_MUTEX_RECURSIVE_NP );

  int ret = pthread_mutex_init( mutex, &attr );
  if ( ret != 0 ) {
    char error_string[ ERROR_STRING_SIZE ];
    error( "Failed to initialize mutex ( mutex = %p, ret = %s [%d] ).",
           mutex, safe_strerror_r( ret, error_string, sizeof( error_string ) ), ret );
    return false;
  }

  return true;
}


bool
finalize_mutex( pthread_mutex_t *mutex ) {
  assert( mutex != NULL );

  int ret = pthread_mutex_destroy( mutex );
  if ( ret != 0 ) {
    char error_string[ ERROR_STRING_SIZE ];
    error( "Failed to destroy mutex ( mutex = %p, ret = %s [%d] ).",
           mutex, safe_strerror_r( ret, error_string, sizeof( error_string ) ), ret );
    return false;
  }

  return true;
}


bool
lock_mutex( pthread_mutex_t *mutex ) {
  assert( mutex != NULL );

  int ret = pthread_mutex_lock( mutex );
  if ( ret != 0 ) {
    char error_string[ ERROR_STRING_SIZE ];
    error( "Failed to lock mutex ( mutex = %p, ret = %s [%d] ).",
           mutex, safe_strerror_r( ret, error_string, sizeof( error_string ) ), ret );
    return false;
  }

  return true;
}


bool
unlock_mutex( pthread_mutex_t *mutex ) {
  assert( mutex != NULL );

  int ret = pthread_mutex_unlock( mutex );
  if ( ret != 0 ) {
    char error_string[ ERROR_STRING_SIZE ];
    error( "Failed to unlock mutex ( mutex = %p, ret = %s [%d] ).",
           mutex, safe_strerror_r( ret, error_string, sizeof( error_string ) ), ret );
    return false;
  }

  return true;
}


bool
try_lock( pthread_mutex_t *mutex ) {
  assert( mutex != NULL );

  int ret = pthread_mutex_trylock( mutex );
  if ( ret != 0 ) {
    char error_string[ ERROR_STRING_SIZE ];
    error( "Failed to try lock mutex ( mutex = %p, ret = %s [%d] ).",
           mutex, safe_strerror_r( ret, error_string, sizeof( error_string ) ), ret );
    return false;
  }

  return true;
}


char *
safe_strerror_r( int errnum, char *buf, size_t buflen ) {
  assert( buf != NULL );
  assert( buflen > 0 );

  int original = errnum;

  memset( buf, '\0', buflen );

#if ( _POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600 ) && ! _GNU_SOURCE
  int ret = strerror_r( errnum, buf, buflen );
  char *error_string = buf;
#else
  char *error_string = strerror_r( errnum, buf, buflen );
#endif

  errno = original;

  return error_string;
}

/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/
