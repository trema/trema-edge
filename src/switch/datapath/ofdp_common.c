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


#include "ofdp_common.h"


#define dump info


void
time_now( struct timespec *now ) {
  assert( clock_gettime( CLOCK_MONOTONIC, now ) == 0 );
}


void
timespec_diff( struct timespec start, struct timespec end, struct timespec *diff ) {
  assert( diff != NULL );

  if ( ( end.tv_nsec - start.tv_nsec ) < 0 ) {
    diff->tv_sec = end.tv_sec - start.tv_sec - 1;
    diff->tv_nsec = 1000000000 + end.tv_nsec - start.tv_nsec;
  }
  else {
    diff->tv_sec = end.tv_sec - start.tv_sec;
    diff->tv_nsec = end.tv_nsec - start.tv_nsec;
  }
}


void
print_bitmap( const uint64_t bitmap, const uint64_t bit, const char *name ) {
  assert( name != NULL );

  dump( "%s = %s.", ( bitmap & bit ) != 0 ? "true" : "false" );
}


void
copy_buffer( buffer *dst, const buffer *src ) {
  assert( dst != NULL );
  assert( src != NULL );

  reset_buffer( dst );
  void *p = append_back_buffer( dst, src->length );
  memcpy( p, src->data, src->length );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/
