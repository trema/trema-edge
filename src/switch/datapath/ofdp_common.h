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


#ifndef OFDP_COMMON_H
#define OFDP_COMMON_H


#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#include "ofdp_error.h"
#include "trema.h"


enum {
  ERROR_STRING_SIZE = 256,
};


extern uint16_t MISS_SEND_LEN;


void time_now( struct timespec *tp );
void timespec_diff( struct timespec start, struct timespec end, struct timespec *diff );
void print_bitmap( const uint64_t bitmap, const uint64_t bit, const char *name );
void copy_buffer( buffer *dst, const buffer *src );


#endif // OFDP_COMMON_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/
