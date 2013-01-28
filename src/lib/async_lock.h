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


#ifndef ASYNC_LOCK_H
#define ASYNC_LOCK_H


#include <pthread.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


enum lock_section {
  event_section,
  timer_section,
  MAX_SECTIONS,
};


struct lock_group {
  pthread_mutex_t mutex;
  pthread_mutex_t rw_mutex;
  pthread_cond_t read_cond;
  pthread_cond_t write_cond;
  uint32_t read_count;
  uint32_t writer_waiting;
};


#define LCK_GRP_INIT { .mutex = PTHREAD_MUTEX_INITIALIZER, .read_count = 0, .writer_waiting = 0x80000000 }


struct section {
  uint32_t incremented_read;
};


struct thread_info {
  pthread_t thread_id;
  struct section sections[ MAX_SECTIONS ];
};


#define attr( attr, idx ) \
  sections[ ( idx ) ].attr


struct thread_info_list {
  struct thread_info **threads;
  uint32_t threads_nr;
  uint32_t threads_alloc;
};


void event_read_begin( void );
void timer_read_begin( void );


int event_write_begin( void );
int timer_write_begin( void );


void event_read_end( void );
void timer_read_end( void );


void event_write_end( void );
void timer_write_end( void );


void add_thread( void );


#ifdef __cplusplus
}
#endif


#endif // ASYNC_LOCK_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
