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
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "array_util.h"
#include "async_lock.h"
#include "async_util.h"
#include "log.h"
#include "trema_wrapper.h"
#include "wrapper.h"


static struct thread_info_list thread_list;
static struct lock_group lck_grp[ MAX_SECTIONS ] = { 
  LCK_GRP_INIT,
  LCK_GRP_INIT
};
static pthread_mutex_t global_mutex;
LOCK_OBJ( global )
UNLOCK_OBJ( global )
GET_OBJ_INFO( thread )


static inline int
compare_and_swap( const uint32_t old, const uint32_t new, uint32_t *address, pthread_mutex_t *mutex  ) {
  assert( address != NULL );
  assert( mutex != NULL );

  int ret = 0;
  pthread_mutex_lock( mutex );
  if ( *address == old ) {
    *address = new;
    ret = 1;
  }
  pthread_mutex_unlock( mutex );

  return ret;
}


static void
lock_read_begin( enum lock_section section ) {
  uint32_t new_value;
  uint32_t old_value;

  struct thread_info *thread = get_thread_info();
  assert( thread != NULL );

  if ( thread->attr( incremented_read, section ) == lck_grp[ section ].writer_waiting ) {
    trema_abort();
  }

  struct timespec ts = { 0, 0 };
  int ret = -1;
  do {
again:
    pthread_mutex_lock( &lck_grp[ section ].mutex );
    old_value = lck_grp[ section ].read_count;
    pthread_mutex_unlock( &lck_grp[ section ].mutex );

    if ( ( old_value & lck_grp[ section ].writer_waiting ) != 0 && thread->attr( incremented_read, section ) == 0 ) {
      pthread_mutex_lock( &lck_grp[ section ].rw_mutex );
      {
        clock_gettime( CLOCK_REALTIME, &ts );
        ts.tv_sec += 1;
        ret = pthread_cond_timedwait( &lck_grp[ section ].read_cond, &lck_grp[ section ].rw_mutex, &ts );
      }
      pthread_mutex_unlock( &lck_grp[ section ].rw_mutex );
      if ( ret == ETIMEDOUT ) {
        goto again;
      }
    }
    new_value = old_value + 1;
  } while ( !compare_and_swap( old_value, new_value, &lck_grp[ section ].read_count, &lck_grp[ section ].mutex ) );

  thread->attr( incremented_read, section )++;
}


static void
lock_read_end( enum lock_section section ) {
  struct thread_info *thread = get_thread_info();
  assert( thread != NULL );

  pthread_mutex_lock( &lck_grp[ section ].mutex );
  lck_grp[ section ].read_count--;
  pthread_mutex_unlock( &lck_grp[ section ].mutex );
  thread->attr( incremented_read, section )--;
  if ( lck_grp[ section ].read_count == lck_grp[ section ].writer_waiting ) {
    pthread_mutex_lock( &lck_grp[ section ].rw_mutex );
    {
      pthread_cond_signal( &lck_grp[ section ].write_cond );
    }
    pthread_mutex_unlock( &lck_grp[ section ].rw_mutex );
  }
}


static int
lock_write_begin( enum lock_section section ) {
  struct thread_info *thread = get_thread_info();
  assert( thread != NULL );

  if ( thread->attr( incremented_read, section ) != 0 ) {
    return -1;
  }
  pthread_mutex_lock( &lck_grp[ section ].mutex );
  lck_grp[ section ].read_count |= lck_grp[ section ].writer_waiting;

  struct timespec ts = { 0, 0 };
  int ret = -1;

again:
  if ( lck_grp[ section ].read_count == lck_grp[ section ].writer_waiting ) {
    thread->attr( incremented_read, section ) = lck_grp[ section ].writer_waiting;
    return 0;
  }
  else {
    pthread_mutex_lock( &lck_grp[ section ].rw_mutex );
    {
      clock_gettime( CLOCK_REALTIME, &ts );
      ts.tv_sec += 1;
      ret = pthread_cond_timedwait( &lck_grp[ section ].write_cond, &lck_grp[ section ].rw_mutex, &ts );
    }
    pthread_mutex_unlock( &lck_grp[ section ].rw_mutex );
    if ( ret == ETIMEDOUT ) {
      goto again;
    }
  }

  return 0;
}


static void
lock_write_end( enum lock_section section ) {
  struct thread_info *thread = get_thread_info();
  assert( thread != NULL );

  if ( thread->attr( incremented_read, section ) != lck_grp[ section ].writer_waiting ) {
    trema_abort();
  }
  lck_grp[ section ].read_count &= ~( lck_grp[ section ].writer_waiting );
  pthread_mutex_unlock( &lck_grp[ section ].mutex );
  thread->attr( incremented_read, section ) = 0;
  pthread_mutex_lock( &lck_grp[ section ].rw_mutex ) ;
  {
    pthread_cond_signal( &lck_grp [ section ].read_cond );
  }
  pthread_mutex_unlock( &lck_grp[ section ].rw_mutex ) ;
}


void 
add_thread( void ) {
  struct thread_info *thread = get_thread_info();

  if ( thread != NULL ) {
    error( "add_thread has been called twice for thread id %ld", thread->thread_id );
    return;
  }
  thread = ( struct thread_info * ) xmalloc( sizeof( *thread ) );
  thread->thread_id = current_thread();
  memset( &thread->sections, 0, sizeof( struct section ) * MAX_SECTIONS );
  global_lock();
  ALLOC_GROW( thread_list.threads, thread_list.threads_nr + 1, thread_list.threads_alloc );
  thread_list.threads[ thread_list.threads_nr++ ] = thread;
  global_unlock();
}


#define OBJ_READ_BEGIN( name ) \
void \
name##_read_begin( void ) { \
  return lock_read_begin( name##_section ); \
}


OBJ_READ_BEGIN( event )
OBJ_READ_BEGIN( timer )


#define OBJ_READ_END( name ) \
void \
name##_read_end( void ) { \
  return lock_read_end( name##_section ); \
}


OBJ_READ_END( event )
OBJ_READ_END( timer )


#define OBJ_WRITE_BEGIN( name ) \
int \
name##_write_begin( void ) { \
  return lock_write_begin( name##_section ); \
}


OBJ_WRITE_BEGIN( event )
OBJ_WRITE_BEGIN( timer )


#define OBJ_WRITE_END( name ) \
void \
name##_write_end( void ) { \
  return lock_write_end( name##_section ); \
}


OBJ_WRITE_END( event )
OBJ_WRITE_END( timer )


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
