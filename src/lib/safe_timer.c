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
#include <limits.h>
#include <stdbool.h>
#include <sys/time.h>
#include <time.h>
#include "array_util.h"
#include "async_lock.h"
#include "async_util.h"
#include "log.h"
#include "safe_timer.h"
#include "wrapper.h"


static struct timer_info_list timer_list;
GET_OBJ_INFO( timer )
DELETE_OBJ_INFO( timer )


static bool
_init_timer() {
  struct timer_info *timer = get_timer_info(); 
  if ( timer != NULL ) {
    error( "init_timer has been called twice for thread id %ld", timer->thread_id ); 
    return false;
  }

  timer = ( struct timer_info * ) xmalloc( sizeof( *timer ) );
  timer->thread_id = current_thread();
  timer->timer_callbacks = create_dlist();
  timer_write_begin();
  ALLOC_GROW( timer_list.timers, timer_list.timers_nr + 1, timer_list.timers_alloc );
  timer_list.timers[ timer_list.timers_nr++ ] = timer;
  timer_write_end();

  debug( "Initializing timer callbacks ( timer_callbacks = %p ).", timer->timer_callbacks );

  return true;
}
bool ( *init_timer_safe )( void ) = _init_timer;


static bool
_finalize_timer() {
  timer_read_begin();
  struct timer_info *timer = get_timer_info();
  timer_read_end();
  assert( timer != NULL );

  debug( "Deleting timer callbacks ( timer_callbacks = %p ).", timer->timer_callbacks );

  if ( timer->timer_callbacks != NULL ) {
    dlist_element *sentinel = timer->timer_callbacks;
    for ( dlist_element *e = sentinel->next; e != sentinel; e = e->next ) {
      xfree( e->data );
    }
    delete_dlist( timer->timer_callbacks );
    timer->timer_callbacks = NULL;
  }
  else {
    error( "All timer callbacks are already deleted or not created yet." );
  }

  timer_write_begin();
  delete_timer_info( timer );
  timer_write_end();

  return true;
}
bool ( *finalize_timer_safe )( void ) = _finalize_timer;


static void
on_timer( timer_callback_info *callback, struct timespec *now ) {
  assert( callback != NULL );
  assert( callback->function != NULL );

  debug( "Executing a timer event ( function = %p, expires_at = %u.%09u, interval = %u.%09u, user_data = %p ).",
         callback->function, callback->expires_at.tv_sec, callback->expires_at.tv_nsec,
         callback->interval.tv_sec, callback->interval.tv_nsec, callback->user_data );

  if ( VALID_TIMESPEC( &callback->expires_at ) ) {
    callback->function( callback->user_data );
    if ( VALID_TIMESPEC( &callback->interval ) ) {
      ADD_TIMESPEC( &callback->expires_at, &callback->interval, &callback->expires_at );
      if ( TIMESPEC_LESS_THEN( &callback->expires_at, now ) ) {
        callback->expires_at.tv_sec = now->tv_sec;
        callback->expires_at.tv_nsec = now->tv_nsec;
      }
    }
    else {
      callback->expires_at.tv_sec = 0;
      callback->expires_at.tv_nsec = 0;
      callback->function = NULL;
    }
    debug( "Set expires_at value to %u.%09u.", callback->expires_at.tv_sec, callback->expires_at.tv_nsec );
  }
  else {
    error( "Invalid expires_at value." );
  }
}


static void
insert_timer_callback( struct timer_info *timer, timer_callback_info *new_cb ) {
  assert( timer != NULL );
  assert( timer->timer_callbacks != NULL );

  // note: new_cb is likely to be the last element
  dlist_element *sentinel = timer->timer_callbacks;
  for ( dlist_element *element = sentinel->prev; element != sentinel; element = element->prev ) {
    timer_callback_info *cb = element->data;
    if ( TIMESPEC_LESS_THEN( &cb->expires_at, &new_cb->expires_at ) ) {
      insert_after_dlist( sentinel, element, new_cb );
      return;
    }
  }
  insert_after_dlist( sentinel, sentinel, new_cb );
}


static void
_execute_timer_events( int *next_timeout_usec ) {
  assert( next_timeout_usec != NULL );

  timer_read_begin();
  struct timer_info *timer = get_timer_info();
  timer_read_end();
  assert( timer != NULL );

  debug( "Executing timer events ( timer_callbacks = %p ).", timer->timer_callbacks );

  struct timespec now = { 0, 0 };
  assert( clock_gettime( CLOCK_MONOTONIC, &now ) == 0 );
  assert( timer->timer_callbacks != NULL );

  dlist_element *element_next, *sentinel = timer->timer_callbacks;
  for ( dlist_element *element = sentinel->next; element != sentinel; element = element_next ) {
    element_next = element->next;
    timer_callback_info *callback = element->data;
    if ( callback->function != NULL ) {
      if ( TIMESPEC_LESS_THEN( &now, &callback->expires_at ) ) {
        break;
      }
      on_timer( callback, &now );
    }
    delete_dlist_element( sentinel, element );
    if ( callback->function == NULL ) {
      xfree( callback );
    }
    else { // callback interval is set
      insert_timer_callback( timer, callback );
    }
  }

  struct timespec max_timeout = { ( INT_MAX / 1000000 ), 0 };
  struct timespec min_timeout = { 0, 0 };
  if ( timer->timer_callbacks->next == timer->timer_callbacks ) {
    TIMESPEC_TO_MICROSECONDS( &max_timeout, next_timeout_usec );
  }
  else {
    timer_callback_info *callback = timer->timer_callbacks->next->data;
    if ( TIMESPEC_LESS_THEN( &callback->expires_at, &now ) ) {
      TIMESPEC_TO_MICROSECONDS( &min_timeout, next_timeout_usec );
    }
    else {
      struct timespec timeout = { 0, 0 };
      SUB_TIMESPEC( &callback->expires_at, &now, &timeout );
      if ( TIMESPEC_LESS_THEN( &timeout, &max_timeout ) ) {
        TIMESPEC_TO_MICROSECONDS( &timeout, next_timeout_usec );
      }
      else {
        TIMESPEC_TO_MICROSECONDS( &max_timeout, next_timeout_usec );
      }
    }
  }
}
void ( *execute_timer_events_safe )( int * ) = _execute_timer_events;


static bool
_add_timer_event_callback( struct itimerspec *interval, timer_callback callback, void *user_data ) {
  assert( interval != NULL );
  assert( callback != NULL );

  timer_read_begin();
  struct timer_info *timer = get_timer_info();
  timer_read_end();
  assert( timer != NULL );

  debug( "Adding a timer event callback ( interval = %u.%09u, initial expiration = %u.%09u, callback = %p, user_data = %p ).",
         interval->it_interval.tv_sec, interval->it_interval.tv_nsec,
         interval->it_value.tv_sec, interval->it_value.tv_nsec, callback, user_data );

  timer_callback_info *cb = xmalloc( sizeof( timer_callback_info ) );
  memset( cb, 0, sizeof( timer_callback_info ) );
  cb->function = callback;
  cb->user_data = user_data;

  struct timespec now = { 0, 0 };
  if ( clock_gettime( CLOCK_MONOTONIC, &now ) != 0 ) {
    error( "Failed to retrieve monotonic time ( %s [%d] ).", strerror( errno ), errno );
    xfree( cb );
    return false;
  }

  cb->interval = interval->it_interval;

  if ( VALID_TIMESPEC( &interval->it_value ) ) {
    ADD_TIMESPEC( &now, &interval->it_value, &cb->expires_at );
  }
  else if ( VALID_TIMESPEC( &interval->it_interval ) ) {
    ADD_TIMESPEC( &now, &interval->it_interval, &cb->expires_at );
  }
  else {
    error( "Timer must not be zero when a timer event is added." );
    xfree( cb );
    return false;
  }

  debug( "Set an initial expiration time to %u.%09u.", now.tv_sec, now.tv_nsec );

  assert( timer->timer_callbacks != NULL );
  insert_timer_callback( timer, cb );

  return true;
}
bool ( *add_timer_event_callback_safe )( struct itimerspec *interval, timer_callback callback, void *user_data ) = _add_timer_event_callback;


static bool
_add_periodic_event_callback( const time_t seconds, timer_callback callback, void *user_data ) {
  assert( callback != NULL );

  debug( "Adding a periodic event callback ( interval = %u, callback = %p, user_data = %p ).",
         seconds, callback, user_data );

  struct itimerspec interval;

  interval.it_value.tv_sec = 0;
  interval.it_value.tv_nsec = 0;
  interval.it_interval.tv_sec = seconds;
  interval.it_interval.tv_nsec = 0;

  return _add_timer_event_callback( &interval, callback, user_data );
}
bool ( *add_periodic_event_callback_safe )( const time_t seconds, timer_callback callback, void *user_data ) = _add_periodic_event_callback;


static bool
_delete_timer_event( timer_callback callback, void *user_data ) {
  assert( callback != NULL );
  timer_read_begin();
  struct timer_info *timer = get_timer_info();
  timer_read_end();

  debug( "Deleting a timer event ( callback = %p, user_data = %p ).", callback, user_data );

  if ( timer->timer_callbacks == NULL ) {
    debug( "All timer callbacks are already deleted or not created yet." );
    return false;
  }

  dlist_element *sentinel = timer->timer_callbacks;
  for ( dlist_element *e = sentinel->next; e != sentinel; e = e->next ) {
    timer_callback_info *cb = e->data;
    if ( cb->function == callback && cb->user_data == user_data ) {
      debug( "Deleting a callback ( callback = %p, user_data = %p ).", callback, user_data );
      cb->function = NULL;
      cb->user_data = NULL;
      cb->expires_at.tv_sec = 0;
      cb->expires_at.tv_nsec = 0;
      cb->interval.tv_sec = 0;
      cb->interval.tv_nsec = 0;
      return true;
    }
  }

  error( "No registered timer event callback found." );

  return false;
}
bool ( *delete_timer_event_safe )( timer_callback callback, void *user_data ) = _delete_timer_event;


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
