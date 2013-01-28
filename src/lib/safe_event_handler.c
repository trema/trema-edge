/*
 * Copyright (C) 2008-2013 NEC Corporation
 * Copyright (C) 2011 axsh Ltd.
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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/time.h>
#include "array_util.h"
#include "async_lock.h"
#include "async_util.h"
#include "log.h"
#include "safe_event_handler.h"
#include "safe_timer.h"
#include "trema_wrapper.h"
#include "wrapper.h"


static struct event_info_list event_list;
GET_OBJ_INFO( event )
DELETE_OBJ_INFO( event )


/*
 * Usually we get an event_info object by calling the get_info().
 * But there is a case (ie packet_out) where the protocol thread calls
 * the datapath thread to send the packet out. If we use the current_thread()
 * to retrieve the event info object we fail hence we match on fd as below.
 */
static struct event_info *
get_event_info_by_fd( int fd ) {
  struct event_info *event = NULL;
  uint32_t events_nr = event_list.events_nr;

  for ( uint32_t i = 0; i < events_nr; i++ ) {
    if ( event_list.events[ i ]->event_fd_set[ fd ] != NULL &&
         event_list.events[ i ]->event_fd_set[ fd ]->fd == fd ) {
      event = event_list.events[ i ];
      break;
    }
  }

  return event;
}


static void
_init_event_handler() {
  struct event_info *event = get_event_info();
  
  if ( event != NULL ) {
    error( "init_event_handler has been called twice for thread id %ld", event->thread_id );
    return;
  }
  event = ( struct event_info * ) xmalloc( sizeof( *event ) );
  event->thread_id = current_thread();
  event->event_last = event->event_list;
  event->event_handler_state = EVENT_HANDLER_INITIALIZED;
  event->external_callback = NULL;

  memset( event->event_list, 0, sizeof( struct event_fd ) * FD_SETSIZE );
  memset( event->event_fd_set, 0, sizeof( struct event_fd * ) * FD_SETSIZE );

  FD_ZERO( &event->event_read_set );
  FD_ZERO( &event->event_write_set );

  event_write_begin();
  ALLOC_GROW( event_list.events, event_list.events_nr + 1, event_list.events_alloc ); 
  event_list.events[ event_list.events_nr++ ] = event;
  event_write_end();

}
void ( *init_event_handler_safe )() = _init_event_handler;


static void
_finalize_event_handler() {
  event_read_begin();
  struct event_info *event = get_event_info();
  event_read_end();
  assert( event != NULL );

  if ( event->event_last != event->event_list ) {
    warn( "Event Handler finalized with %i fd event handlers still active. (%i, ...)",
          ( event->event_last - event->event_list ), ( event->event_last > event->event_list ? event->event_list->fd : -1 ) );
    return;
  }
  event_write_begin();
  delete_event_info( event );
  event_write_end();
}
void ( *finalize_event_handler_safe )() = _finalize_event_handler;


static bool
_run_event_handler_once( int timeout_usec ) {
  event_read_begin();
  struct event_info *event = get_event_info();
  event_read_end();
  assert( event != NULL );

  if ( event->external_callback != NULL ) {
    external_callback_t callback = event->external_callback;
    event->external_callback = NULL;

    callback();
  }
  memcpy( &event->current_read_set, &event->event_read_set, sizeof( fd_set ) );
  memcpy( &event->current_write_set, &event->event_write_set, sizeof( fd_set ) );

  struct timeval timeout;
  timeout.tv_sec = timeout_usec / 1000000;
  timeout.tv_usec = timeout_usec % 1000000;
  int set_count = select( event->fd_set_size, &event->current_read_set, &event->current_write_set, NULL, &timeout );

  if ( set_count == -1 ) {
    if ( errno == EINTR ) {
      return true;
    }
    error( "Failed to select ( errno = %s [%d] ).", strerror( errno ), errno );
    return false;

  }
  else if ( set_count == 0 ) {
    // timed out
    return true;
  }

  struct event_fd *event_itr = event->event_list;

  while ( event_itr < event->event_last ) {
    struct event_fd current_event = *event_itr;

    if ( FD_ISSET( current_event.fd, &event->current_write_set ) ) {
      current_event.write_callback( current_event.fd, current_event.write_data );
    }

    if ( FD_ISSET( current_event.fd, &event->current_read_set ) ) {
      current_event.read_callback( current_event.fd, current_event.read_data );
    }

    // In the rare cases the current fd is closed, a new one is opened
    // with the same fd and is put in the same location we can just
    // wait for the next select call.
    if ( current_event.fd == event_itr->fd ) {
      event_itr = event_itr + 1;
    }
    else {
      debug( "run_event_handler_once: event fd is changed ( current = %d, new = %d )", current_event.fd, event_itr->fd ) ;
    }
  }

  return true;
}
bool ( *run_event_handler_once_safe )( int ) = _run_event_handler_once;


static bool
_start_event_handler() {
  debug( "Starting event handler." );

  event_read_begin();
  struct event_info *event = get_event_info();
  event_read_end();
  assert( event != NULL );

  event->event_handler_state &= ~EVENT_HANDLER_STOP;
  event->event_handler_state |= EVENT_HANDLER_RUNNING;

  int timeout_usec = 0;
  while ( !( event->event_handler_state & EVENT_HANDLER_STOP ) ) {
    execute_timer_events_safe( &timeout_usec );

    if ( !_run_event_handler_once( timeout_usec ) ) {
      error( "Failed to run main loop." );
      return false;
    }
  }

  event->event_handler_state &= ~EVENT_HANDLER_RUNNING;

  debug( "Event handler terminated." );

  return true;
}
bool ( *start_event_handler_safe )() = _start_event_handler;


static void
_stop_event_handler() {
  event_read_begin();
  struct event_info *event = get_event_info();
  event_read_end();
  assert( event != NULL );

  debug( "Terminating event handler." );
  event->event_handler_state |= EVENT_HANDLER_STOP;
}
void ( *stop_event_handler_safe )() = _stop_event_handler;


static void
_set_fd_handler( int fd,
                 event_fd_callback read_callback, void *read_data,
                 event_fd_callback write_callback, void *write_data ) {
  debug( "Adding event handler for fd %i, %p, %p.", fd, read_callback, write_callback );

  event_read_begin();
  struct event_info *event = get_event_info();
  event_read_end();
  assert( event != NULL );

  // Currently just issue critical warnings instead of killing the
  // program."
  if ( event->event_fd_set[ fd ] != NULL ) {
    error( "Tried to add an already active fd event handler." );
    return;
  }

  if ( ( fd < 0 ) || ( fd >= FD_SETSIZE ) ) {
    error( "Tried to add an invalid fd." );
    return;
  }

  if ( event->event_last >= event->event_list + FD_SETSIZE ) {
    error( "Event handler list in invalid state." );
    return;
  }

  event->event_last->fd = fd;
  event->event_last->read_callback = read_callback;
  event->event_last->write_callback = write_callback;
  event->event_last->read_data = read_data;
  event->event_last->write_data = write_data;

  event->event_fd_set[ fd ] = event->event_last++;

  if ( fd >= event->fd_set_size ) {
    event->fd_set_size = fd + 1;
  }
}
void ( *set_fd_handler_safe )( int fd, event_fd_callback read_callback, void *read_data, event_fd_callback write_callback, void *write_data ) = _set_fd_handler;


static void
_delete_fd_handler( int fd ) {
  debug( "Deleting event handler for fd %i.", fd );
  event_read_begin();
  struct event_info *event_info = get_event_info();
  event_read_end();
  assert( event_info != NULL );

  struct event_fd *event = event_info->event_list;

  while ( event != event_info->event_last && event->fd != fd ) {
    event++;
  }

  if ( ( event >= event_info->event_last ) || ( event_info->event_fd_set[ fd ] ) == NULL ) {
    error( "Tried to delete an inactive fd event handler." );
    return;
  }

  if ( FD_ISSET( fd, &event_info->event_read_set ) ) {
    error( "Tried to delete an fd event handler with active read notification." );
    FD_CLR( fd, &event_info->event_read_set );
  }

  if ( FD_ISSET( fd, &event_info->event_write_set ) ) {
    error( "Tried to delete an fd event handler with active write notification." );
    FD_CLR( fd, &event_info->event_write_set );
  }

  FD_CLR( fd, &event_info->current_read_set );
  FD_CLR( fd, &event_info->current_write_set );

  event_info->event_fd_set[ fd ] = NULL;

  if ( event != --event_info->event_last ) {
    memcpy( event, event_info->event_last, sizeof( struct event_fd ) );
    event_info->event_fd_set[ event->fd ] = event;
  }

  memset( event_info->event_last, 0, sizeof( struct event_fd ) );
  event_info->event_last->fd = -1;

  if ( fd == ( event_info->fd_set_size  - 1 ) ) {
    int i;
    for ( i = ( event_info->fd_set_size - 2 ); i >= 0; --i ) {
      if ( event_info->event_fd_set[ i ] != NULL ) {
        break;
      }
    }
    event_info->fd_set_size = i + 1;
  }
}
void ( *delete_fd_handler_safe )( int fd ) = _delete_fd_handler;


static void
_set_readable( int fd, bool state ) {
  if ( ( fd < 0 ) || ( fd >= FD_SETSIZE ) ) {
    error( "Invalid fd to set_readable call; %i.", fd );
    return;
  }
  event_read_begin();
  struct event_info *event = get_event_info();
  event_read_end();
  assert( event != NULL );

  if ( ( event->event_fd_set[ fd ] == NULL ) || ( event->event_fd_set[ fd ]->read_callback == NULL ) ) {
    error( "Found fd in invalid state in set_readable; %i, %p.", fd, event->event_fd_set[ fd ] );
    return;
  }

  if ( state ) {
    FD_SET( fd, &event->event_read_set );
  }
  else {
    FD_CLR( fd, &event->event_read_set );
    FD_CLR( fd, &event->current_read_set );
  }
}
void ( *set_readable_safe )( int fd, bool state ) = _set_readable;


static void
_set_writable( int fd, bool state ) {
  if ( ( fd < 0 ) || ( fd >= FD_SETSIZE ) ) {
    error( "Invalid fd to notify_writeable_event call; %i.", fd );
    return;
  }

  event_read_begin();
  struct event_info *event = get_event_info();
  if ( event->event_fd_set[ fd ] == NULL || event->event_fd_set[ fd ]->fd != fd ) {
    event = get_event_info_by_fd( fd );
  }
  event_read_end();
  assert( event != NULL );

  if ( ( event->event_fd_set[ fd ] == NULL ) || ( event->event_fd_set[ fd ]->write_callback == NULL ) ) {
    error( "Found fd in invalid state in notify_writeable_event; %i, %p.", fd, event->event_fd_set[ fd ] );
    return;
  }

  if ( state ) {
    FD_SET( fd, &event->event_write_set );
  }
  else {
    FD_CLR( fd, &event->event_write_set );
    FD_CLR( fd, &event->current_write_set );
  }
}
void ( *set_writable_safe )( int fd, bool state ) = _set_writable;


static bool
_readable( int fd ) {
  event_read_begin();
  struct event_info *event = get_event_info();
  event_read_end();
  assert( event != NULL );
  
  return FD_ISSET( fd, &event->event_read_set );
}
bool ( *readable_safe )( int fd ) = _readable;


static bool
_writable( int fd ) {
  event_read_begin();
  struct event_info *event = get_event_info();
  event_read_end();
  assert( event != NULL );

  return FD_ISSET( fd, &event->event_write_set );
}
bool ( *writable_safe )( int fd ) = _writable;


static bool
_set_external_callback( external_callback_t callback ) {
  event_read_begin();
  struct event_info *event = get_event_info();
  event_read_end();
  assert( event != NULL );

  // one external callback per thread
  if ( event->external_callback != NULL ) {
    return false;
  }

  event->external_callback = callback;

  return true;
}
bool ( *set_external_callback_safe )( external_callback_t callback ) = _set_external_callback;


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
