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


#ifndef SAFE_EVENT_HANDLER_H
#define SAFE_EVENT_HANDLER_H


#ifdef __cplusplus
extern "C" {
#endif

  
#include <sys/types.h>
#include "bool.h"
#include "event_handler.h"


enum {
  EVENT_HANDLER_INITIALIZED = 1 << 0,
  EVENT_HANDLER_RUNNING = 1 << 1,
  EVENT_HANDLER_STOP = 1 << 2,
  EVENT_HANDLER_FINALIZED = 1 << 3,
};


struct event_fd {
  int fd;
  event_fd_callback read_callback;
  event_fd_callback write_callback;
  void *read_data;
  void *write_data;
};

struct event_info {
  struct event_fd event_list[ FD_SETSIZE ];
  struct event_fd *event_last;
  struct event_fd *event_fd_set[ FD_SETSIZE ];
  external_callback_t external_callback;
  fd_set event_read_set; 
  fd_set event_write_set;
  fd_set current_read_set;
  fd_set current_write_set;
  pthread_t thread_id;
  pthread_mutex_t mutex;
  int event_handler_state; 
  int fd_set_size;
};

struct event_info_list {
  struct event_info **events;
  uint32_t events_nr;
  uint32_t events_alloc;
};


void ( *init_event_handler_safe )();
void ( *finalize_event_handler_safe )();
bool ( *start_event_handler_safe )();
void ( *stop_event_handler_safe )();
void ( *set_readable_safe )( int fd, bool state );
void ( *set_writable_safe )( int fd, bool state );
void ( *set_fd_handler_safe )( int fd, event_fd_callback read_callback, void *read_data, event_fd_callback write_callback, void *write_data );
bool ( *set_external_callback_safe )( external_callback_t callback );
void ( *delete_fd_handler_safe )( int fd );
bool ( *readable_safe )( int fd );
bool ( *writable_safe )( int fd );


#ifdef __cplusplus
}
#endif


#endif // SAFE_EVENT_HANDLER_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
