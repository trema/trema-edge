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


#include "packet_buffer.h"


packet_buffers *
create_packet_buffers( const unsigned int max_length, const size_t mtu ) {
  assert( max_length > 0 );
  assert( mtu > 0 || mtu <= UINT16_MAX );

  packet_buffers *buffers = xmalloc( sizeof( packet_buffers ) );
  memset( buffers, 0, sizeof( packet_buffers ) );

  buffers->max_length = max_length;
  buffers->mtu = mtu;
  buffers->buffers = create_message_queue();
  init_mutex( &buffers->buffers_mutex );
  buffers->free_buffers = create_message_queue();
  init_mutex( &buffers->free_buffers_mutex );
  for ( unsigned int i = 0; i < max_length; i++ ) {
    enqueue_message( buffers->free_buffers, alloc_buffer_with_length( buffers->mtu ) );
  }

  return buffers;
}


void
delete_packet_buffers( packet_buffers *buffers ) {
  assert( buffers != NULL );
  assert( buffers->buffers != NULL );
  assert( buffers->free_buffers != NULL );

  delete_message_queue( buffers->buffers );
  finalize_mutex( &buffers->buffers_mutex );
  delete_message_queue( buffers->free_buffers );
  finalize_mutex( &buffers->free_buffers_mutex );
  xfree( buffers );
}


buffer *
get_buffer_from_free_buffers( packet_buffers *buffers ) {
  assert( buffers != NULL );
  assert( buffers->free_buffers != NULL );

  buffer *ret = NULL;
  if ( lock_mutex( &buffers->free_buffers_mutex ) ) {
    ret = dequeue_message( buffers->free_buffers );
    unlock_mutex( &buffers->free_buffers_mutex);
  }
  return ret;
}


void
add_buffer_to_free_buffers( packet_buffers *buffers, buffer *buf ) {
  assert( buffers != NULL );
  assert( buffers->free_buffers != NULL );
  assert( buf != NULL );

  if ( buf->user_data != NULL ) {
    if ( buf->user_data_free_function != NULL ) {
      ( buf->user_data_free_function )( buf );
    }
    else {
      xfree( buf->user_data ); // FIXME: this may not be safe.
    }
    buf->user_data = NULL;
  }

  reset_buffer( buf );
  
  if ( lock_mutex( &buffers->free_buffers_mutex ) ) {
    enqueue_message( buffers->free_buffers, buf );
    unlock_mutex( &buffers->free_buffers_mutex );
  }
}


buffer *
peek_packet_buffer( packet_buffers *buffers ) {
  assert( buffers != NULL );
  assert( buffers->buffers != NULL );

  return peek_message( buffers->buffers );
}


buffer *
dequeue_packet_buffer( packet_buffers *buffers ) {
  assert( buffers != NULL );
  assert( buffers->buffers != NULL );

  buffer *ret = NULL;
  if ( lock_mutex( &buffers->buffers_mutex ) ) {
    ret = dequeue_message( buffers->buffers );
    unlock_mutex( &buffers->buffers_mutex );
  }
  return ret;
}


void
enqueue_packet_buffer( packet_buffers *buffers, buffer *buf ) {
  assert( buffers != NULL );
  assert( buffers->buffers != NULL );

  if ( lock_mutex( &buffers->buffers_mutex ) ) {
    enqueue_message( buffers->buffers, buf );
    unlock_mutex( &buffers->buffers_mutex );
  }
}


unsigned int
get_packet_buffers_length( packet_buffers *buffers ) {
  assert( buffers != NULL );
  assert( buffers->buffers != NULL );

  return buffers->buffers->length;
}


unsigned int
get_max_packet_buffers_length( packet_buffers *buffers ) {
  assert( buffers != NULL );

  return buffers->max_length;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
