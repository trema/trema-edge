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


#ifndef PACKET_BUFFER_H
#define PACKET_BUFFER_H


#include "ofdp_common.h"


typedef struct {
  unsigned int max_length;
  size_t mtu;
  message_queue *buffers;
  message_queue *free_buffers;
} packet_buffers;


packet_buffers *create_packet_buffers( const unsigned int max_length, const size_t mtu );
void delete_packet_buffers( packet_buffers *buffers );
buffer *get_buffer_from_free_buffers( packet_buffers *buffers );
#define get_free_packet_buffer get_buffer_from_free_buffers
void add_buffer_to_free_buffers( packet_buffers *buffers, buffer *buf );
#define mark_packet_buffer_as_used add_buffer_to_free_buffers
buffer *peek_packet_buffer( packet_buffers *buffers );
buffer *dequeue_packet_buffer( packet_buffers *buffers );
void enqueue_packet_buffer( packet_buffers *buffers, buffer *buf );
unsigned int get_packet_buffers_length( packet_buffers *buffers );
unsigned int get_max_packet_buffers_length( packet_buffers *buffers );


#endif // PACKET_BUFFER_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
