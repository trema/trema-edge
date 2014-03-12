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


#ifndef PROTOCOL_H
#define PROTOCOL_H


#ifdef __cplusplus
extern "C" {
#endif


#define MAX_OUTSTANDING_REQUESTS  16


/*
 * This structure is used to keep track of the number of multipart requests.
 */
struct outstanding_request {
  uint32_t transaction_id;
  uint16_t type;
  uint16_t flags;
};


struct protocol_ctrl {
  struct outstanding_request outstanding_requests[ MAX_OUTSTANDING_REQUESTS ];
  uint32_t nr_requests;
  uint32_t capabilities;
  bool controller_connected;
};


struct protocol {
  struct async thread;
  const struct switch_arguments *args;
  message_queue *input_queue;
  uint64_t send_count;
  void *data;
  int own_efd;
  int peer_efd;
  struct protocol_ctrl ctrl;
};


pthread_t start_async_protocol( struct switch_arguments *args );
void wakeup_datapath( struct protocol *protocol );

struct protocol* get_protocol();
void handle_datapath_packet( buffer *packet, struct protocol *protocol );


#ifdef __cplusplus
}
#endif


#endif // PROTOCOL_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
