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


#ifndef DATAPATH_H
#define DATAPATH_H


#include "trema.h"


#ifdef __cplusplus
extern "C" {
#endif


#define NUM_CONTROLLER_BUFFER  256
#define MAX_SEND_QUEUE  512
#define MAX_RECV_QUEUE  512
#define DATAPATH_ID  1


struct datapath {
  struct async thread;
  const struct switch_arguments *args; 
  message_queue *peer_queue;
  uint64_t send_count;
  void *data;
  int own_efd;
  int peer_efd;
  int running;
};


struct datapath_ctrl {
  int status;
};


pthread_t start_async_datapath( struct switch_arguments *args );


#ifdef __cplusplus
}
#endif


#endif // DATAPATH_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
