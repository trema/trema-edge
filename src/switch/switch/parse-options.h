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


#ifndef PARSE_OPTIONS_H
#define PARSE_OPTIONS_H


#ifdef __cplusplus
extern "C" {
#endif


#include "trema.h"


struct switch_arguments {
  const char *progname;
  logging_type log_type;
  const char *log_level;
  const struct option *options;

  const char *datapath_ports;
  uint64_t datapath_id;
  int efd[ 2 ]; // event descriptors associated with the to_protocol_queue
  message_queue *to_protocol_queue;
  uint32_t server_ip;
  bool run_as_daemon;
  uint16_t server_port;
  uint16_t max_flow_entries;
}; 


void ( *parse_options )( struct switch_arguments *args, int argc, char **argv );


#ifdef __cplusplus
}
#endif


#endif // PARSE_OPTIONS_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
