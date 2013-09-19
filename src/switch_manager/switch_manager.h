/*
 * OpenFlow Switch Listener
 *
 * Author: Kazushi SUGYO
 *
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


#ifndef SWITCH_LISTENER_H
#define SWITCH_LISTENER_H


#include <sys/types.h>


extern const char SWITCH_MANAGER_NAME_OPTION[];
extern const uint SWITCH_MANAGER_NAME_OPTION_STR_LEN;
extern const char SWITCH_MANAGER_SOCKET_OPTION[];
extern const uint SWITCH_MANAGER_SOCKET_OPTION_STR_LEN;
extern const char SWITCH_MANAGER_DAEMONIZE_OPTION[];
extern const uint SWITCH_MANAGER_SOCKET_STR_LEN;
extern const char SWITCH_MANAGER_COMMAND_PREFIX[];
extern const uint SWITCH_MANAGER_COMMAND_PREFIX_STR_LEN;
extern const char SWITCH_MANAGER_PREFIX[];
extern const uint SWITCH_MANAGER_PREFIX_STR_LEN;
extern const uint SWITCH_MANAGER_ADDR_STR_LEN;

extern const char SWITCH_MANAGER_PATH[];
extern const char SWITCH_MANAGER_STATE_PREFIX[];


struct listener_info {
  const char *switch_daemon;
  int switch_daemon_argc;
  char **switch_daemon_argv;
  uint16_t listen_port;
  int listen_fd;
};


#endif // SWITCH_LISTENER_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
