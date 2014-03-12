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


#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "trema.h"
#include "daemon.h"
#include "datapath.h"
#include "parse-options.h"
#include "protocol.h"
#include "switch-init.h"
#include "switch.h"


static struct switch_arguments *args;


static struct switch_arguments *
init_switch( int argc, char **argv ) {
  char *switch_tmp = get_switch_tmp();
  init_messenger( switch_tmp );
  xfree( switch_tmp );
  return init_parse_args( argc, argv );
}


static pthread_t threads[ 2 ];

static void
run_switch( struct switch_arguments *args ) {
  int i;

  threads[ 0 ] = start_async_protocol( args );
  threads[ 1 ] = start_async_datapath( args );
  for ( i = 0; i < 2; i++ ) {
    if ( pthread_join( threads[ i ], NULL ) ) {
      error( "Failed to join a thread %d", threads[ i ] );
      break;
    }
  }
}


bool
is_protocol( ) {
  if ( pthread_self() == threads[ 0 ] ) {
    return true;
  }
  return false;
}


bool
is_datapath( ) {
  if ( pthread_self() == threads[ 1 ] ) {
    return true;
  }
  return false;
}


static void
stop_switch( struct switch_arguments *args ) {
  finalize_openflow_switch_interface();
  if ( args->to_protocol_queue != NULL ) {
    delete_message_queue( args->to_protocol_queue );
  }
}


static void
set_signal_mask() {
  sigset_t signals;
  sigemptyset( &signals );
  sigaddset( &signals, SIGPIPE );
  sigaddset( &signals, SIGUSR1 );
  sigaddset( &signals, SIGUSR2 );
  sigprocmask( SIG_BLOCK, &signals, 0 );
}


/*
 * Trap the SIGINT delete the switch.datapath.pid file and exit.
 */
static void
sigint_handler( int signum ) {
  if ( args != NULL ) {
    char *switch_pid_dir = get_switch_pid_dir();
    char name[ PATH_MAX ];
    snprintf( name, PATH_MAX, "%s.%#" PRIx64, args->progname, args->datapath_id );
    unlink_pid( switch_pid_dir, name );
  }
  exit( signum );
}


int
main( int argc, char **argv ) {
  signal( SIGINT, sigint_handler );
  signal( SIGTERM, sigint_handler );
  set_signal_mask();

  if ( ( args = init_switch( argc, argv ) ) != NULL ) {
    run_switch( args );
    stop_switch( args );
  }
  return EXIT_SUCCESS;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
