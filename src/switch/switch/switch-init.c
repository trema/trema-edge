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
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "trema.h"
#include "daemon.h"
#include "parse-options.h"


static const char *
get_switch_home( void ) {
  return getenv( "TREMA_HOME" );
}


char *
get_switch_tmp( void ) {
  const char *tmp = get_switch_home();
  char path[ PATH_MAX ];

  if ( tmp == NULL ) {
    tmp = "/tmp";
  }
  snprintf( path, PATH_MAX, "%s/tmp", tmp );
  return xstrdup( path );
}


char *
get_switch_pid_dir( void ) {
  char path[ PATH_MAX ];

  char *switch_tmp = get_switch_tmp();
  sprintf( path, "%s/pid", switch_tmp );
  xfree( switch_tmp );
  return xstrdup( path );
}


static char *
get_switch_log( void ) {
  char path[ PATH_MAX ];

  char *switch_tmp = get_switch_tmp();
  sprintf( path, "%s/log", switch_tmp );
  xfree( switch_tmp );
  return xstrdup( path );
}


static void
ignore_sigpipe( void ) {
  sigset_t signal_mask;

  sigemptyset( &signal_mask );
  sigaddset( &signal_mask, SIGPIPE );
  pthread_sigmask( SIG_BLOCK, &signal_mask, NULL );
}


struct switch_arguments *
init_parse_args( int argc, char **argv ) {
  struct switch_arguments *args = xmalloc( sizeof( struct switch_arguments ) );

  parse_options( args, argc, argv );

  char *switch_log = get_switch_log();
  logging_type log_output_type = 0;

  if ( args->log_type == LOGGING_TYPE_UNSET ) {
    log_output_type = LOGGING_TYPE_FILE;
    if ( args->run_as_daemon == false ) {
      log_output_type |= LOGGING_TYPE_STDOUT;
    }
  } else {
    log_output_type = args->log_type;
  }
  if ( args->run_as_daemon == true ) {
    log_output_type &= ~LOGGING_TYPE_STDOUT;
  }

  char name[ PATH_MAX ];
  snprintf( name, PATH_MAX, "%s.%#" PRIx64, args->progname, args->datapath_id );
  init_log( name, switch_log, log_output_type );
  xfree( switch_log );

  int efd[ 2 ];
  uint32_t i;
  for ( i = 0; i < sizeof( efd ) / sizeof( efd[ 0 ] ); i++ ) {
    efd[ i ] = create_event_fd();
    if ( efd[ i ] == -1 ) {
      error( "failed to create_event_fd %d", errno );
      xfree( args );
      return NULL;
    }
  }
  memcpy( args->efd, &efd, sizeof( efd ) );
  args->to_protocol_queue = create_message_queue();
  assert( args->to_protocol_queue != NULL );

  ignore_sigpipe();
  if ( args->run_as_daemon == true ) {
    daemonize( get_switch_home() );
  }

  char *switch_pid_dir = get_switch_pid_dir();
  write_pid( switch_pid_dir, name );
  char cmd[ PATH_MAX ];
  /*
   * change the pid file permissions to allow deletion since switch is started
   * as sudo. This would become obsolete if sudo is removed.
   */
  snprintf( cmd, PATH_MAX, "chmod 0666 %s/%s.pid", switch_pid_dir, name );
  system( cmd );
  xfree( switch_pid_dir );

  return args;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
