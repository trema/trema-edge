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


#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "parse-options.h"


static char const * const switch_usage[] = {
  "  -l --logging_level=level                   set the logging level",
  "  -d --daemonize                             run as a daemon",
  "  -i --datapath_id=datapath_id               set datapath_id to a decimal number",
  "  -m --max_flow_entries=number               set datapath's maximum no. of flow entries in a table",
  "  -c --server_ip=ipv4_addr                   set server's ipv4 address to connect to",
  "  -p --server_port=port                      set server's port to connect to",
  "  -e --switch_ports=<interface/logical port> one or more comma separated list of switch ports",
  "  -h --help                                  display usage and exit",
  NULL
};


static void
print_usage( const struct switch_arguments *args, int exit_code ) {
  fprintf( stderr, "Usage: %s [options] \n", args->progname );
  
  int i = 0;
  while ( switch_usage[ i ] ) {
    fprintf( stderr, "%s\n", switch_usage[ i++ ] );
  }
  exit( exit_code );
}


static void
set_default_opts( struct switch_arguments *args, const struct option long_options[] ) {
  args->progname = "switch",
  args->log_type = LOGGING_TYPE_UNSET,
  args->log_level = "info",
  args->datapath_ports = "",
  args->datapath_id = 1,
  args->server_ip = 0x7f000001,
  args->server_port = 6653,
  args->max_flow_entries = UINT8_MAX;
  args->run_as_daemon = false,
  args->options = long_options;
}


void 
_parse_options( struct switch_arguments *args, int argc, char **argv ) {
  static struct option long_options[] = {
    { "logging_type", optional_argument, 0, 't' },
    { "logging_level", required_argument, 0, 'l' },
    { "daemonize", no_argument, 0, 'd' },
    { "datapath_id", required_argument, 0, 'i' },
    { "max_flow_entries", required_argument, 0, 'm' },
    { "server_ip", required_argument, 0, 'c' },
    { "server_port", required_argument, 0, 'p' },
    { "switch_ports", optional_argument, 0, 'e' },
    { "help", no_argument, 0, 'h' },
    { 0, 0, 0, 0 },
  };
  static const char *short_options = "t:l:di:c:p:e:h";
  set_default_opts( args, long_options );
  
  int c, index = 0;
  optind = 0;
  while ( 1 ) {
    c = getopt_long( argc, argv, short_options, args->options, &index );
    if ( c == -1 ) {
      break;
    }
    switch ( c ) {
      case 'h':
        print_usage( args, 0 );
      break;
      case 't':
        args->log_type = 0;
        if ( optarg ) {
          char *save_ptr = NULL;
          char *p = strtok_r( optarg, ",", &save_ptr );
          while ( p ) {
            if ( strcasecmp( p, "file" ) == 0 ) {
              args->log_type |= LOGGING_TYPE_FILE;
            } else if ( strcasecmp( p, "syslog" ) == 0 ) {
              args->log_type |= LOGGING_TYPE_SYSLOG;
            } else if ( strcasecmp( p, "stdout" ) == 0 ) {
              args->log_type |= LOGGING_TYPE_STDOUT;
            }
            p = strtok_r( NULL, ".", &save_ptr );
          }
        }
      break;
      case 'l':
        if ( optarg ) {
          args->log_level = optarg;
          set_logging_level( args->log_level );
        }
      break;
      case 'd':
        args->run_as_daemon = true;
      break;
      case 'i':
        if ( optarg ) {
          string_to_datapath_id( optarg, &args->datapath_id );
        }
      break;
      case 'm':
        if ( optarg ) {
          args->max_flow_entries = ( uint16_t ) atoi( optarg );
        }
      break;
      case 'c':
        if ( optarg ) {
            char *save_ptr = NULL;
            uint32_t temp_addr = 0;
            char *p = strtok_r( optarg, ".", &save_ptr );
            while ( p ) {
              temp_addr = ( temp_addr << 8 ) | ( uint32_t ) atoi( p );
              p = strtok_r( NULL, ".", &save_ptr ); 
            }
            if ( temp_addr ) {
              args->server_ip = temp_addr;
            }
        }
      break;
      case 'p':
        if ( optarg ) {
          args->server_port = ( uint16_t ) atoi( optarg );
        }
      break;
      case 'e':
        if ( optarg ) {
          args->datapath_ports = optarg;
        }
      break;
      default:
      break;
    }
  }
}
void ( *parse_options )( struct switch_arguments *args, int argc, char **argv ) = _parse_options;


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
