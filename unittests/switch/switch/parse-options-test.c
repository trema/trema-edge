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

#include <stdio.h>
#include <string.h>
#include "trema.h"
#include "parse-options.h"
#include "cmockery_trema.h"


static void *
cast_non_const( const void *ptr ) {
  union {
    const void* const_value;
    void *value;
  } ret;
  ret.const_value = ptr;
  return ret.value;
}


static void
create_switch_arguments( void **state ) {
  struct switch_arguments *args = ( struct switch_arguments * ) xmalloc( sizeof( struct switch_arguments ) );
  *state = ( void * )args;
}


static void
destroy_switch_arguments( void **state ) {
  UNUSED( state );
}


static void
test_parse_datapath_long_option( void **state ) {
  struct switch_arguments *args = *state;
  int argc = 3;
  char **argv = xmalloc( sizeof ( char * ) * ( size_t ) ( argc + 1 ) );
  const char *options[] = { "switch", "--datapath_id", "2" }; 
  argv[ 0 ] = cast_non_const( options[ 0 ] );
  argv[ 1 ] = cast_non_const( options[ 1 ] );
  argv[ 2 ] = cast_non_const( options[ 2 ] );
  argv[ 3 ] = NULL;

  parse_options( args, argc, argv );
  assert_int_equal( args->datapath_id, 2 );
}


static void
test_parse_datapath_short_option( void **state ) {
  struct switch_arguments *args = *state;
  int argc = 3;
  char **argv = xmalloc( sizeof ( char * ) * ( size_t ) ( argc + 1 ) );
  const char *options[] = { "switch", "-i", "2" }; 
  argv[ 0 ] = cast_non_const( options[ 0 ] );
  argv[ 1 ] = cast_non_const( options[ 1 ] );
  argv[ 2 ] = cast_non_const( options[ 2 ] );
  argv[ 3 ] = NULL;

  parse_options( args, argc, argv );
  assert_int_equal( args->datapath_id, 2 );
}


static void
test_parse_datapath_hex_long_option( void **state ) {
  struct switch_arguments *args = *state;
  int argc = 3;
  char **argv = xmalloc( sizeof ( char * ) * ( size_t ) ( argc + 1 ) );
  const char *options[] = { "switch", "--datapath_id", "0xa" }; 
  argv[ 0 ] = cast_non_const( options[ 0 ] );
  argv[ 1 ] = cast_non_const( options[ 1 ] );
  argv[ 2 ] = cast_non_const( options[ 2 ] );
  argv[ 3 ] = NULL;

  parse_options( args, argc, argv );
  assert_int_equal( args->datapath_id, 10 );
}


static void
test_parse_switch_ports_option( void **state ) {
  struct switch_arguments *args = *state;
  int argc = 3;
  char **argv = xmalloc( sizeof ( char * ) * ( size_t ) ( argc + 1 ) );
  const char *options[] = { "switch", "--switch_ports", "eth0:1,eth1:2,lo:3" }; 
  argv[ 0 ] = cast_non_const( options[ 0 ] );
  argv[ 1 ] = cast_non_const( options[ 1 ] );
  argv[ 2 ] = cast_non_const( options[ 2 ] );
  argv[ 3 ] = NULL;

  parse_options( args, argc, argv );
  assert_string_equal( args->datapath_ports, options[ 2 ] );
}


int
main() {
  const UnitTest tests[] = {
    unit_test_setup_teardown( test_parse_datapath_long_option, create_switch_arguments, destroy_switch_arguments ),
    unit_test_setup_teardown( test_parse_datapath_hex_long_option, create_switch_arguments, destroy_switch_arguments ),
    unit_test_setup_teardown( test_parse_datapath_short_option, create_switch_arguments, destroy_switch_arguments ),
    unit_test_setup_teardown( test_parse_switch_ports_option, create_switch_arguments, destroy_switch_arguments ),
  };
  return run_tests( tests );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
