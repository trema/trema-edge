/*
 * Copyright (C) 2008-2012 NEC Corporation
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
#include "cmockery_trema.h"
#include "openflow.h"
#include "wrapper.h"
#include "checks.h"
#include "message_queue.h"
#include "controller_manager.h"
#include "async.h"
#include "datapath.h"
#include "mocks.h"


#define MY_TRANSACTION_ID 0x11223344
#define GROUP_ID 1
#define INVALID_GROUP_ID 3333
#define WATCH_GROUP_1 0xaa
#define WATCH_GROUP_2 0xbb
#define WATCH_PORT_1 1
#define WATCH_PORT_2 2
#define WEIGHT_1 123
#define WEIGHT_2 456


static void
create_datapath_error( void **state ) {
  notify_parameter_error *error = ( notify_parameter_error * ) xmalloc( sizeof( *error ) );

  error->error_code = ERROR_OFDPE_FLOW_MOD_FAILED_TABLE_FULL;
  const char *error_desc = "this is a test";
  size_t error_len = sizeof( error_desc );
  
  error->packet = alloc_buffer_with_length( error_len );
  append_back_buffer( error->packet, error_len );
  memcpy( error->packet->data, error_desc, error_len );
  *state = ( void * ) error;
}


static void
destroy_datapath_error( void **state ) {
  notify_parameter_error *error = *state;
  free_buffer( error->packet );
  xfree( error );
}


static void
test_datapath_error( void **state ) {
  UNUSED( state );
}


int
main() {
  const UnitTest tests[] = {
    unit_test_setup_teardown( test_datapath_error, create_datapath_error, destroy_datapath_error ),
  };
  return run_tests( tests );
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
