/*
 * Copyright (C) 2013 NEC Corporation
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


#include "trema.h"


static void
handle_multipart_reply( uint64_t datapath_id, uint32_t transaction_id, uint16_t type,
                        uint16_t flags, const buffer *data, void *user_data ) {
  UNUSED( user_data );

  if ( type != OFPMP_GROUP_DESC ) {
    return;
  }

  info( "datapath_id: %#" PRIx64, datapath_id );
  info( "transaction_id: %x", transaction_id );
  info( "type: %u", type );
  info( "flags: %u", flags );
  struct ofp_group_desc *group_desc = ( struct ofp_group_desc * ) data->data;
  size_t length = data->length;
  while ( length >= sizeof( struct ofp_group_desc ) ) {
    info( "group_id: %u", group_desc->group_id );
    info( "  type: %u", group_desc->type );
    struct ofp_bucket *bucket = group_desc->buckets;
    uint16_t bucket_length = ( uint16_t ) ( group_desc->length - offsetof( struct ofp_group_desc, buckets ) );
    while ( bucket_length >= sizeof( struct ofp_bucket ) ) {
      info( "  bucket:" );
      info( "    weight: %u", bucket->weight );
      info( "    watch_port: %u", bucket->watch_port );
      info( "    watch_group: %u", bucket->watch_group );
      uint16_t action_length = ( uint16_t ) ( bucket->len - offsetof( struct ofp_bucket, actions ) );
      char actions_str[ 4096 ];
      actions_str[ 0 ] = '\0';
      if ( action_length > 0 ) {
	actions_to_string( bucket->actions, action_length, actions_str, sizeof( actions_str ) );
      }
      info( "    actions: %s", actions_str );

      bucket_length = ( uint16_t ) ( bucket_length - bucket->len );
      bucket = ( struct ofp_bucket * ) ( ( char * ) bucket + bucket->len );
    }

    length -= group_desc->length;
    group_desc = ( struct ofp_group_desc * ) ( ( char * ) group_desc + group_desc->length );
  }
}


static void
send_group_mod( uint64_t datapath_id ) {

  openflow_actions *actions = create_actions();
  append_action_output( actions, OFPP_CONTROLLER, OFPCML_NO_BUFFER );
  openflow_buckets *buckets = create_buckets();
  append_bucket( buckets, 0, 0, 0, actions );

  buffer *group_mod = create_group_mod(
    get_transaction_id(),
    OFPGC_ADD,
    OFPGT_INDIRECT,
    200,
    buckets
  );
  send_openflow_message( datapath_id, group_mod );
  free_buffer( group_mod );

  delete_buckets( buckets );
  delete_actions( actions );
}


static void
send_group_desc_multipart_request( uint64_t datapath_id ) {
  buffer *group_desc_multipart_request = create_group_desc_multipart_request( get_transaction_id(), 0 );
  send_openflow_message( datapath_id, group_desc_multipart_request );
  free_buffer( group_desc_multipart_request );
}


static void
handle_switch_ready( uint64_t datapath_id, void *user_data ) {
  UNUSED( user_data );
  send_group_mod( datapath_id );
  send_group_desc_multipart_request( datapath_id );
}


int
main( int argc, char *argv[] ) {
  init_trema( &argc, &argv );

  set_switch_ready_handler( handle_switch_ready, NULL );
  set_multipart_reply_handler( handle_multipart_reply, NULL );

  start_trema();

  return 0;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
