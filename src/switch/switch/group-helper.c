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


#include "trema.h"
#include "ofdp.h"
#include "action-helper.h"


#ifdef UNIT_TESTING


#ifdef send_error_message
#undef send_error_message
#endif
#define send_error_message mock_send_error_message
bool mock_send_error_message( uint32_t transaction_id, uint16_t type, uint16_t code );


#endif // UNIT_TESTING


static bucket_list *
construct_bucket_list( const list_element *buckets ) {
  bucket_list *bkt_list = create_action_bucket_list();

  for ( const list_element *e = buckets; e != NULL; e = e->next ) {
    const struct ofp_bucket *ofp_bucket = e->data;
    uint16_t offset = ( uint16_t ) offsetof( struct ofp_bucket, actions );
    if ( ofp_bucket->len > offset ) {
      action_list *ac_list = create_action_list();
      uint16_t action_length = ( uint16_t ) ( ofp_bucket->len - offset );
      ac_list = assign_actions( ac_list, ofp_bucket->actions, action_length );
      bucket *bucket = create_action_bucket( ofp_bucket->weight, ofp_bucket->watch_port, ofp_bucket->watch_group, ac_list );
      if ( bucket != NULL ) {
        append_action_bucket( bkt_list, bucket );
      }
    }
  }
  return bkt_list;
}


static void
_handle_group_add( const uint32_t transaction_id, const uint8_t type, const uint32_t group_id, const list_element *buckets ) {
  bucket_list *bkt_list = construct_bucket_list( buckets );
  group_entry *entry = alloc_group_entry( type, group_id, bkt_list );
  if ( entry == NULL ) {
    send_error_message( transaction_id, OFPET_GROUP_MOD_FAILED, OFPGMFC_EPERM );
    delete_action_bucket_list( bkt_list );
    return;
  }

  OFDPE ret = add_group_entry( entry );
  if ( ret != OFDPE_SUCCESS ) {
    uint16_t type = OFPET_GROUP_MOD_FAILED;
    uint16_t code = OFPGMFC_EPERM;
    get_ofp_error( ret, &type, &code );
    send_error_message( transaction_id, type, code );
    free_group_entry( entry );
  }
}
void ( *handle_group_add )( const uint32_t transaction_id, const uint8_t type, const uint32_t group_id, const list_element *buckets ) = _handle_group_add;


static void
_handle_group_mod_mod( const uint32_t transaction_id, const uint8_t type, const uint32_t group_id, const list_element *buckets ) {
  bucket_list *bkt_list = construct_bucket_list( buckets );

  OFDPE ret = update_group_entry( group_id, type, bkt_list );
  if ( ret != OFDPE_SUCCESS ) {
    uint16_t type = OFPET_GROUP_MOD_FAILED;
    uint16_t code = OFPGMFC_EPERM;
    get_ofp_error( ret, &type, &code );
    send_error_message( transaction_id, type, code );
    delete_action_bucket_list( bkt_list );
  }
}
void ( *handle_group_mod_mod )( const uint32_t transaction_id, const uint8_t type, const uint32_t group_id, const list_element *buckets ) = _handle_group_mod_mod;


static void
_handle_group_mod_delete( const uint32_t transaction_id, const uint32_t group_id ) {
  OFDPE ret = delete_group_entry( group_id );
  if ( ret != OFDPE_SUCCESS ) {
    uint16_t type = OFPET_GROUP_MOD_FAILED;
    uint16_t code = OFPGMFC_EPERM;
    get_ofp_error( ret, &type, &code );
    send_error_message( transaction_id, type, code );
  }
}
void ( *handle_group_mod_delete )( const uint32_t transaction_id, const uint32_t group_id ) = _handle_group_mod_delete;


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

