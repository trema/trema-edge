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


#include <stdint.h>
#include "ofdp.h"
#include "trema.h"
#include "action-tlv-copy-ttl-in.h"
#include "action-tlv-copy-ttl-out.h"
#include "action-tlv-dec-mpls-ttl.h"
#include "action-tlv-dec-nw-ttl.h"
#include "action-tlv-experimenter.h"
#include "action-tlv-group.h"
#include "action-tlv-output.h"
#include "action-tlv-pop-mpls.h"
#include "action-tlv-pop-pbb.h"
#include "action-tlv-pop-vlan.h"
#include "action-tlv-push-mpls.h"
#include "action-tlv-push-pbb.h"
#include "action-tlv-push-vlan.h"
#include "action-tlv-set-field.h"
#include "action-tlv-set-mpls-ttl.h"
#include "action-tlv-set-nw-ttl.h"
#include "action-tlv-set-queue.h"
#include "action-tlv.h"
#include "oxm-helper.h"


static struct action_tlv **actions_arr;
static uint32_t actions_nr, actions_alloc;


void
register_action( struct action_tlv *action ) {
  ALLOC_GROW( actions_arr, actions_nr + 1, actions_alloc );
  actions_arr[ actions_nr++ ] = action;
}


void
init_actions( void ) {
  init_action_tlv_output();
  init_action_tlv_set_field();
  init_action_tlv_group();
  init_action_tlv_set_queue();
  init_action_tlv_set_mpls_ttl();
  init_action_tlv_dec_mpls_ttl();
  init_action_tlv_set_nw_ttl();
  init_action_tlv_dec_nw_ttl();
  init_action_tlv_copy_ttl_out();
  init_action_tlv_copy_ttl_in();
  init_action_tlv_push_vlan();
  init_action_tlv_push_mpls();
  init_action_tlv_push_pbb();
  init_action_tlv_pop_vlan();
  init_action_tlv_pop_mpls();
  init_action_tlv_pop_pbb();
  init_action_tlv_experimenter();
}


void
finalize_actions( void ) {
  assert( actions_arr != NULL );
  actions_nr = actions_alloc = 0;
}


uint16_t
action_tlv_length_by_type( uint16_t type ) {
  uint16_t length = 0;

  for ( uint32_t i = 0; i < actions_nr; i++ ) {
    if ( type == actions_arr[ i ]->type ) {
      length = ( uint16_t ) ( length + actions_arr[ i ]->len );
    }
  }
  return length;
}



static void
map_action_args( struct action_tlv_args *args, const action *action  ) {
  switch ( action->type ) {
    case OFPAT_OUTPUT:
      args->uac_output.port = action->port;
      args->uac_output.max_len = action->max_len;
      break;
    case OFPAT_GROUP:
      args->uac_group.group_id = action->group_id;
      break;
    case OFPAT_SET_QUEUE:
      args->uac_set_queue.queue_id = action->queue_id;
      break;
    case OFPAT_SET_MPLS_TTL:
      args->uac_mpls_ttl.mpls_ttl = action->mpls_ttl;
      break;
    case OFPAT_SET_NW_TTL:
      args->uac_nw_ttl.nw_ttl = action->nw_ttl;
      break;
    case OFPAT_PUSH_VLAN:
      args->uac_push_vlan.ethertype = action->ethertype;
      break;
    case OFPAT_PUSH_MPLS:
      args->uac_push_mpls.ethertype = action->ethertype;
      break;
    case OFPAT_PUSH_PBB:
      args->uac_push_pbb.ethertype = action->ethertype;
      break;
    case OFPAT_POP_MPLS:
      args->uac_pop_mpls.ethertype = action->ethertype;
      break;
    default:
      break;
   }
}


void
action_tlv_pack( struct ofp_action_header *ac_hdr, const action *action  ) {
  struct action_tlv_args action_tlv_args;

  map_action_args( &action_tlv_args, action );
  for ( uint32_t i = 0; i < actions_nr; i++ ) {
    if ( actions_arr[ i ]->type == action->type ) {
      actions_arr[ i ]->pack( ac_hdr, &action_tlv_args );
      if ( action->type == OFPAT_SET_FIELD ) {
        struct ofp_action_set_field *set_field = ( struct ofp_action_set_field * ) ac_hdr;
        set_field->len = ( uint16_t ) ( set_field->len - sizeof( set_field->field ) ); // PADLEN_TO_64() below
        oxm_match_header *oxm_hdr = ( oxm_match_header * ) ( ( char * ) set_field + offsetof( struct ofp_action_set_field, field ) );
        set_field->len = ( uint16_t ) ( set_field->len + pack_oxm( oxm_hdr, action->match ) );
        set_field->len = ( uint16_t ) ( set_field->len + PADLEN_TO_64( set_field->len ) );
      }
    }
  }
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
