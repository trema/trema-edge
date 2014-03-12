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
#include "action-tlv-interface.h"
#include "oxm.h"
#include "oxm-helper.h"


action_list *
_assign_actions( action_list *action_list, const struct ofp_action_header *action_hdr, uint16_t action_length ) {
  size_t offset = 0;
  uint16_t type;

  while( action_length - offset >= sizeof( struct ofp_action_header ) ) {
    type = ( ( const struct ofp_action_header * )( ( const char * )action_hdr + offset ) )->type;
    if ( type == OFPAT_OUTPUT ) {
      const struct ofp_action_output *action_output = ( const struct ofp_action_output * )( ( const char * )action_hdr + offset );
      action *ac = create_action_output( action_output->port, action_output->max_len );
      if ( ac != NULL ) {
        offset += action_output->len;
        append_action( action_list, ac );
      }
    }
    else if ( type == OFPAT_COPY_TTL_OUT ) {
      append_action( action_list, create_action_copy_ttl_out() );
      offset += sizeof( *action_hdr );
    }
    else if ( type == OFPAT_COPY_TTL_IN ) {
      append_action( action_list, create_action_copy_ttl_in() );
      offset += sizeof( *action_hdr );
    }
    else if ( type == OFPAT_SET_MPLS_TTL ) {
      const struct ofp_action_mpls_ttl *action_mpls_ttl = ( const struct ofp_action_mpls_ttl * )( ( const char * )action_hdr + offset );
      append_action( action_list, create_action_set_mpls_ttl( action_mpls_ttl->mpls_ttl ) );
      offset += action_mpls_ttl->len;
    }
    else if ( type == OFPAT_DEC_MPLS_TTL ) {
      append_action( action_list, create_action_dec_mpls_ttl() );
      offset += sizeof( *action_hdr );
    }
    else if ( type == OFPAT_SET_NW_TTL ) {
      const struct ofp_action_nw_ttl *action_nw_ttl = ( const struct ofp_action_nw_ttl *)( ( const char * )action_hdr + offset );
      append_action( action_list, create_action_set_ipv4_ttl( action_nw_ttl->nw_ttl ) );
      offset += action_nw_ttl->len;
    }
    else if ( type == OFPAT_DEC_NW_TTL ) {
      append_action( action_list, create_action_dec_ipv4_ttl() );
      offset += sizeof( *action_hdr );
    }
    else if ( type == OFPAT_PUSH_VLAN ) {
      const struct ofp_action_push *action_push = ( const struct ofp_action_push * )( ( const char * )action_hdr + offset );
      append_action( action_list, create_action_push_vlan( action_push->ethertype ) );
      offset += action_push->len;
    }
    else if ( type == OFPAT_PUSH_MPLS ) {
      const struct ofp_action_push *action_push = ( const struct ofp_action_push * )( ( const char * )action_hdr + offset );
      append_action( action_list, create_action_push_mpls( action_push->ethertype ) );
      offset += action_push->len;
    }
    else if ( type == OFPAT_PUSH_PBB ) {
      const struct ofp_action_push *action_push = ( const struct ofp_action_push * )( ( const char * )action_hdr + offset );
      append_action( action_list, create_action_push_pbb( action_push->ethertype ) );
      offset += action_push->len;
    }
    else if ( type == OFPAT_POP_VLAN ) {
      append_action( action_list, create_action_pop_vlan() );
      offset += sizeof( *action_hdr );
    }
    else if ( type == OFPAT_POP_MPLS ) {
      const struct ofp_action_pop_mpls *action_pop_mpls = ( const struct ofp_action_pop_mpls * )( ( const char * )action_hdr + offset );
      append_action( action_list, create_action_pop_mpls( action_pop_mpls->ethertype ) );
      offset += action_pop_mpls->len;
    }
    else if ( type == OFPAT_POP_PBB ) {
      append_action( action_list, create_action_pop_pbb() );
      offset += sizeof( *action_hdr );
    }
    else if ( type == OFPAT_SET_QUEUE ) {
      const struct ofp_action_set_queue *set_queue = ( const struct ofp_action_set_queue * )( ( const char * )action_hdr + offset );
      append_action( action_list, create_action_set_queue( set_queue->queue_id ) );
      offset += set_queue->len;
    }
    else if ( type == OFPAT_SET_FIELD ) {
      const struct ofp_action_set_field *set_field = ( const struct ofp_action_set_field * )( ( const char * )action_hdr + offset );
      match *match = create_match();
      assign_match( match, ( oxm_match_header * ) &set_field->field );
      append_action( action_list, create_action_set_field( match ) );
      offset += set_field->len;
    }
    else if ( type == OFPAT_GROUP ) {
      const struct ofp_action_group *action_group = ( const struct ofp_action_group * )( ( const char * )action_hdr + offset );
      append_action( action_list, create_action_group( action_group->group_id ) );
      offset += action_group->len;
    }
    else {
      warn( "Invalid action type %u", action_hdr->type );
      break;
    }
  }
  return action_list;
}
action_list * ( *assign_actions )( action_list *action_list, const struct ofp_action_header *action, uint16_t action_len ) = _assign_actions;


void
_action_pack( void *dest, action_list **list  ) {
  if ( *list == NULL ) {
    return;
  }
  dlist_element *item = get_first_element( *list );
  action *action;
  struct ofp_action_header *ac_hdr = dest;
  while ( item != NULL ) {
    action = item->data;
    if ( action != NULL ) {
      action_tlv_pack( ac_hdr, action );
      ac_hdr = ( struct ofp_action_header * ) ( ( char * ) ac_hdr + ac_hdr->len );
    }
    item = item->next;
  }
}
void ( *action_pack )( void *dest, action_list **list ) = _action_pack;


uint16_t
_action_list_length( action_list **list ) {
  if ( *list == NULL ) {
    return 0;
  }
  uint16_t length = 0;
  dlist_element *item = get_first_element( *list );
  action *action;
  while ( item != NULL ) {
    action = item->data;
    if ( action != NULL ) {
      length = ( uint16_t ) ( length + action_tlv_length_by_type( action->type ) );
      if ( action->type == OFPAT_SET_FIELD && action->match ) {
        length = ( uint16_t ) ( length - sizeof( ( ( struct ofp_action_set_field * ) NULL )->field ) ); // // PADLEN_TO_64() below
        uint16_t m_len = match_length( action->match );
        length = ( uint16_t ) ( length + m_len );
        length = ( uint16_t ) ( length + PADLEN_TO_64( length ) );
      }
    }
    item = item->next;
  }
  return length;
}
uint16_t ( *action_list_length )( action_list **list ) = _action_list_length;


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
