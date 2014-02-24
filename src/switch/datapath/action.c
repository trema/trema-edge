/*
 * Copyright (C) 2012-2013 NEC Corporation
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


#include "action.h"
#include "group_table.h"
#include "port_manager.h"
#include "switch_port.h"


static action *
create_action() {
  action *new_action = xmalloc( sizeof( action ) );
  memset( new_action, 0, sizeof( action ) );

  return new_action;
}


action *
create_action_output( const uint32_t port, const uint16_t max_len ) {
  action *action = create_action();

  action->type = OFPAT_OUTPUT;
  action->port = port;
  action->max_len = max_len;

  return action;
}


action *
create_action_group( const uint32_t group_id ) {
  action *action = create_action();

  action->type = OFPAT_GROUP;
  action->group_id = group_id;

  return action;
}


action *
create_action_set_queue( const uint32_t queue_id ) {
  action *action = create_action();

  action->type = OFPAT_SET_QUEUE;
  action->queue_id = queue_id;

  return action;
}


action *
create_action_set_mpls_ttl( const uint8_t mpls_ttl ) {
  action *action = create_action();

  action->type = OFPAT_SET_MPLS_TTL;
  action->mpls_ttl = mpls_ttl;

  return action;
}


action *
create_action_dec_mpls_ttl( void ) {
  action *action = create_action();

  action->type = OFPAT_DEC_MPLS_TTL;

  return action;
}


action *
create_action_set_ipv4_ttl( const uint8_t nw_ttl ) {
  action *action = create_action();

  action->type = OFPAT_SET_NW_TTL;
  action->nw_ttl = nw_ttl;

  return action;
}


action *
create_action_dec_ipv4_ttl() {
  action *action = create_action();

  action->type = OFPAT_DEC_NW_TTL;

  return action;
}


action *
create_action_copy_ttl_out( void ) {
  action *action = create_action();

  action->type = OFPAT_COPY_TTL_OUT;

  return action;
}


action *
create_action_copy_ttl_in() {
  action *action = create_action();

  action->type = OFPAT_COPY_TTL_IN;

  return action;
}


action *
create_action_push_vlan( const uint16_t ethertype ) {
  action *action = create_action();

  action->type = OFPAT_PUSH_VLAN;
  action->ethertype = ethertype;

  return action;
}


action *
create_action_push_mpls( const uint16_t ethertype ) {
  action *action = create_action();

  action->type = OFPAT_PUSH_MPLS;
  action->ethertype = ethertype;

  return action;
}


action *
create_action_push_pbb( const uint16_t ethertype ) {
  action *action = create_action();

  action->type = OFPAT_PUSH_PBB;
  action->ethertype = ethertype;

  return action;
}


action *
create_action_pop_vlan( void ) {
  action *action = create_action();

  action->type = OFPAT_POP_VLAN;

  return action;
}


action *
create_action_pop_mpls( const uint16_t ethertype ) {
  action *action = create_action();

  action->type = OFPAT_POP_MPLS;
  action->ethertype = ethertype;

  return action;
}


action *
create_action_pop_pbb( void ) {
  action *action = create_action();

  action->type = OFPAT_POP_PBB;

  return action;
}


action *
create_action_set_field( match *match ) {
  action *action = create_action();

  action->type = OFPAT_SET_FIELD;
  action->match = match;

  return action;
}


void
delete_action( action *action ) {
  assert( action != NULL );

  if ( action->match != NULL ) {
    delete_match( action->match );
  }
  xfree( action );
}


action_list *
create_action_list() {
  return create_dlist();
}


void
delete_action_list( action_list *list ) {
  assert( list != NULL );

  for ( dlist_element *element = get_first_element( list ); element != NULL; element = element->next ) {
    action *action = element->data;
    if ( action != NULL ) {
      delete_action( action );
    }
  }
  delete_dlist( list );
}


OFDPE
append_action( action_list *list, action *action ) {
  assert( list != NULL );
  assert( action != NULL );

  switch ( action->type ) {
    case OFPAT_OUTPUT:
    case OFPAT_COPY_TTL_OUT:
    case OFPAT_COPY_TTL_IN:
    case OFPAT_SET_MPLS_TTL:
    case OFPAT_DEC_MPLS_TTL:
    case OFPAT_PUSH_VLAN:
    case OFPAT_POP_VLAN:
    case OFPAT_PUSH_MPLS:
    case OFPAT_POP_MPLS:
    case OFPAT_SET_QUEUE:
    case OFPAT_GROUP:
    case OFPAT_SET_NW_TTL:
    case OFPAT_DEC_NW_TTL:
    case OFPAT_SET_FIELD:
    case OFPAT_PUSH_PBB:
    case OFPAT_POP_PBB:
      break;

    default:
      return ERROR_OFDPE_BAD_ACTION_BAD_TYPE;
  }

  list = insert_before_dlist( list, ( void * ) action );
  if ( list == NULL ) {
    return ERROR_APPEND_TO_LIST;
  }

  return OFDPE_SUCCESS;
}


OFDPE
remove_action( action_list *list, action *action ) {
  assert( list != NULL );
  assert( action != NULL );
  
  dlist_element *element = find_element( get_first_element( list ), action );
  if ( element == NULL ) {
    return ERROR_NOT_FOUND;
  }
  delete_action( action );
  delete_dlist_element( element );

  return OFDPE_SUCCESS;
}


action *
duplicate_action( const action *src ) {
  assert( src != NULL );

  action *dst = create_action();
  memcpy( dst, src, sizeof( action ) );
  if ( src->match != NULL ) {
    dst->match = duplicate_match( src->match );
  }

  return dst;
}


action_list *
duplicate_action_list( action_list *list ) {
  if ( list == NULL ) {
    return NULL;
  }

  dlist_element *dst = create_action_list();
  for ( dlist_element *element = get_first_element( list ); element != NULL; element = element->next ) {
    action *src_action = element->data;
    if ( src_action != NULL ) {
      action *dst_action = duplicate_action( src_action );
      insert_before_dlist( dst, dst_action );
    }
  }

  return dst;
}


bool
validate_action_set( action_list *list ) {
  assert( list != NULL );

  bool copy_ttl_inwards = false;
  bool pop = false;
  bool push_mpls = false;
  bool push_pbb = false;
  bool push_vlan = false;
  bool copy_ttl_outwards = false;
  bool decrement_ttl = false;
  bool set = false;
  bool qos = false;
  bool group = false;
  bool output = false;

  bool ret = true;
  for ( dlist_element *element = get_first_element( list ); element != NULL; element = element->next ) {
    action *action = element->data;
    if ( action == NULL ) {
      continue;
    }
    switch( action->type ) {
      case OFPAT_OUTPUT:
      {
        if ( output ) {
          ret = false;
        }
        output = true;
      }
      break;

      case OFPAT_COPY_TTL_OUT:
      {
        if ( copy_ttl_outwards ) {
          ret = false;
        }
        copy_ttl_outwards = true;
      }
      break;

      case OFPAT_COPY_TTL_IN:
      {
        if ( copy_ttl_inwards ) {
          ret = false;
        }
        copy_ttl_inwards = true;
      }
      break;

      case OFPAT_SET_MPLS_TTL:
      case OFPAT_SET_NW_TTL:
      {
        ret = false;
      }
      break;

      case OFPAT_PUSH_VLAN:
      {
        if ( push_vlan ) {
          ret = false;
        }
        push_vlan = true;
      }
      break;

      case OFPAT_PUSH_MPLS:
      {
        if ( push_mpls ) {
          ret = false;
        }
        push_mpls = true;
      }
      break;

      case OFPAT_PUSH_PBB:
      {
        if ( push_pbb ) {
          ret = false;
        }
        push_pbb = true;
      }
      break;

      case OFPAT_POP_VLAN:
      case OFPAT_POP_MPLS:
      case OFPAT_POP_PBB:
      {
        if ( pop ) {
          ret = false;
        }
        pop = true;
      }
      break;

      case OFPAT_DEC_MPLS_TTL:
      case OFPAT_DEC_NW_TTL:
      {
        if ( decrement_ttl ) {
         ret = false;
        }
        decrement_ttl = true;
      }
      break;

      case OFPAT_SET_QUEUE:
      {
        if ( qos ) {
          ret = false;
        }
        qos = true;
      }
      break;

      case OFPAT_SET_FIELD:
      {
        if ( set ) {
          ret = false;
        }
        set = true;
      }
      break;

      case OFPAT_GROUP:
      {
        if ( group ) {
          ret = false;
        }
        group = true;
      }
      break;

      case OFPAT_EXPERIMENTER:
      {
        ret = false;
      }
      break;
    }

    if ( !ret ) {
      break;
    }
  }

  return ret;
}


OFDPE
validate_action_list( action_list *list ) {
  if ( list == NULL ) {
    return true;
  }

  OFDPE ret = OFDPE_SUCCESS;
  for ( dlist_element *element = get_first_element( list ); element != NULL; element = element->next ) {
    if ( element->data == NULL ) {
      continue;
    }
    action *action = element->data;
    if ( action->type == OFPAT_GROUP ) {
      if ( !group_exists( action->group_id ) ) {
        ret = ERROR_OFDPE_BAD_ACTION_BAD_OUT_GROUP;
        break;
      }
    }
    if ( action->type == OFPAT_OUTPUT ) {
      if ( action->port > 0 && action->port <= OFPP_MAX ) {
        if ( !switch_port_exists( action->port ) ) {
          ret = ERROR_OFDPE_BAD_ACTION_BAD_OUT_PORT;
        }
        break;
      }
      else if ( action->port != OFPP_ALL && action->port != OFPP_FLOOD &&
                action->port != OFPP_IN_PORT && action->port != OFPP_CONTROLLER ) {
        ret = ERROR_OFDPE_BAD_ACTION_BAD_OUT_PORT;
        break;
      }
    }
  }

  return ret;
}


void
clear_action_set( action_set *set ) {
  assert( set != NULL );

  set->copy_ttl_in = NULL;
  set->copy_ttl_out = NULL;
  set->dec_mpls_ttl = NULL;
  set->dec_nw_ttl = NULL;
  set->group = NULL;
  set->output = NULL;
  set->pop_mpls = NULL;
  set->pop_pbb = NULL;
  set->pop_vlan = NULL;
  set->push_mpls = NULL;
  set->push_pbb = NULL;
  set->push_vlan = NULL;
  if ( set->set_field != NULL ) {
    delete_action( set->set_field );
  }
  set->set_field = NULL;
  set->set_mpls_ttl = NULL;
  set->set_nw_ttl = NULL;
  set->set_queue = NULL;
}


OFDPE
write_action_set( action_list *list, action_set *set ) {
  assert( list != NULL );
  assert( set != NULL );

  OFDPE ret = OFDPE_SUCCESS;
  for ( dlist_element *element = get_first_element( list ); element != NULL; element = element->next ) {
    if ( element->data == NULL ) {
      continue;
    }
    action *act = element->data;

    debug( "Writing an action ( type = %#x ) to action set ( set = %p ).", act->type, set );

    switch ( act->type ) {
      case OFPAT_OUTPUT:
      {
        set->output = act;
      }
      break;

      case OFPAT_COPY_TTL_OUT:
      {
        set->copy_ttl_out = act;
      }
      break;

      case OFPAT_COPY_TTL_IN:
      {
        set->copy_ttl_in = act;
      }
      break;

      case OFPAT_SET_MPLS_TTL:
      {
        set->set_mpls_ttl = act;
      }
      break;

      case OFPAT_DEC_MPLS_TTL:
      {
        set->dec_mpls_ttl = act;
      }
      break;

      case OFPAT_PUSH_VLAN:
      {
        set->push_vlan = act;
      }
      break;

      case OFPAT_POP_VLAN:
      {
        set->pop_vlan = act;
      }
      break;

      case OFPAT_PUSH_MPLS:
      {
        set->push_mpls = act;
      }
      break;

      case OFPAT_POP_MPLS:
      {
        set->pop_mpls = act;
      }
      break;

      case OFPAT_SET_QUEUE:
      {
        set->set_queue = act;
      }
      break;

      case OFPAT_GROUP:
      {
        set->group = act;
      }
      break;

      case OFPAT_SET_NW_TTL:
      {
        set->set_nw_ttl = act;
      }
      break;

      case OFPAT_DEC_NW_TTL:
      {
        set->dec_nw_ttl = act;
      }
      break;

      case OFPAT_SET_FIELD:
      {
        if ( set->set_field == NULL ) {
          set->set_field = create_action_set_field( duplicate_match( act->match ) );
        }
        else{
          merge_match( set->set_field->match, ( const match * ) act->match );
        }
      }
      break;

      case OFPAT_PUSH_PBB:
      {
        set->push_pbb = act;
      }
      break;

      case OFPAT_POP_PBB:
      {
        set->pop_pbb = act;
      }
      break;

      case OFPAT_EXPERIMENTER:
      {
        error( "OFPAT_EXPERIMENTER is not implemented." );
        ret = ERROR_OFDPE_BAD_ACTION_BAD_TYPE;
      }
      break;

      default:
      {
        error( "Undefined action type ( %#x ).", act->type );
        ret = ERROR_INVALID_PARAMETER;
      }
      break;
    }
  }

  return ret;
}


void
dump_action_capabilities( const action_capabilities capabilities ) {
  print_bitmap( capabilities, ACTION_OUTPUT, "output" );
  print_bitmap( capabilities, ACTION_COPY_TTL_OUT, "copy_ttl_out" );
  print_bitmap( capabilities, ACTION_COPY_TTL_IN, "copy_ttl_in" );
  print_bitmap( capabilities, ACTION_SET_MPLS_TTL, "set_mpls_ttl" );
  print_bitmap( capabilities, ACTION_DEC_MPLS_TTL, "dec_mpls_ttl" );
  print_bitmap( capabilities, ACTION_PUSH_VLAN, "push_vlan" );
  print_bitmap( capabilities, ACTION_POP_VLAN, "pop_vlan" );
  print_bitmap( capabilities, ACTION_PUSH_MPLS, "push_mpls" );
  print_bitmap( capabilities, ACTION_POP_MPLS, "pop_mpls" );
  print_bitmap( capabilities, ACTION_SET_QUEUE, "set_queue" );
  print_bitmap( capabilities, ACTION_GROUP, "group" );
  print_bitmap( capabilities, ACTION_SET_NW_TTL, "set_nw_ttl" );
  print_bitmap( capabilities, ACTION_DEC_NW_TTL, "dec_nw_ttl" );
  print_bitmap( capabilities, ACTION_SET_FIELD, "set_field" );
  print_bitmap( capabilities, ACTION_PUSH_PBB, "push_pbb" );
  print_bitmap( capabilities, ACTION_POP_PBB, "pop_pbb" );
  print_bitmap( capabilities, ACTION_EXPERIMENTER, "experimenter" );
}


void
dump_action( const action *action, void dump_function( const char *format, ... ) ) {
  assert( action != NULL );
  assert( dump_function != NULL );

  switch ( action->type ) {
    case OFPAT_OUTPUT:
    {
      ( *dump_function )( "type: OUTPUT ( %#x )", action->type );
      ( *dump_function )( "port: %u ( %#x )", action->port, action->port );
      ( *dump_function )( "max_len: %u ( %#x )", action->max_len, action->max_len );
    }
    break;

    case OFPAT_COPY_TTL_OUT:
    {
      ( *dump_function )( "type: COPY_TTL_OUT ( %#x )", action->type );
    }
    break;

    case OFPAT_COPY_TTL_IN:
    {
      ( *dump_function )( "type: COPY_TTL_IN ( %#x )", action->type );
    }
    break;

    case OFPAT_SET_MPLS_TTL:
    {
      ( *dump_function )( "type: SET_MPLS_TTL ( %#x )", action->type );
      ( *dump_function )( "mpls_ttl: %u ( %#x )", action->mpls_ttl, action->mpls_ttl );
    }
    break;

    case OFPAT_DEC_MPLS_TTL:
    {
      ( *dump_function )( "type: DEC_MPLS_TTL ( %#x )", action->type );
    }
    break;

    case OFPAT_PUSH_VLAN:
    {
      ( *dump_function )( "type: PUSH_VLAN ( %#x )", action->type );
      ( *dump_function )( "ethertype: %#x", action->ethertype );
    }
    break;

    case OFPAT_POP_VLAN:
    {
      ( *dump_function )( "type: POP_VLAN ( %#x )", action->type );
    }
    break;

    case OFPAT_PUSH_MPLS:
    {
      ( *dump_function )( "type: PUSH_MPLS ( %#x )", action->type );
      ( *dump_function )( "ethertype: %#x", action->ethertype );
    }
    break;

    case OFPAT_POP_MPLS:
    {
      ( *dump_function )( "type: POP_MPLS ( %#x )", action->type );
    }
    break;

    case OFPAT_SET_QUEUE:
    {
      ( *dump_function )( "type: SET_QUEUE ( %#x )", action->type );
      ( *dump_function )( "queue_id: %u ( %#x )", action->queue_id, action->queue_id );
    }
    break;

    case OFPAT_GROUP:
    {
      ( *dump_function )( "type: GROUP ( %#x )", action->type );
      ( *dump_function )( "group_id: %u ( %#x )", action->group_id, action->group_id );
    }
    break;

    case OFPAT_SET_NW_TTL:
    {
      ( *dump_function )( "type: SET_NW_TTL ( %#x )", action->type );
      ( *dump_function )( "nw_ttl: %u ( %#x )", action->nw_ttl, action->nw_ttl );
    }
    break;

    case OFPAT_DEC_NW_TTL:
    {
      ( *dump_function )( "type: DEC_NW_TTL ( %#x )", action->type );
    }
    break;

    case OFPAT_SET_FIELD:
    {
      ( *dump_function )( "type: SET_FIELD ( %#x )", action->type );
      dump_match( action->match, dump_function );
    }
    break;

    case OFPAT_PUSH_PBB:
    {
      ( *dump_function )( "type: PUSH_PBB ( %#x )", action->type );
      ( *dump_function )( "ethertype: %#x", action->ethertype );
    }
    break;

    case OFPAT_POP_PBB:
    {
      ( *dump_function )( "type: POP_PBB ( %#x )", action->type );
    }
    break;

    case OFPAT_EXPERIMENTER:
    {
      ( *dump_function )( "type: EXPERIMENTER ( %#x )", action->type );
    }
    break;

    default:
    {
      ( *dump_function )( "type: UNDEFINED ( %#x )", action->type );
    }
    break;
  }

  ( *dump_function )( "flow entry: %p", action->entry );
}


void
dump_action_list( action_list *list, void dump_function( const char *format, ... ) ) {
  assert( dump_function != NULL );

  for ( dlist_element *e = get_first_element( list ); e != NULL; e = e->next ) {
    if ( e->data == NULL ) {
      continue;
    }
    dump_action( e->data, dump_function );
  }
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
