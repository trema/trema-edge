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
#include <stdio.h>
#include <stdlib.h>
#include "trema.h"
#include "ofdp.h"
#include "action-helper.h"


size_t
_instructions_len( const instruction_set *ins_set ) {
  size_t total_len = 0;

  if ( ins_set->goto_table != NULL ) {
    total_len += sizeof( struct ofp_instruction_goto_table ); 
  }
  if ( ins_set->write_metadata != NULL ) {
    total_len += sizeof( struct ofp_instruction_write_metadata );
  }
  if ( ins_set->write_actions != NULL ) {
    total_len += sizeof( struct ofp_instruction_actions ) + action_list_length( &ins_set->write_actions->actions );
  }
  if ( ins_set->apply_actions != NULL  ) {
    total_len += sizeof( struct ofp_instruction_actions ) + action_list_length( &ins_set->apply_actions->actions );
  }
  if ( ins_set->clear_actions != NULL ) {
    total_len += sizeof( struct ofp_instruction_actions );
  }
  if ( ins_set->meter != NULL ) {
    total_len += sizeof( struct ofp_instruction_meter );
  }
  if ( ins_set->experimenter != NULL ) {
    total_len += sizeof( struct ofp_instruction_experimenter );
  }

  return total_len;
}
size_t ( *instructions_len ) ( const instruction_set *ins_set ) = _instructions_len;


static int
_assign_instructions( instruction_set *ins_set, list_element *element ) {
  assert( element );
  assert( ins_set );
  int ret = OFDPE_FAILED;

  while ( element != NULL ) {
    const struct ofp_instruction *hdr = ( struct ofp_instruction * ) element->data;
    switch ( hdr->type ) {
      case OFPIT_GOTO_TABLE: {
        const struct ofp_instruction_goto_table *goto_table = ( const struct ofp_instruction_goto_table * ) element->data;
        ret = add_instruction( ins_set, alloc_instruction_goto_table( goto_table->table_id ) );
      }
      break;
      case OFPIT_WRITE_METADATA: {
        const struct ofp_instruction_write_metadata *metadata_ins = ( const struct ofp_instruction_write_metadata * ) element->data;
        ret = add_instruction( ins_set, alloc_instruction_write_metadata( metadata_ins->metadata, metadata_ins->metadata_mask ) );
      }
      break;
      case OFPIT_WRITE_ACTIONS: {
        const struct ofp_instruction_actions *action_ins = ( const struct ofp_instruction_actions * ) element->data;
        action_list *ac_list = create_action_list();
        size_t offset = offsetof( struct ofp_instruction_actions, actions );
        uint16_t ac_len = ( uint16_t )( action_ins->len - offset );
        ret = add_instruction( ins_set, alloc_instruction_write_actions( assign_actions( ac_list, action_ins->actions, ac_len ) ) );
      }
      break;
      case OFPIT_APPLY_ACTIONS: {
        const struct ofp_instruction_actions *action_ins = ( const struct ofp_instruction_actions * ) element->data;
        action_list *ac_list = create_action_list();
        size_t offset = offsetof( struct ofp_instruction_actions, actions );
        uint16_t ac_len = ( uint16_t )( action_ins->len - offset );
        ret = add_instruction( ins_set, alloc_instruction_apply_actions( assign_actions( ac_list, action_ins->actions, ac_len ) ) );
      }
      break;
      case OFPIT_CLEAR_ACTIONS: {
        ret = add_instruction( ins_set, alloc_instruction_clear_actions() );
      }
      break;
      case OFPIT_METER: {
        const struct ofp_instruction_meter *meter_ins = ( const struct ofp_instruction_meter * ) element->data;
        ret = add_instruction( ins_set, alloc_instruction_meter( meter_ins->meter_id ) );
      }
      break;
      default:
      break;
    }
    element = element->next;
  }
  return ret;
}
int ( *assign_instructions )( instruction_set *ins_set, list_element *element ) = _assign_instructions;


void
_pack_ofp_instruction( const instruction_set *ins_set, struct ofp_instruction *ins ) {
  size_t ins_len = 0;

  if ( ins_set->goto_table != NULL ) {
    struct ofp_instruction_goto_table *instruction_goto_table = ( struct ofp_instruction_goto_table * )( ( char * ) ins + ins_len );
    instruction_goto_table->type = OFPIT_GOTO_TABLE;
    instruction_goto_table->len = sizeof( *instruction_goto_table );
    instruction_goto_table->table_id = ins_set->goto_table->table_id;
    memset( instruction_goto_table->pad, 0, sizeof( instruction_goto_table->pad ) );
    ins_len += instruction_goto_table->len;
  }
  if ( ins_set->write_metadata != NULL ) {
    struct ofp_instruction_write_metadata *instruction_write_metadata = ( struct ofp_instruction_write_metadata * )( ( char * ) ins + ins_len );
    instruction_write_metadata->type = OFPIT_WRITE_METADATA;
    instruction_write_metadata->len = sizeof( *instruction_write_metadata );
    instruction_write_metadata->metadata = ins_set->write_metadata->metadata;
    instruction_write_metadata->metadata_mask = ins_set->write_metadata->metadata_mask;
    ins_len += instruction_write_metadata->len;
  }
  if ( ins_set->write_actions != NULL ) {
    struct ofp_instruction_actions *instruction_actions = ( struct ofp_instruction_actions * )( ( char * ) ins + ins_len );
    instruction_actions->type = OFPIT_WRITE_ACTIONS;
    instruction_actions->len = ( uint16_t ) ( sizeof( *instruction_actions ) + action_list_length( &ins_set->write_actions->actions ) );
    memset( instruction_actions->pad, 0, sizeof( instruction_actions->pad ) );
    void *a = ( void * ) ( ( char * ) instruction_actions + offsetof( struct ofp_instruction_actions, actions ) );
    action_pack( a, &ins_set->write_actions->actions );
    ins_len += instruction_actions->len;
  }
  if ( ins_set->apply_actions != NULL ) {
    struct ofp_instruction_actions *instruction_actions = ( struct ofp_instruction_actions * )( ( char * ) ins + ins_len );
    instruction_actions->type = OFPIT_APPLY_ACTIONS;
    instruction_actions->len = ( uint16_t ) ( sizeof( *instruction_actions ) + action_list_length( &ins_set->apply_actions->actions ) );
    memset( instruction_actions->pad, 0, sizeof( instruction_actions->pad ) );
    void *a = ( void * ) ( ( char * ) instruction_actions + offsetof( struct ofp_instruction_actions, actions ) );
    action_pack( a, &ins_set->apply_actions->actions );
    ins_len += instruction_actions->len;
  }
  if ( ins_set->clear_actions != NULL ) {
    struct ofp_instruction_actions *instruction_actions = ( struct ofp_instruction_actions * )( ( char * ) ins + ins_len );
    instruction_actions->type = OFPIT_CLEAR_ACTIONS;
    instruction_actions->len = sizeof( *instruction_actions );
    memset( instruction_actions->pad, 0, sizeof( instruction_actions->pad ) );
    ins_len += instruction_actions->len;
  }
  if ( ins_set->meter != NULL ) {
    struct ofp_instruction_meter *instruction_meter = ( struct ofp_instruction_meter * )( ( char * ) ins + ins_len );
    instruction_meter->type = OFPIT_METER;
    instruction_meter->len = sizeof( *instruction_meter );
    instruction_meter->meter_id = ins_set->meter->meter_id;
    ins_len += instruction_meter->len;
  }
  if ( ins_set->experimenter != NULL ) {
    struct ofp_instruction_experimenter *instruction_experimenter = ( struct ofp_instruction_experimenter * )( ( char * ) ins + ins_len );
    instruction_experimenter->type = OFPIT_EXPERIMENTER;
    instruction_experimenter->len = sizeof ( *instruction_experimenter );
    ins_len += instruction_experimenter->len;
  }
}
void ( *pack_ofp_instruction )( const instruction_set *ins_set, struct ofp_instruction *ins ) = _pack_ofp_instruction;


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

