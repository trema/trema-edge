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


static int
_assign_instructions( instruction_set *ins_set, list_element *element, const uint8_t table_id ) {
  assert( element );
  assert( ins_set );
  int ret = OFDPE_FAILED;

  while ( element != NULL ) {
    const struct ofp_instruction *hdr = ( struct ofp_instruction * ) element->data;
    switch ( hdr->type ) {
      case OFPIT_GOTO_TABLE: {
          ret = add_instruction( ins_set, alloc_instruction_goto_table( table_id ) );
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
int ( *assign_instructions )( instruction_set *ins_set, list_element *element, uint8_t table_id ) = _assign_instructions;


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

