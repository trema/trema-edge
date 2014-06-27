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


#include "flow_table.h"
#include "group_table.h"
#include "meter_table.h"
#include "instruction.h"


typedef enum {
  INCREMENT,
  DECREMENT,
} counter_update_type;


static instruction *
alloc_instruction() {
  instruction *new_instruction = xmalloc( sizeof( instruction ) );
  memset( new_instruction, 0, sizeof( instruction ) );

  return new_instruction;
}


instruction *
alloc_instruction_goto_table( const uint8_t table_id ) {
  assert( valid_table_id( table_id ) );

  instruction *instruction = alloc_instruction();
  instruction->type = OFPIT_GOTO_TABLE;
  instruction->table_id = table_id;

  return instruction;
}


instruction *
alloc_instruction_write_metadata( const uint64_t metadata, const uint64_t metadata_mask ) {
  instruction *instruction = alloc_instruction();
  instruction->type = OFPIT_WRITE_METADATA;
  instruction->metadata = metadata;
  instruction->metadata_mask = metadata_mask;

  return instruction;
}


instruction *
alloc_instruction_write_actions( action_list *action ) {
  instruction *instruction = alloc_instruction();
  instruction->type = OFPIT_WRITE_ACTIONS;
  instruction->actions = action;

  return instruction;
}


instruction *
alloc_instruction_apply_actions( action_list *action ) {
  instruction *instruction = alloc_instruction();
  instruction->type = OFPIT_APPLY_ACTIONS;
  instruction->actions = action;

  return instruction;
}


instruction *
alloc_instruction_clear_actions( void ) {
  instruction *instruction = alloc_instruction();
  instruction->type = OFPIT_CLEAR_ACTIONS;

  return instruction;
}


instruction *
alloc_instruction_meter( const uint32_t meter_id ) {
  instruction *instruction = alloc_instruction();
  instruction->type = OFPIT_METER;
  instruction->meter_id = meter_id;

  return instruction;
}


void
free_instruction( instruction *instruction ) {
  assert( instruction != NULL );

  if ( instruction->actions != NULL ) {
    delete_action_list( instruction->actions );
  }

  xfree( instruction );
}


instruction *
duplicate_instruction( const instruction *src ) {
  if ( src == NULL ) {
    return NULL;
  }

  instruction *duplicated = xmalloc( sizeof( instruction ) );
  memcpy( duplicated, src, sizeof( instruction ) );
  if ( src->actions != NULL ) {
    duplicated->actions = duplicate_actions( src->actions );
  }

  return duplicated;
}


instruction_set *
create_instruction_set() {
  instruction_set *new_instructions = xmalloc( sizeof( instruction_set ) );
  memset( new_instructions, 0, sizeof( instruction_set ) );

  new_instructions->goto_table = NULL;
  new_instructions->write_metadata = NULL;
  new_instructions->write_actions = NULL;
  new_instructions->apply_actions = NULL;
  new_instructions->meter = NULL;
  new_instructions->experimenter = NULL;

  return new_instructions;
}


void
delete_instruction_set( instruction_set *instructions ) {
  assert( instructions != NULL );

  if ( instructions->goto_table != NULL ) {
    free_instruction( instructions->goto_table );
  }
  if ( instructions->write_metadata != NULL ) {
    free_instruction( instructions->write_metadata );
  }
  if ( instructions->write_actions != NULL ) {
    free_instruction( instructions->write_actions );
  }
  if ( instructions->apply_actions != NULL ) {
    free_instruction( instructions->apply_actions );
  }
  if ( instructions->clear_actions != NULL ) {
    free_instruction( instructions->clear_actions );
  }
  if ( instructions->meter != NULL ) {
    free_instruction( instructions->meter );
  }
  if ( instructions->experimenter != NULL ) {
    free_instruction( instructions->experimenter );
  }

  xfree( instructions );
}


OFDPE
add_instruction( instruction_set *instructions, instruction *instruction ) {
  assert( instructions != NULL );
  assert( instruction != NULL );
  assert( instruction->type >= 1 );

  bool duplicated = false;
  OFDPE ret = OFDPE_SUCCESS;
  switch( instruction->type ) {
    case OFPIT_GOTO_TABLE:
    {
      if ( instructions->goto_table == NULL ) {
        instructions->goto_table = instruction;
      }
      else {
        duplicated = true;
      }
    }
    break;

    case OFPIT_WRITE_METADATA:
    {
      if ( instructions->write_metadata == NULL ) {
        instructions->write_metadata = instruction;
      }
      else {
        duplicated = true;
      }
    }
    break;

    case OFPIT_WRITE_ACTIONS:
    {
      if ( instructions->write_actions == NULL ) {
        instructions->write_actions = instruction;
      }
      else {
        duplicated = true;
      }
    }
    break;

    case OFPIT_APPLY_ACTIONS:
    {
      if ( instructions->apply_actions == NULL ) {
        instructions->apply_actions = instruction;
      }
      else {
        duplicated = true;
      }
    }
    break;

    case OFPIT_CLEAR_ACTIONS:
    {
      if ( instructions->clear_actions == NULL ) {
        instructions->clear_actions = instruction;
      }
      else {
        duplicated = true;
      }
    }
    break;

    case OFPIT_METER:
    {
      if ( instructions->meter == NULL ) {
        instructions->meter = instruction;
      }
      else {
        duplicated = true;
      }
    }
    break;

    case OFPIT_EXPERIMENTER:
    {
      error( "OFPIT_EXPERIMENTER is not supported." );
      ret = ERROR_OFDPE_BAD_INSTRUCTION_UNSUP_INST;
    }
    break;

    default:
    {
      error( "Invalid instruction type ( %#x ).", instruction->type );
      ret = ERROR_OFDPE_BAD_INSTRUCTION_UNKNOWN_INST;
    }
    break;
  }

  if ( duplicated ) {
    error( "Only a single instruction can be set for each type ( type = %#x ).", instruction->type );
    ret = ERROR_INVALID_PARAMETER;
  }

  return ret;
}


OFDPE
delete_instruction( instruction_set *instructions, const uint16_t type ) {
  assert( instructions != NULL );
  assert( type >= 1 );

  OFDPE ret = OFDPE_SUCCESS;
  switch( type ) {
    case OFPIT_GOTO_TABLE:
    {
      if ( instructions->goto_table != NULL ) {
        free_instruction( instructions->goto_table );
        instructions->goto_table = NULL;
      }
      else {
        ret = ERROR_INVALID_PARAMETER;
      }
    }
    break;

    case OFPIT_WRITE_METADATA:
    {
      if ( instructions->write_metadata != NULL ) {
        free_instruction( instructions->write_metadata );
        instructions->write_metadata = NULL;
      }
      else {
        ret = ERROR_INVALID_PARAMETER;
      }
    }
    break;

    case OFPIT_WRITE_ACTIONS:
    {
      if ( instructions->write_actions != NULL ) {
        free_instruction( instructions->write_actions );
        instructions->write_actions = NULL;
      }
      else {
        ret = ERROR_INVALID_PARAMETER;
      }
    }
    break;

    case OFPIT_APPLY_ACTIONS:
    {
      if ( instructions->apply_actions != NULL ) {
        free_instruction( instructions->apply_actions );
        instructions->apply_actions = NULL;
      }
      else {
        ret = ERROR_INVALID_PARAMETER;
      }
    }
    break;

    case OFPIT_CLEAR_ACTIONS:
    {
      if ( instructions->clear_actions != NULL ) {
        free_instruction( instructions->clear_actions );
        instructions->clear_actions = NULL;
      }
      else {
        ret = ERROR_INVALID_PARAMETER;
      }
    }
    break;

    case OFPIT_METER:
    {
      if ( instructions->meter != NULL ) {
        free_instruction( instructions->meter );
        instructions->goto_table = NULL;
      }
      else {
        ret = ERROR_INVALID_PARAMETER;
      }
    }
    break;

    case OFPIT_EXPERIMENTER:
    {
      error( "OFPIT_EXPERIMENTER is not supported." );
      ret = ERROR_OFDPE_BAD_INSTRUCTION_UNSUP_INST;
    }
    break;

    default:
    {
      error( "Invalid instruction type ( %#x ).", type );
      ret = ERROR_OFDPE_BAD_INSTRUCTION_UNKNOWN_INST;
    }
    break;
  }

  return ret;
}


instruction_set *
duplicate_instruction_set( const instruction_set *instructions ) {
  if ( instructions == NULL ) {
    return NULL;
  }

  instruction_set *duplicated = create_instruction_set();

  if ( instructions->goto_table != NULL ) {
    duplicated->goto_table = duplicate_instruction( instructions->goto_table );
  }
  if ( instructions->write_metadata != NULL ) {
    duplicated->write_metadata = duplicate_instruction( instructions->write_metadata );
  }
  if ( instructions->write_actions != NULL ) {
    duplicated->write_actions = duplicate_instruction( instructions->write_actions );
  }
  if ( instructions->apply_actions != NULL ) {
    duplicated->apply_actions = duplicate_instruction( instructions->apply_actions );
  }
  if ( instructions->clear_actions != NULL ) {
    duplicated->clear_actions = duplicate_instruction( instructions->clear_actions );
  }
  if ( instructions->meter != NULL ) {
    duplicated->meter = duplicate_instruction( instructions->meter );
  }
  if ( instructions->experimenter != NULL ) {
    duplicated->experimenter = duplicate_instruction( instructions->experimenter );
  }

  return duplicated;
}


OFDPE
validate_instruction_goto_table( const instruction *instruction ) {
  assert( instruction != NULL );
  assert( instruction->type == OFPIT_GOTO_TABLE );

  if ( !valid_table_id( instruction->table_id ) ) {
    return ERROR_OFDPE_BAD_INSTRUCTION_BAD_TABLE_ID;
  }

  return OFDPE_SUCCESS;
}


OFDPE
validate_instruction_write_metadata( const instruction *instruction, const uint64_t metadata_range ) {
  assert( instruction != NULL );
  assert( instruction->type == OFPIT_WRITE_METADATA );

  if ( ( instruction->metadata & metadata_range ) != instruction->metadata ) {
    return ERROR_OFDPE_BAD_INSTRUCTION_UNSUP_METADATA;
  }
  if ( ( instruction->metadata_mask & metadata_range ) != instruction->metadata_mask ) {
    return ERROR_OFDPE_BAD_INSTRUCTION_UNSUP_METADATA;
  }

  return OFDPE_SUCCESS;
}


OFDPE
validate_instruction_write_actions( const instruction *instruction ) {
  assert( instruction != NULL );
  assert( instruction->type == OFPIT_WRITE_ACTIONS );

  OFDPE ret = OFDPE_SUCCESS;
  if ( instruction->actions != NULL ) {
    ret = validate_action_list( instruction->actions );
  }

  return ret;
}


OFDPE
validate_instruction_apply_actions( const instruction *instruction ) {
  assert( instruction != NULL );
  assert( instruction->type == OFPIT_APPLY_ACTIONS );

  OFDPE ret = OFDPE_SUCCESS;
  if ( instruction->actions != NULL ) {
    ret = validate_action_list( instruction->actions );
  }

  return ret;
}


OFDPE
validate_instruction_clear_actions( const instruction *instruction ) {
  assert( instruction != NULL );
  assert( instruction->type == OFPIT_CLEAR_ACTIONS );

  OFDPE ret = OFDPE_SUCCESS;
  if ( instruction->actions != NULL ) {
    ret = ERROR_OFDPE_BAD_ACTION_BAD_ARGUMENT;
  }

  return ret;
}


OFDPE
validate_instruction_meter( const instruction *instruction ) {
  assert( instruction != NULL );
  assert( instruction->type == OFPIT_METER );

  if ( instruction->meter_id == 0 || instruction->meter_id > OFPM_MAX ){
    return ERROR_OFDPE_METER_MOD_FAILED_INVALID_METER;
  }

  return OFDPE_SUCCESS;
}


OFDPE
validate_instruction_set( const instruction_set *instructions, const uint64_t metadata_range ) {
  assert( instructions != NULL );

  OFDPE ret = OFDPE_SUCCESS;
  if ( instructions->goto_table != NULL ) {
    ret = validate_instruction_goto_table( instructions->goto_table );
  }
  if ( instructions->write_metadata != NULL ) {
    ret = validate_instruction_write_metadata( instructions->write_metadata, metadata_range );
  }
  if ( instructions->write_actions != NULL ) {
    ret = validate_instruction_write_actions( instructions->write_actions );
  }
  if ( instructions->apply_actions != NULL ) {
    ret = validate_instruction_apply_actions( instructions->apply_actions );
  }
  if ( instructions->clear_actions != NULL ) {
    ret = validate_instruction_clear_actions( instructions->clear_actions );
  }
  if ( instructions->meter != NULL ) {
    ret = validate_instruction_meter( instructions->meter );
  }
  if ( instructions->experimenter != NULL ) {
    warn( "OFPIT_EXPERIMENTER is not supported." );
    ret = ERROR_OFDPE_BAD_INSTRUCTION_UNSUP_INST;
  }

  return ret;
}


static void
update_reference_counters_in_instruction( instruction *instruction, counter_update_type type ) {
  assert( instruction != NULL );

  if ( instruction->actions == NULL ) {
    return;
  }

  for ( dlist_element *a = get_first_element( instruction->actions ); a != NULL; a = a->next ) {
    if ( a->data == NULL ) {
      continue;
    }
    action *action = a->data;
    if ( action->type == OFPAT_GROUP ) {
      if ( type == INCREMENT ) {
        increment_reference_count( action->group_id );
      }
      else if ( type == DECREMENT ) {
        decrement_reference_count( action->group_id );
      }
      else {
        error( "Undefined counter update type ( %#x ).", type );
      }
    }
  }
}


static void
update_reference_counters( instruction_set *instructions, counter_update_type type ) {
  if ( instructions == NULL ) {
    return;
  }

  if ( instructions->meter != NULL ) {
    uint32_t meter_id = instructions->meter->meter_id;
    if ( type == INCREMENT ) {
      if ( OFDPE_SUCCESS != ref_meter_id( meter_id ) ) {
        error( "meter id=%d reference counter increment error", meter_id );
      }
    } else if ( type == DECREMENT ) {
      if ( OFDPE_SUCCESS != unref_meter_id( meter_id ) ) {
        error( "meter id=%d reference counter decrement error", meter_id );
      }
    } else {
      error( "Undefined counter update type ( %#x ).", type );
    }
  }

  if ( instructions->write_actions != NULL ) {
    if ( instructions->write_actions->actions != NULL ) {
      update_reference_counters_in_instruction( instructions->write_actions, type );
    }
  }
  if ( instructions->apply_actions != NULL ) {
    if ( instructions->apply_actions->actions != NULL ) {
      update_reference_counters_in_instruction( instructions->apply_actions, type );
    }
  }
}


void increment_reference_counters_in_groups( instruction_set *instructions ) {
  update_reference_counters( instructions, INCREMENT );
}


void decrement_reference_counters_in_groups( instruction_set *instructions ) {
  update_reference_counters( instructions, DECREMENT );
}


void
dump_instruction_capabilities( const instruction_capabilities capabilities ) {
  print_bitmap( capabilities, INSTRUCTION_GOTO_TABLE, "goto_table" );
  print_bitmap( capabilities, INSTRUCTION_WRITE_METADATA, "write_metadata" );
  print_bitmap( capabilities, INSTRUCTION_WRITE_ACTIONS, "write_actions" );
  print_bitmap( capabilities, INSTRUCTION_APPLY_ACTIONS, "apply_actions" );
  print_bitmap( capabilities, INSTRUCTION_CLEAR_ACTIONS, "clear_actions" );
  print_bitmap( capabilities, INSTRUCTION_METER, "meter" );
  print_bitmap( capabilities, INSTRUCTION_EXPERIMENTER, "experimenter" );
}


static void
dump_instruction_goto_table( const instruction *i, void dump_function( const char *format, ... ) ) {
  assert( i != NULL );
  assert( dump_function != NULL );

  ( *dump_function )( "goto_table: type = %#x, table_id = %#x", i->type, i->table_id );
}


static void
dump_instruction_write_metadata( const instruction *i, void dump_function( const char *format, ... ) ) {
  assert( i != NULL );
  assert( dump_function != NULL );

  ( *dump_function )( "write_metadata: type = %#x, metadata= %#" PRIx64 "/%#" PRIx64,
                      i->type, i->metadata, i->metadata_mask );
}


static void
dump_instruction_write_actions( const instruction *i, void dump_function( const char *format, ... ) ) {
  assert( i != NULL );
  assert( dump_function != NULL );

  ( *dump_function )( "write_actions: type = %#x, actions = %p", i->type, i->actions );
  dump_action_list( i->actions, dump_function );
}


static void
dump_instruction_apply_actions( const instruction *i, void dump_function( const char *format, ... ) ) {
  assert( i != NULL );
  assert( dump_function != NULL );

  ( *dump_function )( "apply_actions: type = %#x, actions = %#x", i->type, i->actions );
  dump_action_list( i->actions, dump_function );
}


static void
dump_instruction_clear_actions( const instruction *i, void dump_function( const char *format, ... ) ) {
  assert( i != NULL );
  assert( dump_function != NULL );

  ( *dump_function )( "clear_actions: type = %#x", i->type );
}


static void
dump_instruction_meter( const instruction *i, void dump_function( const char *format, ... ) ) {
  assert( i != NULL );
  assert( dump_function != NULL );

  ( *dump_function )( "meter: type = %#x, meter_id = %#x", i->type, i->meter_id );
}


static void
dump_instruction_experimenter( const instruction *i, void dump_function( const char *format, ... ) ) {
  assert( i != NULL );
  assert( dump_function != NULL );

  ( *dump_function )( "experimenter: type = %#x", i->type );
}


void
dump_instruction_set( const instruction_set *instructions, void dump_function( const char *format, ... ) ) {
  assert( instructions != NULL );
  assert( dump_function != NULL );

  if ( instructions->goto_table != NULL ) {
    dump_instruction_goto_table( instructions->goto_table, dump_function );
  }
  if ( instructions->write_metadata != NULL ) {
    dump_instruction_write_metadata( instructions->write_metadata, dump_function );
  }
  if ( instructions->write_actions != NULL ) {
    dump_instruction_write_actions( instructions->write_actions, dump_function );
  }
  if ( instructions->apply_actions != NULL ) {
    dump_instruction_apply_actions( instructions->apply_actions, dump_function );
  }
  if ( instructions->clear_actions != NULL ) {
    dump_instruction_clear_actions( instructions->clear_actions, dump_function );
  }
  if ( instructions->meter != NULL ) {
    dump_instruction_meter( instructions->meter, dump_function );
  }
  if ( instructions->experimenter != NULL ) {
    dump_instruction_experimenter( instructions->experimenter, dump_function );
  }
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
