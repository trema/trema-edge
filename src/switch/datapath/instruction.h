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


#ifndef INSTRUCTION_H
#define INSTRUCTION_H


#include "ofdp_common.h"
#include "action.h"


enum {
  INSTRUCTION_GOTO_TABLE = 1ULL << OFPIT_GOTO_TABLE,
  INSTRUCTION_WRITE_METADATA = 1ULL << OFPIT_WRITE_METADATA,
  INSTRUCTION_WRITE_ACTIONS = 1ULL << OFPIT_WRITE_ACTIONS,
  INSTRUCTION_APPLY_ACTIONS = 1ULL << OFPIT_APPLY_ACTIONS,
  INSTRUCTION_CLEAR_ACTIONS = 1ULL << OFPIT_CLEAR_ACTIONS,
  INSTRUCTION_METER = 1ULL << OFPIT_METER,
  INSTRUCTION_EXPERIMENTER = 1ULL << 63, // OFPIT_EXPERIMENTER is 0xffff
};


typedef uint64_t instruction_capabilities;

typedef struct {
  uint16_t type;
  uint8_t table_id;
  uint64_t metadata;
  uint64_t metadata_mask;
  uint32_t meter_id;
  action_list *actions;
} instruction;

typedef struct {
  instruction *goto_table;
  instruction *write_metadata;
  instruction *write_actions;
  instruction *apply_actions;
  instruction *clear_actions;
  instruction *meter;
  instruction *experimenter;
} instruction_set;


instruction *alloc_instruction_goto_table( const uint8_t table_id );
instruction *alloc_instruction_write_metadata( const uint64_t metadata, const uint64_t metadata_mask );
instruction *alloc_instruction_write_actions( action_list *action );
instruction *alloc_instruction_apply_actions( action_list *action );
instruction *alloc_instruction_clear_actions( void );
instruction *alloc_instruction_meter( const uint32_t meter_id );
void free_instruction( instruction *instruction );
instruction *duplicate_instruction( const instruction *instruction );

instruction_set *create_instruction_set();
#define create_instructions create_instruction_set
void delete_instruction_set( instruction_set *instructions );
#define delete_instructions delete_instruction_set
OFDPE add_instruction( instruction_set *instructions, instruction *instruction );
OFDPE delete_instruction( instruction_set *instructions, const uint16_t type );
instruction_set *duplicate_instruction_set( const instruction_set *instructions );
#define duplicate_instructions duplicate_instruction_set

OFDPE validate_instruction_goto_table( const instruction *instruction );
OFDPE validate_instruction_write_metadata( const instruction *instruction, const uint64_t metadata_range );
OFDPE validate_instruction_write_actions( const instruction *instruction );
OFDPE validate_instruction_apply_actions( const instruction *instruction );
OFDPE validate_instruction_clear_actions( const instruction *instruction );
OFDPE validate_instruction_meter( const instruction *instruction );
OFDPE validate_instruction_set( const instruction_set *instructions, const uint64_t metadata_range );

void increment_reference_counters_in_groups( instruction_set *instructions );
void decrement_reference_counters_in_groups( instruction_set *instructions );

void dump_instruction_capabilities( const instruction_capabilities capabilities );
void dump_instruction_set( const instruction_set *instructions, void dump_function( const char *format, ... ) );


#endif // INSTRUCTION_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/
