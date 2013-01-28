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
#include <stdlib.h>
#include "trema.h"
#include "ofdp.h"
#include "instruction-goto-table.h"
#include "switch-instruction.h"


static struct instruction **instruction_arr;
static uint32_t nr_instruction;
static uint32_t instruction_alloc;


void
register_instruction( struct instruction *instruction ) {
  ALLOC_GROW( instruction_arr, nr_instruction + 1, instruction_alloc );
  instruction_arr[ nr_instruction++ ] = instruction;
}


void
init_instruction( void ) {
  init_instruction_goto_table();
}


uint16_t
instruction_length( const uint16_t type ) {
  for ( uint32_t i = 0; i < nr_instruction; i++ ) {
    if ( instruction_arr[ i ]->type == type ) {
      return instruction_arr[ i ]->len;
    }
  }
  return 0;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
