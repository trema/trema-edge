#ifndef METER_TABLE_H
#define METER_TABLE_H

#include "ofdp_common.h"
#include "meter_entry.h"

typedef struct {
  bool initialized;
  list_element *entries;
} meter_table;


void init_meter_table( void );
void finalize_meter_table( void );
OFDPE add_meter_entry( const uint16_t flags, const uint32_t meter_id, const list_element *bands );
OFDPE replace_meter_entry( const uint16_t flags, const uint32_t meter_id, const list_element *bands );
OFDPE delete_meter_entry( const uint32_t meter_id );
meter_entry* lookup_meter_entry( const uint32_t meter_id );
OFDPE ref_meter_id( const uint32_t );
OFDPE unref_meter_id( const uint32_t );
OFDPE get_meter_stats( const uint32_t meter_id, meter_entry **entries, uint32_t *count );

#endif // METER_TABLE_H
