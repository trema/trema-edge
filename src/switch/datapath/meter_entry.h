#ifndef METER_ENTRY_H
#define METER_ENTRY_H

#include "ofdp_common.h"

typedef struct {
  uint16_t type; // OFPMBT_
  uint32_t rate;
  uint32_t burst_size;
  // only used with OFPMBT_DSCP_REMARK
  uint8_t prec_level;
  // bucket will be refreshed per sec
  uint64_t bucket;
  uint64_t packet_count;
  uint64_t byte_count;
} meter_band;

typedef struct {
  uint32_t meter_id;
  uint16_t flags;
  size_t bands_count;
  meter_band *bands;
  
  uint32_t ref_count;
  uint64_t packet_count;
  uint64_t byte_count;
  struct timespec created_at;
  struct timespec meter_at;
  // packets/sec if flags & OFPMF_PKTPS
  // bits/sec otherwise
  double estimated_rate;
} meter_entry;

meter_entry* alloc_meter_entry( const uint16_t flags, const uint32_t meter_id, const list_element *bands );
void free_meter_entry( meter_entry *entry );
meter_entry* clone_meter_entry( meter_entry *dst, const meter_entry *src );

#endif // METER_ENTRY_H
