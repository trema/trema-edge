#include "meter_executor.h"
#include "meter_table.h"
#include "action_executor.h"

#define BASE_INTERVAL 2.0

OFDPE
execute_meter( uint32_t meter_id, buffer *frame ) {
  assert( frame != NULL );
  meter_entry *entry = lookup_meter_entry( meter_id );
  if ( entry == NULL ) {
    return ERROR_NOT_FOUND;
  }
  entry->packet_count++;
  entry->byte_count += frame->length;
  
  struct timespec now = { 0, 0 };
  time_now( &now );
  struct timespec interval = { 0, 0 };
  timespec_diff( entry->meter_at, now, &interval);
  entry->meter_at = now;
  double interval_sec = interval.tv_sec + interval.tv_nsec/1000000000.0;
  
  uint64_t rate_size = frame->length * 8; // bits
  if ( entry->flags & OFPMF_PKTPS ) {
    rate_size = 1;
  }
  
  int selected_burst_band = -1;
  int selected_rate_band = -1;
  
  if ( entry->flags & OFPMF_BURST ) {
    // drain
    for( int i=0; i<entry->bands_count; i++ ) {
      uint64_t drain = interval_sec * entry->bands[i].rate;
      if ( ( entry->flags & OFPMF_PKTPS ) != OFPMF_PKTPS ) {
        drain = drain * 1000; // kilobits; we compare in bits
      }
      if ( entry->bands[i].bucket < drain ) {
        entry->bands[i].bucket = 0;
      } else {
        entry->bands[i].bucket -= drain;
      }
    }
  }
  
  // select band
  double passing_rate = ( BASE_INTERVAL * entry->estimated_rate + rate_size ) / ( interval_sec + BASE_INTERVAL );
  uint16_t rate_for_select_max = 0;
  for( int i=0; i<entry->bands_count; i++ ) {
    if ( !packet_type_ipv4( frame ) && !packet_type_ipv6( frame ) && entry->bands[i].type == OFPMBT_DSCP_REMARK ){
      continue;
    }
    if ( ( entry->flags & OFPMF_BURST ) != 0 && selected_burst_band == -1 ) {
      uint64_t burst_size = entry->bands[i].burst_size;
      if ( ( entry->flags & OFPMF_PKTPS ) != OFPMF_PKTPS ) {
        burst_size = burst_size * 1000; // kilobits; we compare in bits
      }
      if ( burst_size < entry->bands[i].bucket + rate_size ) {
        selected_burst_band = i;
        debug("burst hit %d %d", burst_size, entry->bands[i].bucket + rate_size);
      }
    }
    
    uint32_t rate = entry->bands[i].rate;
    if ( ( entry->flags & OFPMF_PKTPS ) != OFPMF_PKTPS ) {
      rate = rate * 1000; // kilobits; we compare in bits
    }
    if ( rate < passing_rate ) {
      if ( rate_for_select_max < rate ) {
        selected_rate_band = i;
        debug("rate hit %d %f", rate, passing_rate);
      }
    }
  }
  // apply
  bool do_drop = false;
  meter_band *band = NULL;
  if ( selected_burst_band != -1 ) {
    band = entry->bands + selected_burst_band;
  } else if ( selected_rate_band != -1 ) {
    band = entry->bands + selected_rate_band;
  }
  if ( band != NULL ) {
    if ( band->type == OFPMBT_DROP ) {
      do_drop = true;
    } else if ( band->type == OFPMBT_DSCP_REMARK ) {
      packet_info info = get_packet_info( frame );
      uint8_t phb = info.ip_dscp >> 3;
      if ( phb == 1 || phb == 2 || phb == 3 ) { // AF classes
        uint8_t prec = ( info.ip_dscp & 0x07 ) + band->prec_level;
        if ( prec > 0x07 ) {
          prec = 0x07;
        }
        if ( set_nw_dscp( frame, (phb<<3)|prec ) == false ){
          error("DSCP remark failed");
        }
      }
    }
    band->packet_count++;
    band->byte_count += frame->length;
  }
  
  if ( entry->flags & OFPMF_BURST ) {
    // update bucket
    if ( false == do_drop ) {
      for( int i=0; i<entry->bands_count; i++ ) {
        if ( entry->bands[i].bucket > UINT64_MAX - rate_size ) {
          entry->bands[i].bucket = UINT64_MAX;
        } else {
          entry->bands[i].bucket += rate_size;
        }
      }
    }
  }
  
  if ( do_drop ) {
    entry->estimated_rate = ( BASE_INTERVAL * entry->estimated_rate ) / ( interval_sec + BASE_INTERVAL );
    return ERROR_DROP_PACKET;
  } else {
    entry->estimated_rate = passing_rate;
    return OFDPE_SUCCESS;
  }
}
