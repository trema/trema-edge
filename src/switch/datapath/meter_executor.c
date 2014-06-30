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
  
  struct timespec now;
  time_now( &now );
  struct timespec interval;
  timespec_diff( entry->meter_at, now, &interval);
  entry->meter_at = now;
  double interval_sec = (double)interval.tv_sec + (double)interval.tv_nsec/1000000000.0;
  
  uint64_t rate_size = frame->length * 8; // bits
  if ( entry->flags & OFPMF_PKTPS ) {
    rate_size = 1;
  }
  
  int selected_burst_band = -1;
  int selected_rate_band = -1;
  
  if ( entry->flags & OFPMF_BURST ) {
    // drain
    for( unsigned int i=0; i<entry->bands_count; i++ ) {
      uint64_t drain = ( uint64_t )( interval_sec * entry->bands[i].rate );
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
  
  packet_info *info = NULL;
  if ( frame->user_data != NULL || parse_packet( frame ) == true) {
    info = frame->user_data;
  }
  
  // select band
  double passing_rate = ( BASE_INTERVAL * entry->estimated_rate + ( double ) rate_size ) / ( interval_sec + BASE_INTERVAL );
  uint16_t rate_for_select_max = 0;
  for( unsigned int i=0; i<entry->bands_count; i++ ) {
    if ( entry->bands[i].type == OFPMBT_DSCP_REMARK ) {
      if( info == NULL || ( info->format & (NW_IPV4|NW_IPV6) ) == 0 ) {
        continue;
      }
    }
    if ( ( entry->flags & OFPMF_BURST ) != 0 && selected_burst_band == -1 ) {
      uint64_t burst_size = entry->bands[i].burst_size;
      if ( ( entry->flags & OFPMF_PKTPS ) != OFPMF_PKTPS ) {
        burst_size = burst_size * 1000; // kilobits; we compare in bits
      }
      if ( burst_size < entry->bands[i].bucket + rate_size ) {
        selected_burst_band = ( int ) i;
        debug("burst hit %d %d", burst_size, entry->bands[i].bucket + rate_size);
      }
    }
    
    uint32_t rate = entry->bands[i].rate;
    if ( ( entry->flags & OFPMF_PKTPS ) != OFPMF_PKTPS ) {
      rate = rate * 1000; // kilobits; we compare in bits
    }
    if ( rate < passing_rate ) {
      if ( rate_for_select_max < rate ) {
        selected_rate_band = ( int ) i;
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
      if ( band->prec_level > 0 && info != NULL ) {
        uint8_t phb = info->ip_dscp >> 3;
        uint8_t prec = ( info->ip_dscp >> 1 ) & 0x03;
        if ( prec != 0 && ( phb == 1 || phb == 2 || phb == 3 || phb == 4 ) ) { // AF classes
          prec = ( uint8_t ) ( prec + band->prec_level );
          if ( prec > 0x03 ) {
            prec = 0x03;
          }
          if ( set_nw_dscp( frame, ( uint8_t ) ((phb<<3)|(prec<<1)) ) == false ){
            error("DSCP remark failed");
          }
        }
      }
    }
    band->packet_count++;
    band->byte_count += frame->length;

    entry->estimated_rate = ( BASE_INTERVAL * entry->estimated_rate ) / ( interval_sec + BASE_INTERVAL );
  } else {
    entry->estimated_rate = passing_rate;
  }
  if ( entry->flags & OFPMF_BURST ) {
    // update bucket
    if ( selected_burst_band == -1 ) {
      for( unsigned int i=0; i<entry->bands_count; i++ ) {
        if ( entry->bands[i].bucket > UINT64_MAX - rate_size ) {
          entry->bands[i].bucket = UINT64_MAX;
        } else {
          entry->bands[i].bucket += rate_size;
        }
      }
    }
  }
  if ( do_drop ) {
    return ERROR_DROP_PACKET;
  } else {
    return OFDPE_SUCCESS;
  }
}
