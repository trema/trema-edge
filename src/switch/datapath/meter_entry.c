#include "meter_entry.h"

meter_entry *
alloc_meter_entry( const uint16_t flags, const uint32_t meter_id, const list_element *bands ) {
  meter_band *bands_array = NULL;
  unsigned int bands_count = list_length_of( bands );
  if ( bands_count > 0 ) {
    bands_array = xcalloc( bands_count, sizeof( meter_entry ) );
    
    int i=0;
    for ( const list_element *e = bands; e != NULL; e = e->next, i++ ) {
      struct ofp_meter_band_header *band = e->data;
      meter_band *target = bands_array+i;
      target->type = band->type;
      target->rate = band->rate;
      target->burst_size = band->burst_size;
      if (band->type == OFPMBT_DSCP_REMARK ){
        target->prec_level = ((struct ofp_meter_band_dscp_remark *)band)->prec_level;
      }
    }
  }
  meter_entry *entry = xcalloc( 1, sizeof( meter_entry ) );

  entry->meter_id = meter_id;
  entry->flags = flags;
  entry->bands_count = bands_count;
  entry->bands = bands_array;
  struct timespec now = { 0, 0 };
  time_now( &now );
  entry->created_at = now;
  entry->meter_at = now;
  
  return entry;
}


meter_entry*
clone_meter_entry( meter_entry *dst, const meter_entry *src ){
  if ( dst == NULL ) {
    dst = xcalloc( 1, sizeof(meter_entry) );
  }
  memcpy( dst, src, sizeof(meter_entry) );
  if ( src->bands_count > 0 ) {
    dst->bands = xcalloc( src->bands_count, sizeof(meter_band) );
    for ( unsigned int i=0; i<src->bands_count; i++ ) {
      memcpy( dst->bands+i, src->bands+i, sizeof(meter_band) );
    }
  }
  return dst;
}


void
free_meter_entry( meter_entry *entry ) {
  assert( entry != NULL );

  if ( entry->bands_count > 0 ) {
    xfree( entry->bands );
  }
  xfree( entry );
}

