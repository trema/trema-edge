#include "meter-helper.h"
#include "meter_table.h"
#include "openflow_helper.h"

static void
_handle_meter_mod_add( const uint32_t transaction_id, const uint16_t flags, const uint32_t meter_id, const list_element *bands ){
  OFDPE ret = add_meter_entry( flags, meter_id, bands );
  if ( ret != OFDPE_SUCCESS ) {
    uint16_t type, code;
    if ( get_ofp_error( ret, &type, &code ) == true ) {
      send_error_message( transaction_id, type, code );
    } else {
      send_error_message( transaction_id, OFPET_METER_MOD_FAILED, OFPMMFC_UNKNOWN );
    }
  }
}
void ( *handle_meter_mod_add )( const uint32_t transaction_id, const uint16_t flags, const uint32_t meter_id, const list_element *bands )  = _handle_meter_mod_add;


static void
_handle_meter_mod_mod( const uint32_t transaction_id, const uint16_t flags, const uint32_t meter_id, const list_element *bands ){
  OFDPE ret = replace_meter_entry( flags, meter_id, bands );
  if ( ret != OFDPE_SUCCESS ) {
    uint16_t type, code;
    if ( get_ofp_error( ret, &type, &code ) == true ) {
      send_error_message( transaction_id, type, code );
    } else {
      send_error_message( transaction_id, OFPET_METER_MOD_FAILED, OFPMMFC_UNKNOWN );
    }
  }
}
void ( *handle_meter_mod_mod )( const uint32_t transaction_id, const uint16_t flags, const uint32_t meter_id, const list_element *bands ) = _handle_meter_mod_mod;

static void
_handle_meter_mod_delete( const uint32_t transaction_id, const uint32_t meter_id ){
  OFDPE ret = delete_meter_entry( meter_id );
  if ( ret != OFDPE_SUCCESS ) {
    uint16_t type, code;
    if ( get_ofp_error( ret, &type, &code ) == true ) {
      send_error_message( transaction_id, type, code );
    } else {
      send_error_message( transaction_id, OFPET_METER_MOD_FAILED, OFPMMFC_UNKNOWN );
    }
  }
}
void ( *handle_meter_mod_delete )( const uint32_t transaction_id, const uint32_t meter_id ) = _handle_meter_mod_delete;
