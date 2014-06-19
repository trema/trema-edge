#include "ofdp_common.h"

void ( *handle_meter_mod_add )( const uint32_t transaction_id, const uint16_t flags, const uint32_t meter_id, const list_element *bands );
void ( *handle_meter_mod_mod )( const uint32_t transaction_id, const uint16_t flags, const uint32_t meter_id, const list_element *bands );
void ( *handle_meter_mod_delete )( const uint32_t transaction_id, const uint32_t meter_id );
