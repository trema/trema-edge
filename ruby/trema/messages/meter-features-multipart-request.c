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


#include "trema.h"
#include "ruby.h"
#include "hash-util.h"


buffer *
pack_meter_features_multipart_request( VALUE options ) {
  uint32_t xid = get_transaction_id();
  VALUE r_xid = HASH_REF( options, transaction_id );
  if ( !NIL_P( r_xid ) ) {
    xid = NUM2UINT( r_xid );
  }

  uint16_t flags = 0;
  VALUE r_flags = HASH_REF( options, flags );
  if ( !NIL_P( r_flags ) ) {
    flags = ( uint16_t ) NUM2UINT( r_flags );
  }
  buffer *meter_features_multipart_request = create_meter_features_multipart_request( xid, flags );
  return meter_features_multipart_request;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
