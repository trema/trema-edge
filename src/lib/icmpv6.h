/*
 * ICMPv6 header definitions
 *
 * Author: SUGYO Kazushi
 *
 * Copyright (C) 2013 NEC Corporation
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


#ifndef ICMPV6_H
#define ICMPV6_H

#include "ether.h"
#include "ipv6.h"


typedef struct icmpv6_header {
  uint8_t type;
  uint8_t code;
  uint16_t csum;
  uint8_t data[0];
} icmpv6_header_t;


typedef struct icmpv6data_ndp {
  uint32_t reserved;
  uint8_t nd_target[ IPV6_ADDRLEN ];
  uint8_t ll_type;
  uint8_t length;
  uint8_t ll_addr[ ETH_ADDRLEN ];
} icmpv6data_ndp_t;


#define ICMPV6_TYPE_NEIGHBOR_SOL 135
#define ICMPV6_TYPE_NEIGHBOR_ADV 136
#define ICMPV6_ND_SOURCE_LINK_LAYER_ADDRESS 1
#define ICMPV6_ND_TARGET_LINK_LAYER_ADDRESS 2


#endif // ICMPV6_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
