/*
 * Ethernet header definitions
 *
 * Author: Kazuya Suzuki
 *
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


#ifndef ETHER_H
#define ETHER_H


#include <stdint.h>
#include "bool.h"
#include "buffer.h"


#define ETH_ADDRLEN 6
#define ETH_FCS_LENGTH 4
#define ETH_MINIMUM_LENGTH 64
#define ETH_MAXIMUM_LENGTH 1518
#define ETH_HDR_LENGTH sizeof( ether_header_t )
#define ETH_MTU ( ETH_MAXIMUM_LENGTH - ETH_HDR_LENGTH - ETH_FCS_LENGTH )


//Ethernet payload types
#define ETH_ETHTYPE_8023 0x05dc
#define ETH_ETHTYPE_IPV4 0x0800
#define ETH_ETHTYPE_ARP 0x0806
#define ETH_ETHTYPE_TPID 0x8100
#define ETH_ETHTYPE_TPID1 0x88a8
#define ETH_ETHTYPE_TPID2 0x9100
#define ETH_ETHTYPE_TPID3 0x9200
#define ETH_ETHTYPE_TPID4 0x9300
#define ETH_ETHTYPE_PBB 0x88e7
#define ETH_ETHTYPE_IPV6 0x86DD
#define ETH_ETHTYPE_EAPOL 0x88c7
#define ETH_ETHTYPE_LLDP 0x88cc
#define ETH_ETHTYPE_MPLS_UNI 0x8847
#define ETH_ETHTYPE_MPLS_MLT 0x8848
#define ETH_ETHTYPE_UKNOWN 0xffff

#pragma pack(1)

typedef struct ether_headr {
  uint8_t macda[ ETH_ADDRLEN ];
  uint8_t macsa[ ETH_ADDRLEN ];
  uint16_t type;
} ether_header_t;


typedef struct vlantag_header {
  uint16_t tci;
  uint16_t type;
} vlantag_header_t;


// 802.1ah I-TAG TCI + payload ethertype
typedef struct pbb_header {
  uint32_t isid;
  uint8_t cda[ ETH_ADDRLEN ];
  uint8_t csa[ ETH_ADDRLEN ];
  uint16_t type;
} pbb_header_t;


typedef struct snap_header {
  uint8_t llc[ 3 ];
  uint8_t oui[ 3 ];
  uint16_t type;
} snap_header_t;

#pragma pack()

#define TCI_GET_PRIO( _tci ) ( uint8_t )( ( ( _tci ) >> 13 ) & 7 )

#define TCI_GET_CFI( _tci ) ( uint8_t )( ( ( _tci ) >> 12 ) & 1 )

#define TCI_GET_VID( _tci ) ( uint16_t )( ( _tci ) & 0x0FFF )

#define TCI_CREATE( _prio, _cfi, _vid )         \
  ( uint16_t )( ( ( ( _prio ) & 7 ) << 13 ) |   \
                ( ( ( _cfi ) & 1 ) << 12 ) |    \
                ( ( _vid ) & 0x0FFF ) ) 

uint16_t fill_ether_padding( buffer *buf );


#endif // ETHER_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
