/*
 * Copyright (C) 2012-2013 NEC Corporation
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


#include "ofdp_common.h"
#include "openflow_helper.h"


typedef struct {
  OFDPE error_code;
  uint16_t type;
  uint16_t code;
} error_map;


static error_map error_maps[] = {
  { ERROR_OFDPE_HELLO_FAILED_INCOMPATIBLE, OFPET_HELLO_FAILED, OFPHFC_INCOMPATIBLE },
  { ERROR_OFDPE_HELLO_FAILED_EPERM, OFPET_HELLO_FAILED, OFPHFC_EPERM },

  { ERROR_OFDPE_BAD_REQUEST_BAD_VERSION, OFPET_BAD_REQUEST, OFPBRC_BAD_VERSION },
  { ERROR_OFDPE_BAD_REQUEST_BAD_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE },
  { ERROR_OFDPE_BAD_REQUEST_BAD_MULTIPART, OFPET_BAD_REQUEST, OFPBRC_BAD_MULTIPART },
  { ERROR_OFDPE_BAD_REQUEST_BAD_EXPERIMENTER, OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER },
  { ERROR_OFDPE_BAD_REQUEST_BAD_EXP_TYPE, OFPET_BAD_REQUEST, OFPBRC_BAD_EXP_TYPE },
  { ERROR_OFDPE_BAD_REQUEST_EPERM, OFPET_BAD_REQUEST, OFPBRC_EPERM },
  { ERROR_OFDPE_BAD_REQUEST_BAD_LEN, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN },
  { ERROR_OFDPE_BAD_REQUEST_BUFFER_EMPTY, OFPET_BAD_REQUEST, OFPBRC_BUFFER_EMPTY },
  { ERROR_OFDPE_BAD_REQUEST_BUFFER_UNKNOWN, OFPET_BAD_REQUEST, OFPBRC_BUFFER_UNKNOWN },
  { ERROR_OFDPE_BAD_REQUEST_BAD_TABLE_ID, OFPET_BAD_REQUEST, OFPBRC_BAD_TABLE_ID },
  { ERROR_OFDPE_BAD_REQUEST_IS_SLAVE, OFPET_BAD_REQUEST, OFPBRC_IS_SLAVE },
  { ERROR_OFDPE_BAD_REQUEST_BAD_PORT, OFPET_BAD_REQUEST, OFPBRC_BAD_PORT },
  { ERROR_OFDPE_BAD_REQUEST_BAD_PACKET, OFPET_BAD_REQUEST, OFPBRC_BAD_PACKET },
  { ERROR_OFDPE_BAD_REQUEST_MULTIPART_BUFFER_OVERFLOW, OFPET_BAD_REQUEST, OFPBRC_MULTIPART_BUFFER_OVERFLOW },

  { ERROR_OFDPE_BAD_ACTION_BAD_TYPE, OFPET_BAD_ACTION, OFPBAC_BAD_TYPE },
  { ERROR_OFDPE_BAD_ACTION_BAD_LEN, OFPET_BAD_ACTION, OFPBAC_BAD_LEN },
  { ERROR_OFDPE_BAD_ACTION_BAD_EXPERIMENTER, OFPET_BAD_ACTION, OFPBAC_BAD_EXPERIMENTER },
  { ERROR_OFDPE_BAD_ACTION_BAD_EXP_TYPE, OFPET_BAD_ACTION, OFPBAC_BAD_EXP_TYPE },
  { ERROR_OFDPE_BAD_ACTION_BAD_OUT_PORT, OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT },
  { ERROR_OFDPE_BAD_ACTION_BAD_ARGUMENT, OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT },
  { ERROR_OFDPE_BAD_ACTION_EPERM, OFPET_BAD_ACTION, OFPBAC_EPERM },
  { ERROR_OFDPE_BAD_ACTION_TOO_MANY, OFPET_BAD_ACTION, OFPBAC_TOO_MANY },
  { ERROR_OFDPE_BAD_ACTION_BAD_QUEUE, OFPET_BAD_ACTION, OFPBAC_BAD_QUEUE },
  { ERROR_OFDPE_BAD_ACTION_BAD_OUT_GROUP, OFPET_BAD_ACTION, OFPBAC_BAD_OUT_GROUP },
  { ERROR_OFDPE_BAD_ACTION_MATCH_INCONSISTENT, OFPET_BAD_ACTION, OFPBAC_MATCH_INCONSISTENT },
  { ERROR_OFDPE_BAD_ACTION_UNSUPPORTED_ORDER, OFPET_BAD_ACTION, OFPBAC_UNSUPPORTED_ORDER },
  { ERROR_OFDPE_BAD_ACTION_BAD_TAG, OFPET_BAD_ACTION, OFPBAC_BAD_TAG },
  { ERROR_OFDPE_BAD_ACTION_BAD_SET_TYPE, OFPET_BAD_ACTION, OFPBAC_BAD_SET_TYPE },
  { ERROR_OFDPE_BAD_ACTION_BAD_SET_LEN, OFPET_BAD_ACTION, OFPBAC_BAD_SET_LEN },
  { ERROR_OFDPE_BAD_ACTION_BAD_SET_ARGUMENT, OFPET_BAD_ACTION, OFPBAC_BAD_SET_ARGUMENT },

  { ERROR_OFDPE_BAD_INSTRUCTION_UNKNOWN_INST, OFPET_BAD_INSTRUCTION, OFPBIC_UNKNOWN_INST },
  { ERROR_OFDPE_BAD_INSTRUCTION_UNSUP_INST, OFPET_BAD_INSTRUCTION, OFPBIC_UNSUP_INST },
  { ERROR_OFDPE_BAD_INSTRUCTION_BAD_TABLE_ID, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_TABLE_ID },
  { ERROR_OFDPE_BAD_INSTRUCTION_UNSUP_METADATA, OFPET_BAD_INSTRUCTION, OFPBIC_UNSUP_METADATA },
  { ERROR_OFDPE_BAD_INSTRUCTION_UNSUP_METADATA_MASK, OFPET_BAD_INSTRUCTION, OFPBIC_UNSUP_METADATA_MASK },
  { ERROR_OFDPE_BAD_INSTRUCTION_BAD_EXPERIMENTER, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_EXPERIMENTER },
  { ERROR_OFDPE_BAD_INSTRUCTION_BAD_EXP_TYPE, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_EXP_TYPE },
  { ERROR_OFDPE_BAD_INSTRUCTION_BAD_LEN, OFPET_BAD_INSTRUCTION, OFPBIC_BAD_LEN },
  { ERROR_OFDPE_BAD_INSTRUCTION_EPERM, OFPET_BAD_INSTRUCTION, OFPBIC_EPERM },

  { ERROR_OFDPE_BAD_MATCH_BAD_TYPE, OFPET_BAD_MATCH, OFPBMC_BAD_TYPE },
  { ERROR_OFDPE_BAD_MATCH_BAD_LEN, OFPET_BAD_MATCH, OFPBMC_BAD_LEN },
  { ERROR_OFDPE_BAD_MATCH_BAD_TAG, OFPET_BAD_MATCH, OFPBMC_BAD_TAG },
  { ERROR_OFDPE_BAD_MATCH_BAD_DL_ADDR_MASK, OFPET_BAD_MATCH, OFPBMC_BAD_DL_ADDR_MASK },
  { ERROR_OFDPE_BAD_MATCH_BAD_NW_ADDR_MASK, OFPET_BAD_MATCH, OFPBMC_BAD_NW_ADDR_MASK },
  { ERROR_OFDPE_BAD_MATCH_BAD_WILDCARDS, OFPET_BAD_MATCH, OFPBMC_BAD_WILDCARDS },
  { ERROR_OFDPE_BAD_MATCH_BAD_FIELD, OFPET_BAD_MATCH, OFPBMC_BAD_FIELD },
  { ERROR_OFDPE_BAD_MATCH_BAD_VALUE, OFPET_BAD_MATCH, OFPBMC_BAD_VALUE },
  { ERROR_OFDPE_BAD_MATCH_BAD_MASK, OFPET_BAD_MATCH, OFPBMC_BAD_MASK },
  { ERROR_OFDPE_BAD_MATCH_BAD_PREREQ, OFPET_BAD_MATCH, OFPBMC_BAD_PREREQ },
  { ERROR_OFDPE_BAD_MATCH_DUP_FIELD, OFPET_BAD_MATCH, OFPBMC_DUP_FIELD },
  { ERROR_OFDPE_BAD_MATCH_EPERM, OFPET_BAD_MATCH, OFPBMC_EPERM },

  { ERROR_OFDPE_FLOW_MOD_FAILED_UNKNOWN, OFPET_FLOW_MOD_FAILED, OFPFMFC_UNKNOWN },
  { ERROR_OFDPE_FLOW_MOD_FAILED_TABLE_FULL, OFPET_FLOW_MOD_FAILED, OFPFMFC_TABLE_FULL },
  { ERROR_OFDPE_FLOW_MOD_FAILED_BAD_TABLE_ID, OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_TABLE_ID },
  { ERROR_OFDPE_FLOW_MOD_FAILED_OVERLAP, OFPET_FLOW_MOD_FAILED, OFPFMFC_OVERLAP },
  { ERROR_OFDPE_FLOW_MOD_FAILED_EPERM, OFPET_FLOW_MOD_FAILED, OFPFMFC_EPERM },
  { ERROR_OFDPE_FLOW_MOD_FAILED_BAD_TIMEOUT, OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_TIMEOUT },
  { ERROR_OFDPE_FLOW_MOD_FAILED_BAD_COMMAND, OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_COMMAND },
  { ERROR_OFDPE_FLOW_MOD_FAILED_BAD_FLAGS, OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_FLAGS },

  { ERROR_OFDPE_GROUP_MOD_FAILED_GROUP_EXISTS, OFPET_GROUP_MOD_FAILED, OFPGMFC_GROUP_EXISTS },
  { ERROR_OFDPE_GROUP_MOD_FAILED_INVALID_GROUP, OFPET_GROUP_MOD_FAILED, OFPGMFC_INVALID_GROUP },
  { ERROR_OFDPE_GROUP_MOD_FAILED_WEIGHT_UNSUPPORTED, OFPET_GROUP_MOD_FAILED, OFPGMFC_WEIGHT_UNSUPPORTED },
  { ERROR_OFDPE_GROUP_MOD_FAILED_OUT_OF_GROUPS, OFPET_GROUP_MOD_FAILED, OFPGMFC_OUT_OF_GROUPS },
  { ERROR_OFDPE_GROUP_MOD_FAILED_OUT_OF_BUCKETS, OFPET_GROUP_MOD_FAILED, OFPGMFC_OUT_OF_BUCKETS },
  { ERROR_OFDPE_GROUP_MOD_FAILED_CHAINING_UNSUPPORTED, OFPET_GROUP_MOD_FAILED, OFPGMFC_CHAINING_UNSUPPORTED },
  { ERROR_OFDPE_GROUP_MOD_FAILED_WATCH_UNSUPPORTED, OFPET_GROUP_MOD_FAILED, OFPGMFC_WATCH_UNSUPPORTED },
  { ERROR_OFDPE_GROUP_MOD_FAILED_LOOP, OFPET_GROUP_MOD_FAILED, OFPGMFC_LOOP },
  { ERROR_OFDPE_GROUP_MOD_FAILED_UNKNOWN_GROUP, OFPET_GROUP_MOD_FAILED, OFPGMFC_UNKNOWN_GROUP },
  { ERROR_OFDPE_GROUP_MOD_FAILED_CHAINED_GROUP, OFPET_GROUP_MOD_FAILED, OFPGMFC_CHAINED_GROUP },
  { ERROR_OFDPE_GROUP_MOD_FAILED_BAD_TYPE, OFPET_GROUP_MOD_FAILED, OFPGMFC_BAD_TYPE },
  { ERROR_OFDPE_GROUP_MOD_FAILED_BAD_COMMAND, OFPET_GROUP_MOD_FAILED, OFPGMFC_BAD_COMMAND },
  { ERROR_OFDPE_GROUP_MOD_FAILED_BAD_BUCKET, OFPET_GROUP_MOD_FAILED, OFPGMFC_BAD_BUCKET },
  { ERROR_OFDPE_GROUP_MOD_FAILED_BAD_WATCH, OFPET_GROUP_MOD_FAILED, OFPGMFC_BAD_WATCH },
  { ERROR_OFDPE_GROUP_MOD_FAILED_EPERM, OFPET_GROUP_MOD_FAILED, OFPGMFC_EPERM },

  { ERROR_OFDPE_PORT_MOD_FAILED_BAD_PORT, OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_PORT },
  { ERROR_OFDPE_PORT_MOD_FAILED_BAD_HW_ADDR, OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_HW_ADDR },
  { ERROR_OFDPE_PORT_MOD_FAILED_BAD_CONFIG, OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_CONFIG },
  { ERROR_OFDPE_PORT_MOD_FAILED_BAD_ADVERTISE, OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_ADVERTISE },
  { ERROR_OFDPE_PORT_MOD_FAILED_EPERM, OFPET_PORT_MOD_FAILED, OFPPMFC_EPERM },

  { ERROR_OFDPE_TABLE_MOD_FAILED_BAD_TABLE, OFPET_TABLE_MOD_FAILED, OFPTMFC_BAD_TABLE },
  { ERROR_OFDPE_TABLE_MOD_FAILED_BAD_CONFIG, OFPET_TABLE_MOD_FAILED, OFPTMFC_BAD_CONFIG },
  { ERROR_OFDPE_TABLE_MOD_FAILED_EPERM, OFPET_TABLE_MOD_FAILED, OFPTMFC_EPERM },

  { ERROR_OFDPE_QUEUE_OP_FAILED_BAD_PORT, OFPET_QUEUE_OP_FAILED, OFPQOFC_BAD_PORT },
  { ERROR_OFDPE_QUEUE_OP_FAILED_BAD_QUEUE, OFPET_QUEUE_OP_FAILED, OFPQOFC_BAD_QUEUE },
  { ERROR_OFDPE_QUEUE_OP_FAILED_EPERM, OFPET_QUEUE_OP_FAILED, OFPQOFC_EPERM },

  { ERROR_OFDPE_SWITCH_CONFIG_FAILED_BAD_FLAGS, OFPET_SWITCH_CONFIG_FAILED, OFPSCFC_BAD_FLAGS },
  { ERROR_OFDPE_SWITCH_CONFIG_FAILED_BAD_LEN, OFPET_SWITCH_CONFIG_FAILED, OFPSCFC_BAD_LEN },
  { ERROR_OFDPE_SWITCH_CONFIG_FAILED_EPERM, OFPET_SWITCH_CONFIG_FAILED, OFPSCFC_EPERM },

  { ERROR_OFDPE_ROLE_REQUEST_FAILED_STALE, OFPET_ROLE_REQUEST_FAILED, OFPRRFC_STALE },
  { ERROR_OFDPE_ROLE_REQUEST_FAILED_UNSUP, OFPET_ROLE_REQUEST_FAILED, OFPRRFC_UNSUP },
  { ERROR_OFDPE_ROLE_REQUEST_FAILED_BAD_ROLE, OFPET_ROLE_REQUEST_FAILED, OFPRRFC_BAD_ROLE },

  { ERROR_OFDPE_METER_MOD_FAILED_UNKNOWN, OFPET_METER_MOD_FAILED, OFPMMFC_UNKNOWN },
  { ERROR_OFDPE_METER_MOD_FAILED_METER_EXISTS, OFPET_METER_MOD_FAILED, OFPMMFC_METER_EXISTS },
  { ERROR_OFDPE_METER_MOD_FAILED_INVALID_METER, OFPET_METER_MOD_FAILED, OFPMMFC_INVALID_METER },
  { ERROR_OFDPE_METER_MOD_FAILED_UNKNOWN_METER, OFPET_METER_MOD_FAILED, OFPMMFC_UNKNOWN_METER },
  { ERROR_OFDPE_METER_MOD_FAILED_BAD_COMMAND, OFPET_METER_MOD_FAILED, OFPMMFC_BAD_COMMAND },
  { ERROR_OFDPE_METER_MOD_FAILED_BAD_FLAGS, OFPET_METER_MOD_FAILED, OFPMMFC_BAD_FLAGS },
  { ERROR_OFDPE_METER_MOD_FAILED_BAD_RATE, OFPET_METER_MOD_FAILED, OFPMMFC_BAD_RATE },
  { ERROR_OFDPE_METER_MOD_FAILED_BAD_BURST, OFPET_METER_MOD_FAILED, OFPMMFC_BAD_BURST },
  { ERROR_OFDPE_METER_MOD_FAILED_BAD_BAND, OFPET_METER_MOD_FAILED, OFPMMFC_BAD_BAND },
  { ERROR_OFDPE_METER_MOD_FAILED_BAD_BAND_VALUE, OFPET_METER_MOD_FAILED, OFPMMFC_BAD_BAND_VALUE },
  { ERROR_OFDPE_METER_MOD_FAILED_OUT_OF_METERS, OFPET_METER_MOD_FAILED, OFPMMFC_OUT_OF_METERS },
  { ERROR_OFDPE_METER_MOD_FAILED_OUT_OF_BANDS, OFPET_METER_MOD_FAILED, OFPMMFC_OUT_OF_BANDS },

  { ERROR_OFDPE_TABLE_FEATURES_FAILED_BAD_TABLE, OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_TABLE },
  { ERROR_OFDPE_TABLE_FEATURES_FAILED_BAD_METADATA, OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_METADATA },
  { ERROR_OFDPE_TABLE_FEATURES_FAILED_BAD_TYPE, OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_TYPE },
  { ERROR_OFDPE_TABLE_FEATURES_FAILED_BAD_LEN, OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_LEN },
  { ERROR_OFDPE_TABLE_FEATURES_FAILED_BAD_ARGUMENT, OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_ARGUMENT },
  { ERROR_OFDPE_TABLE_FEATURES_FAILED_EPERM, OFPET_TABLE_FEATURES_FAILED, OFPTFFC_EPERM },
};


size_t
get_oxm_length_from_match8( const match8 *match, const unsigned int array_size ) {
  assert( match != NULL );

  bool valid = true;
  bool wildcarded = false;
  for ( unsigned int i = 0; i < array_size; i++ ) {
    if ( !match[ i ].valid ) {
      valid = false;
      break;
    }
    if ( match[ i ].mask != UINT8_MAX ) {
      wildcarded = true;
      break;
    }
  }

  if ( !valid ) {
    return 0;
  }

  size_t length = sizeof( uint32_t ); // oxm header
  if ( wildcarded ) {
    length += ( size_t ) ( 2 * 1 * array_size );
  }
  else {
    length += ( size_t ) ( 1 * array_size );
  }

  return length;
}


size_t
get_oxm_length_from_match16( const match16 *match, const unsigned int array_size ) {
  assert( match != NULL );

  bool valid = true;
  bool wildcarded = false;
  for ( unsigned int i = 0; i < array_size; i++ ) {
    if ( !match[ i ].valid ) {
      valid = false;
      break;
    }
    if ( match[ i ].mask != UINT16_MAX ) {
      wildcarded = true;
      break;
    }
  }

  if ( !valid ) {
    return 0;
  }

  size_t length = sizeof( uint32_t ); // oxm header
  if ( wildcarded ) {
    length += ( size_t ) ( 2 * 2 * array_size );
  }
  else {
    length += ( size_t ) ( 2 * array_size );
  }

  return length;
}


size_t
get_oxm_length_from_match32( const match32 *match, const unsigned int array_size ) {
  assert( match != NULL );

  bool valid = true;
  bool wildcarded = false;
  for ( unsigned int i = 0; i < array_size; i++ ) {
    if ( !match[ i ].valid ) {
      valid = false;
      break;
    }
    if ( match[ i ].mask != UINT32_MAX ) {
      wildcarded = true;
      break;
    }
  }

  if ( !valid ) {
    return 0;
  }

  size_t length = sizeof( uint32_t ); // oxm header
  if ( wildcarded ) {
    length += ( size_t ) ( 2 * 4 * array_size );
  }
  else {
    length += ( size_t ) ( 4 * array_size );
  }

  return length;
}


size_t
get_oxm_length_from_match64( const match64 *match, const unsigned int array_size ) {
  assert( match != NULL );

  bool valid = true;
  bool wildcarded = false;
  for ( unsigned int i = 0; i < array_size; i++ ) {
    if ( !match[ i ].valid ) {
      valid = false;
      break;
    }
    if ( match[ i ].mask != UINT64_MAX ) {
      wildcarded = true;
      break;
    }
  }

  if ( !valid ) {
    return 0;
  }

  size_t length = sizeof( uint32_t ); // oxm header
  if ( wildcarded ) {
    length += ( size_t ) ( 2 * 8 * array_size );
  }
  else {
    length += ( size_t ) ( 8 * array_size );
  }

  return length;
}


size_t
get_oxm_length( const match *match ) {
  assert( match != NULL );

  size_t length = 0;

  length += get_oxm_length_from_match16( &match->arp_opcode, 1 );
  length += get_oxm_length_from_match8( match->arp_sha, ETH_ADDRLEN );
  length += get_oxm_length_from_match32( &match->arp_spa, 1 );
  length += get_oxm_length_from_match8( match->arp_tha, ETH_ADDRLEN );
  length += get_oxm_length_from_match32( &match->arp_tpa, 1 );
  length += get_oxm_length_from_match8( match->eth_dst, ETH_ADDRLEN );
  length += get_oxm_length_from_match8( match->eth_src, ETH_ADDRLEN );
  length += get_oxm_length_from_match16( &match->eth_type, 1 );
  length += get_oxm_length_from_match8( &match->icmpv4_code, 1 );
  length += get_oxm_length_from_match8( &match->icmpv4_type, 1 );
  length += get_oxm_length_from_match8( &match->icmpv6_code, 1 );
  length += get_oxm_length_from_match8( &match->icmpv6_type, 1 );
  length += get_oxm_length_from_match32( &match->in_phy_port, 1 );
  length += get_oxm_length_from_match32( &match->in_port, 1 );
  length += get_oxm_length_from_match8( &match->ip_dscp, 1 );
  length += get_oxm_length_from_match8( &match->ip_ecn, 1 );
  length += get_oxm_length_from_match8( &match->ip_proto, 1 );
  length += get_oxm_length_from_match32( &match->ipv4_dst, 1 );
  length += get_oxm_length_from_match32( &match->ipv4_src, 1 );
  length += get_oxm_length_from_match8( match->ipv6_src, IPV6_ADDRLEN );
  length += get_oxm_length_from_match8( match->ipv6_dst, IPV6_ADDRLEN );
  length += get_oxm_length_from_match16( &match->ipv6_exthdr, 1 );
  length += get_oxm_length_from_match32( &match->ipv6_flabel, 1 );
  length += get_oxm_length_from_match8( match->ipv6_nd_sll, ETH_ADDRLEN );
  length += get_oxm_length_from_match8( match->ipv6_nd_target, IPV6_ADDRLEN );
  length += get_oxm_length_from_match8( match->ipv6_nd_tll, ETH_ADDRLEN );
  length += get_oxm_length_from_match64( &match->metadata, 1 );
  length += get_oxm_length_from_match8( &match->mpls_bos, 1 );
  length += get_oxm_length_from_match32( &match->mpls_label, 1 );
  length += get_oxm_length_from_match8( &match->mpls_tc, 1 );
  length += get_oxm_length_from_match16( &match->sctp_dst, 1 );
  length += get_oxm_length_from_match16( &match->sctp_src, 1 );
  length += get_oxm_length_from_match16( &match->tcp_dst, 1 );
  length += get_oxm_length_from_match16( &match->tcp_src, 1 );
  length += get_oxm_length_from_match64( &match->tunnel_id, 1 );
  length += get_oxm_length_from_match16( &match->udp_dst, 1 );
  length += get_oxm_length_from_match16( &match->udp_src, 1 );
  length += get_oxm_length_from_match8( &match->vlan_pcp, 1 );
  length += get_oxm_length_from_match16( &match->vlan_vid, 1 );
  length += get_oxm_length_from_match32( &match->pbb_isid, 1 );

  return length;
}


size_t
get_ofp_action_length( const action *action ) {
  assert( action != NULL );

  size_t length = 0;

  switch ( action->type ) {
    case OFPAT_OUTPUT:
    {
      length += sizeof( struct ofp_action_output );
    }
    break;

    case OFPAT_COPY_TTL_OUT: 
    case OFPAT_COPY_TTL_IN:
    {
      length += sizeof( struct ofp_action_header );
    }
    break;

    case OFPAT_SET_MPLS_TTL:
    {
      length += sizeof( struct ofp_action_mpls_ttl );
    }
    break;

    case OFPAT_DEC_MPLS_TTL:
    {
      length += sizeof( struct ofp_action_header );
    }
    break;

    case OFPAT_PUSH_VLAN:
    {
      length += sizeof( struct ofp_action_push );
    }
    break;

    case OFPAT_POP_VLAN:
    {
      length += sizeof( struct ofp_action_header );
    }
    break;

    case OFPAT_PUSH_MPLS:
    {
      length += sizeof( struct ofp_action_push );
    }
    break;

    case OFPAT_POP_MPLS:
    {
      length += sizeof( struct ofp_action_pop_mpls );
    }
    break;

    case OFPAT_SET_QUEUE:
    {
      length += sizeof( struct ofp_action_set_queue );
    }
    break;

    case OFPAT_GROUP:
    {
      length += sizeof( struct ofp_action_group );
    }
    break;

    case OFPAT_SET_NW_TTL:
    {
      length += sizeof( struct ofp_action_nw_ttl );
    }
    break;

    case OFPAT_DEC_NW_TTL:
    {
      length += sizeof( struct ofp_action_header );
    }
    break;

    case OFPAT_SET_FIELD:
    {
      size_t oxm_length = offsetof( struct ofp_action_set_field, field );
      if ( action->match != NULL ) {
        // TODO: we need to check if only a single field exists in the match.
        oxm_length += get_oxm_length( action->match );
      }
      else {
        oxm_length = sizeof( struct ofp_action_set_field );
      }
      length += oxm_length;
      length += ( oxm_length + 7 ) / 8 * 8 - oxm_length; // padding
    }
    break;

    case OFPAT_PUSH_PBB:
    {
      length += sizeof( struct ofp_action_push );
    }
    break;

    case OFPAT_POP_PBB:
    {
      length += sizeof( struct ofp_action_header );
    }
    break;

    case OFPAT_EXPERIMENTER:
    {
      warn( "OFPAT_EXPERIMENTER is not supported." );
    }
    break;

    default:
    {
      error( "Undefined action type ( %#x ).", action->type );
    }
    break;
  }

  return length;
}


size_t
get_ofp_bucket_length( const bucket *bucket ) {
  assert( bucket != NULL );

  size_t length = offsetof( struct ofp_bucket, actions );

  if ( bucket->actions != NULL ) {
    for ( dlist_element *e = get_first_element( bucket->actions ); e != NULL; e = e->next ) {
      if ( e->data == NULL ) {
        continue;
      }
      length += get_ofp_action_length( e->data );
    }
  }

  return length;
}


size_t
get_ofp_buckets_length( bucket_list *buckets ) {
  assert( buckets != NULL );

  size_t length = 0;

  for ( dlist_element *e = get_first_element( buckets ); e != NULL; e = e->next ) {
    if ( e->data == NULL ) {
      continue;
    }
    length += get_ofp_bucket_length( e->data );
  }

  return length;
}


bool
get_ofp_action( const action* action, struct ofp_action_header **translated, size_t *length ) {
  assert( action != NULL );
  assert( translated != NULL );
  assert( length != NULL );

  // TODO: implement this function.
  warn( "get_ofp_action() is not implemented yet." );

  *translated = NULL;
  *length = 0;

  bool ret = false;
  switch ( action->type ) {
    case OFPAT_OUTPUT:
    {
    }
    break;

    case OFPAT_COPY_TTL_OUT:
    {
    }
    break;

    case OFPAT_COPY_TTL_IN:
    {
    }
    break;

    case OFPAT_SET_MPLS_TTL:
    {
    }
    break;

    case OFPAT_DEC_MPLS_TTL:
    {
    }
    break;

    case OFPAT_PUSH_VLAN:
    {
    }
    break;

    case OFPAT_POP_VLAN:
    {
    }
    break;

    case OFPAT_PUSH_MPLS:
    {
    }
    break;

    case OFPAT_POP_MPLS:
    {
    }
    break;

    case OFPAT_SET_QUEUE:
    {
    }
    break;

    case OFPAT_GROUP:
    {
    }
    break;

    case OFPAT_SET_NW_TTL:
    {
    }
    break;

    case OFPAT_DEC_NW_TTL:
    {
    }
    break;

    case OFPAT_SET_FIELD:
    {
    }
    break;

    case OFPAT_PUSH_PBB:
    {
    }
    break;

    case OFPAT_POP_PBB:
    {
    }
    break;

    case OFPAT_EXPERIMENTER:
    {
      error( "OFPAT_EXPERIMENTER is not supported." );
    }
    break;

    default:
    {
      error( "Undefined action type ( %#x ).", action->type );
    }
    break;
  }

  *length = get_ofp_action_length( action );

  return ret;
}


bool
get_ofp_bucket( const bucket *bucket, struct ofp_bucket **translated, size_t *length ) {
  assert( bucket != NULL );
  assert( translated != NULL );
  assert( length != NULL );

  *length = get_ofp_bucket_length( bucket );
  *translated = xmalloc( *length );
  memset( *translated, 0, *length );

  ( *translated )->len = ( uint16_t ) *length;
  ( *translated )->weight = bucket->weight;
  ( *translated )->watch_port = bucket->watch_port;
  ( *translated )->watch_group = bucket->watch_group;

  bool ret = true;
  struct ofp_action_header *actions = ( *translated )->actions;
  for ( dlist_element *e = get_first_element( bucket->actions ); e != NULL; e = e->next ) {
    if ( e->data == NULL ) {
      continue;
    }
    action *action = e->data;
    size_t action_length = 0;
    struct ofp_action_header *ofp_action = NULL;
    bool ret = get_ofp_action( action, &ofp_action, &action_length );
    if ( !ret ) {
      xfree( *translated );
      *translated = NULL;
      ret = false;
      break;
    }
    memcpy( actions, ofp_action, action_length );
    xfree( ofp_action );
    actions = ( struct ofp_action_header * ) ( ( char * ) actions + action_length );
  }


  return ret;
}


bool
get_ofp_group_stats( const group_stats *stats, struct ofp_group_stats **translated, size_t *length ) {
  assert( stats != NULL );
  assert( translated != NULL );
  assert( length != NULL );

  unsigned int n_buckets = 0;
  if ( stats->bucket_stats != NULL ) {
    n_buckets = list_length_of( stats->bucket_stats );
  }

  *length = offsetof( struct ofp_group_stats, bucket_stats ) + sizeof( struct ofp_bucket_counter ) * n_buckets;
  *translated = xmalloc( *length );

  struct ofp_bucket_counter *counter = ( *translated )->bucket_stats;
  for ( list_element *e = stats->bucket_stats; e != NULL; e = e->next ) {
    if ( e->data == NULL ) {
      continue;
    }
    bucket_counter *bucket_counter = e->data;
    counter->packet_count = bucket_counter->packet_count;
    counter->byte_count = bucket_counter->byte_count;
    counter++;
  }
  
  ( *translated )->length = ( uint16_t ) *length;
  ( *translated )->group_id = stats->group_id;
  ( *translated )->ref_count = stats->ref_count;
  ( *translated )->packet_count = stats->packet_count;
  ( *translated )->byte_count = stats->byte_count;
  ( *translated )->duration_sec = stats->duration_sec;
  ( *translated )->duration_nsec = stats->duration_nsec;

  return true;
}


bool
get_ofp_bucket_counter( const bucket_counter *counter, struct ofp_bucket_counter *translated ) {
  assert( counter != NULL );
  assert( translated != NULL );

  memcpy( translated, counter, sizeof( struct ofp_bucket_counter ) );

  return true;
}


bool
get_ofp_table_stats( const table_stats *stats, struct ofp_table_stats *translated ) {
  assert( stats != NULL );
  assert( translated != NULL );

  memcpy( translated, stats, sizeof( struct ofp_table_stats ) );

  return true;
}


bool
get_ofp_port_stats( const port_stats *stats, struct ofp_port_stats *translated ) {
  assert( stats != NULL );
  assert( translated != NULL );

  memcpy( translated, stats, sizeof( struct ofp_port_stats ) );

  return true;
}


bool
get_ofp_port( const port_description *description, struct ofp_port *translated ) {
  assert( description != NULL );
  assert( translated != NULL );

  memcpy( translated, description, sizeof( struct ofp_port ) );

  return true;
}


void
switch_port_to_ofp_port( struct ofp_port *ofp_port, const switch_port *port ) {
  assert( port != NULL );
  assert( port->device != NULL );
  assert( ofp_port != NULL );

  memset( ofp_port, 0, sizeof( struct ofp_port ) );

  ofp_port->port_no = port->port_no;
  memcpy( ofp_port->hw_addr, port->device->hw_addr, OFP_ETH_ALEN );
  strncpy( ofp_port->name, port->device->name, OFP_MAX_PORT_NAME_LEN );
  ofp_port->name[ OFP_MAX_PORT_NAME_LEN - 1 ] = '\0';
  ofp_port->config = port->config;
  ofp_port->state = port->status.state;
  ofp_port->curr = port->status.curr;
  ofp_port->advertised = port->status.advertised;
  ofp_port->supported = port->status.supported;
  ofp_port->peer = port->status.peer;
  ofp_port->curr_speed = 0;
  ofp_port->max_speed = 0;
}


bool
get_ofp_error( OFDPE error_code, uint16_t *type, uint16_t *code ) {
  assert( type != NULL );
  assert( code != NULL );

  bool found = false;
  for ( uint32_t i = 0; i < sizeof( error_maps ) / sizeof( error_maps[ 0 ] ); i++ ) {
    if ( error_code == error_maps[ i ].error_code ) {
      *type = error_maps[ i ].type;
      *code = error_maps[ i ].code;
      found = true;
      break;
    }
  }

  return found;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
