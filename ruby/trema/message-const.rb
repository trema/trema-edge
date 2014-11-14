#
# Copyright (C) 2008-2013 NEC Corporation
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2, as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

require_relative 'monkey-patch/kernel'

module Trema
  module MessageConst
    config_flags_hash = {
      ofpc_frag_normal: frag_normal,
      ofpc_frag_drop: frag_drop,
      ofpc_frag_reasm: frag_reasm,
      ofpc_frag_mask: frag_mask
    }
    enum_hash config_flags_hash
    CONFIG_FLAGS = config_flags_hash.values.freeze

    enum_hash(ofp_version: ofp_version)

    enum_step %w( ofpfc_add
                  ofpfc_modify
                  ofpfc_modify_strict
                  ofpfc_delete
                  ofpfc_delete_strict )

    flow_mod_flags = %w( ofpff_send_flow_rem
                         ofpff_check_overlap
                         ofpff_reset_counts
                         ofpff_no_pkt_counts
                         ofpff_no_byt_counts )
    enum_range flow_mod_flags

    port_config = %w( ofppc_port_down
                      ofppc_reserved_1
                      ofppc_no_recv
                      ofppc_reserved_3
                      ofppc_reserved_4
                      ofppc_no_fwd
                      ofppc_no_packet_in )
    enum_range port_config

    enum_hash(ofpp_max: max_port,
              ofpp_in_port: in_port,
              ofpp_table: table_port,
              ofpp_normal: normal_port,
              ofpp_flood: flood_port,
              ofpp_all: all_ports,
              ofpp_controller: controller_port,
              ofpp_local: local_port,
              ofpp_any: any_port)

    port_features = %w( ofppf_10mb_hd
                        ofppf_10mb_fd
                        ofppf_100mb_hd
                        ofppf_100mb_fd
                        ofppf_1gb_hd
                        ofppf_1gb_fd
                        ofppf_10gb_fd
                        ofppf_40gb_fd
                        ofppf_100gb_fd
                        ofppf_1tb_fd
                        ofppf_other
                        ofppf_copper
                        ofppf_fiber
                        ofppf_autoneg
                        ofppf_pause
                        ofppf_pause_asym )
    enum_range port_features

    enum_hash(ofpg_any: any_group)

    enum_hash(ofptt_all: all_tables)

    enum_hash(ofpcml_max: controller_max_len_max,
              ofpcml_no_buffer: controller_max_len_no_buffer)

    enum_hash(ofp_no_buffer: no_buffer)

    enum_hash(ofp_default_priority: default_priority,
              ofp_high_priority: high_priority,
              ofp_low_priority: low_priority)

    port_state = %w( ofpps_link_down
                     ofpps_blocked
                     ofpps_live )
    enum_range port_state

    enum_step %w( ofpr_no_match ofpr_action ofpr_invalid_ttl )

    enum_step %w( ofprr_idle_timeout
                  ofprr_hard_timeout
                  ofprr_delete
                  ofprr_group_delete )

    enum_step %w( ofppr_add ofppr_delete ofppr_modify )

    group_type = %w( ofpgt_all
                     ofpgt_select
                     ofpgt_indirect
                     ofpgt_ff )
    enum_step group_type

    enum_step %w( ofpgc_add ofpgc_modify ofpgc_delete )

    error_type = %w( ofppet_hello_failed
                     ofppet_bad_request
                     ofppet_bad_action
                     ofppet_bad_instruction
                     ofppet_bad_match
                     ofppet_flow_mod_failed
                     ofppet_group_mod_failed
                     ofppet_table_mod_failed
                     ofppet_queue_mod_failed
                     ofppet_switch_config_failed
                     ofppet_role_request_failed
                     ofppet_meter_mod_failed
                     ofppet_table_features_failed )
    enum_step error_type
    enum_hash ofppet_experimenter: experimenter_error

    multipart_type = %w( ofpmp_desc
                         ofpmp_flow
                         ofpmp_aggregate
                         ofpmp_table
                         ofpmp_port_stats
                         ofpmp_queue
                         ofpmp_group
                         ofpmp_group_desc
                         ofpmp_group_features
                         ofpmp_meter
                         ofpmp_meter_config
                         ofpmp_meter_features
                         ofpmp_table_features
                         ofpmp_port_desc )
    enum_step multipart_type
    enum_hash ofpmp_experimenter: experimenter_mp

    enum_hash(ofpat_output: at_output,
              ofpat_copy_ttl_out: at_copy_ttl_out,
              ofpat_copy_ttl_in: at_copy_ttl_in,
              ofpat_set_mpls_ttl: at_set_mpls_ttl,
              ofpat_dec_mpls_ttl: at_dec_mpls_ttl,
              ofpat_push_vlan: at_push_vlan,
              ofpat_pop_vlan: at_pop_vlan,
              ofpat_push_mpls: at_push_mpls,
              ofpat_pop_mpls: at_pop_mpls,
              ofpat_set_queue: at_set_queue,
              ofpat_group: at_group,
              ofpat_set_nw_ttl: at_set_nw_ttl,
              ofpat_dec_nw_ttl: at_dec_nw_ttl,
              ofpat_set_field: at_set_field,
              ofpat_push_pbb: at_push_pbb,
              ofpat_pop_pbb: at_pop_pbb,
              ofpat_experimenter: at_experimenter)

    instruction_type = %w( ofpit_goto_table
                           ofpit_write_metadata
                           ofpit_write_actions
                           ofpit_apply_actions
                           ofpit_clear_actions
                           ofpit_meter )

    enum_step 1, instruction_type
    enum_hash ofpit_experimenter: it_experimenter

    oxm_match_fields = %w( ofpxmt_ofb_in_port
                           ofpxmt_ofb_in_phy_port
                           ofpxmt_ofb_metadata
                           ofpxmt_ofb_eth_dst
                           ofpxmt_ofb_eth_src
                           ofpxmt_ofb_eth_type
                           ofpxmt_ofb_vlan_vid
                           ofpxmt_ofb_vlan_pcp
                           ofpxmt_ofb_ip_dscp
                           ofpxmt_ofb_ip_ecn
                           ofpxmt_ofb_ip_proto
                           ofpxmt_ofb_ipv4_src
                           ofpxmt_ofb_ipv4_dst
                           ofpxmt_ofb_tcp_src
                           ofpxmt_ofb_tcp_dst
                           ofpxmt_ofb_udp_src
                           ofpxmt_ofb_udp_dst
                           ofpxmt_ofb_sctp_src
                           ofpxmt_ofb_sctp_dst
                           ofpxmt_ofb_icmpv4_type
                           ofpxmt_ofb_icmpv4_code
                           ofpxmt_ofb_arp_op
                           ofpxmt_ofb_arp_spa
                           ofpxmt_ofb_arp_tpa
                           ofpxmt_ofb_arp_sha
                           ofpxmt_ofb_arp_tha
                           ofpxmt_ofb_ipv6_src
                           ofpxmt_ofb_ipv6_dst
                           ofpxmt_ofb_ipv6_flabel
                           ofpxmt_ofb_icmpv6_type
                           ofpxmt_ofb_icmpv6_code
                           ofpxmt_ofb_ipv6_nd_target
                           ofpxmt_ofb_ipv6_nd_sll
                           ofpxmt_ofb_ipv6_nd_tll
                           ofpxmt_ofb_mpls_label
                           ofpxmt_ofb_mpls_tc
                           ofpxmt_ofb_mpls_bos
                           ofpxmt_ofb_pbb_isid
                           ofpxmt_ofb_tunnel_id
                           ofpxmt_ofb_ipv6_exthdr )

    enum_step oxm_match_fields
  end
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
