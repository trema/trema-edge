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

module Trema
  class Match < Message
    unsigned_int32 :in_port, :in_phy_port
    unsigned_int64 :metadata, :metadata_mask
    mac :eth_src, :eth_src_mask
    mac :eth_dst, :eth_dst_mask
    unsigned_int16 :eth_type
    unsigned_int16 :vlan_vid, :vlan_vid_mask
    unsigned_int8 :vlan_pcp
    unsigned_int8 :ip_dscp # IP DSCP ( 6 bits in ToS field )
    unsigned_int8 :ip_ecn # IP ECN ( 2 bits in ToS field )
    unsigned_int8 :ip_proto # ip protocol
    ip_addr :ipv4_src, :ipv4_src_mask
    ip_addr :ipv4_dst, :ipv4_dst_mask
    unsigned_int16 :tcp_src, :tcp_dst
    unsigned_int16 :udp_src, :udp_dst
    unsigned_int16 :sctp_src, :sctp_dst
    unsigned_int8 :icmpv4_type, :icmpv4_code
    unsigned_int16 :arp_op
    ip_addr :arp_spa, :arp_spa_mask
    ip_addr :arp_tpa, :arp_tpa_mask
    mac :arp_sha, :arp_sha_mask
    mac :arp_tha, :arp_tha_mask
    ip_addr :ipv6_src, :ipv6_src_mask
    ip_addr :ipv6_dst, :ipv6_dst_mask
    unsigned_int32 :ipv6_flabel, :ipv6_flabel_mask
    unsigned_int8 :icmpv6_type, :icmpv6_code
    ip_addr :ipv6_nd_target
    mac :ipv6_nd_sll, :ipv6_nd_tll
    unsigned_int32 :mpls_label
    unsigned_int8 :mpls_tc, :mpls_bos
    unsigned_int32 :pbb_isid, :pbb_isid_mask
    unsigned_int64 :tunnel_id, :tunnel_id_mask
    unsigned_int16 :ipv6_exthdr, :ipv6_exthdr_mask
  end
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
