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

require 'forwardable'

module Trema
  module Messages
    class PacketIn < Message
      extend Forwardable
      unsigned_int32 :transaction_id
      unsigned_int64 :datapath_id
      unsigned_int32 :buffer_id
      unsigned_int16 :total_len
      unsigned_int8 :reason
      unsigned_int8 :table_id
      unsigned_int64 :cookie
      match :match
      array :data
      packet_info :packet_info

      # delegation methods to match
      def_delegator :@match, :in_port

      # packet info information
      def_delegators :@packet_info, :eth_type, :eth_src, :eth_dst

      def_delegators :@packet_info, :ip_dscp, :ip_ecn, :ip_proto

      def_delegators :@packet_info, :vtag?, :vlan_tci, :vlan_vid, :vlan_prio, :vlan_tpid

      def_delegators :@packet_info, :ipv4?, :ip_proto, :ipv4_src, :ipv4_dst, :ipv4_tos, :ipv4_tot_len, :ipv4_id

      def_delegators :@packet_info, :ipv6?, :ipv6_src, :ipv6_dst, :ipv6_flabel, :ipv6_exthdr

      def_delegators :@packet_info, :arp?, :arp_op, :arp_sha, :arp_spa, :arp_tpa

      def_delegators :@packet_info, :icmpv4?, :icmpv4_type, :icmpv4_code

      def_delegators :@packet_info, :icmpv6?, :icmpv6_type, :icmpv6_code, :ipv6_nd_target, :ipv6_nd_sll, :ipv6_nd_tll

      def_delegators :@packet_info, :tcp?, :tcp_src, :tcp_dst

      def_delegators :@packet_info, :udp?, :udp_src, :udp_dst

      def_delegators :@packet_info, :sctp?, :sctp_src, :sctp_dst

      def_delegators :@packet_info, :mpls?, :mpls_label, :mpls_tc, :mpls_bos

      def_delegators :@packet_info, :pbb?, :pbb_isid
    end
  end

  PacketIn = Messages::PacketIn
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
