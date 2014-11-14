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
  module Messages
    class PacketInfo < Message
      mac :eth_src
      mac :eth_dst
      unsigned_int16 :eth_type

      unsigned_int8 :ip_dscp # IP DSCP ( 6 bits in ToS field )
      unsigned_int8 :ip_ecn # IP ECN ( 2 bits in ToS field )
      unsigned_int8 :ip_proto # ip protocol

      bool :vtag
      alias_method :vtag?, :vtag

      unsigned_int16 :vlan_vid
      unsigned_int16 :vlan_tci
      unsigned_int8 :vlan_prio
      unsigned_int16 :vlan_tpid

      bool :ipv4
      alias_method :ipv4?, :ipv4

      bool :ipv6
      alias_method :ipv6?, :ipv6

      bool :arp
      alias_method :arp?, :arp

      bool :arp_request
      alias_method :arp_request?, :arp_request

      bool :arp_reply
      alias_method :arp_reply?, :arp_reply

      unsigned_int16 :arp_op
      mac :arp_sha
      mac :arp_tha
      ip_addr :arp_spa
      ip_addr :arp_tpa

      bool :icmpv4
      alias_method :icmpv4?, :icmpv4

      unsigned_int8 :icmpv4_type
      unsigned_int8 :icmpv4_code

      bool :icmpv6
      alias_method :icmpv6?, :icmpv6

      unsigned_int8 :icmpv6_type
      unsigned_int8 :icmpv6_code
      ip_addr :ipv6_nd_target
      mac :ipv6_nd_sll
      mac :ipv6_nd_tll

      ip_addr :ipv4_src
      ip_addr :ipv4_dst
      unsigned_int8 :ipv4_tos
      unsigned_int16 :ipv4_tot_len
      unsigned_int16 :ipv4_id

      unsigned_int16 :tcp_src
      unsigned_int16 :tcp_dst

      bool :tcp
      alias_method :tcp?, :tcp

      unsigned_int16 :udp_src
      unsigned_int16 :udp_dst
      bool :udp
      alias_method :udp?, :udp

      unsigned_int16 :sctp_src, :sctp_dst
      bool :sctp
      alias_method :sctp?, :sctp

      ip_addr :ipv6_src
      ip_addr :ipv6_dst
      unsigned_int32 :ipv6_flabel
      unsigned_int16 :ipv6_exthdr

      unsigned_int32 :mpls_label
      unsigned_int8 :mpls_tc
      unsigned_int8 :mpls_bos
      bool :mpls
      alias_method :mpls?, :mpls

      unsigned_int32 :pbb_isid
      bool :pbb
      alias_method :pbb?, :pbb
    end
  end

  PacketInfo = Messages::PacketInfo
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
