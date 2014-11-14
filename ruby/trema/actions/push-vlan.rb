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
  module Actions
    #
    # An action that pushes a new VLAN header onto the packet.
    # Only ethernet type 0x8100(ctag) and 0x88a8(stag) should be used.
    #
    # @example
    #   PushVlan.new( 0x8100 )
    #
    # @param [Integer] ethertype
    #   the ethertype to set to.
    #
    class PushVlan < BasicAction
      #
      # 0x8100 - Customer VLAN tag type (ctag)
      # 0x88a8 - Service VLAN tag identifier (stag)
      #
      VLAN_ETHER_TAGS = [0x8100, 0x88a8]

      unsigned_int16 :ether_type, presence: true, within: :check_vlan_ether_type

      def check_vlan_ether_type(ether_type, name)
        unless VLAN_ETHER_TAGS.include? ether_type
          fail ArgumentError, "Invalid #{ name } specified."
        end
      end
    end
  end

  PushVlan = Actions::PushVlan
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
