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
    # An action that replaces an existing IP TTL. This action ony applies to
    # IPv4 packets.
    #
    class SetIpTtl < BasicAction
      ofp_type OFPAT_SET_NW_TTL
      #
      # An action that replaces an existing IP TTL value. The packet checksum
      # must be re-calculated.
      #
      # @example
      #   SetIpTtl.new( 16 )
      #
      # @param [Integer] ip_ttl
      #   the ip_ttl value to set to.
      #
      # @raise [ArgumentError] if ip_ttl is not specified.
      # @raise [ArgumentError] if ip_ttl is not an unsigned 8-bit integer.
      #
      unsigned_int8 :ip_ttl, presence: true
    end
  end

  SetIpTtl = Actions::SetIpTtl
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
