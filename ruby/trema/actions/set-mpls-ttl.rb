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
    class SetMplsTtl < BasicAction
      # @return [Fixnum] the value of attribute {#mpls_ttl}
      unsigned_int8 :mpls_ttl, presence: true
      #
      # An action that replaces an existing MPLS TTL. This action applies to
      # packets with an existing MPLS shim header.
      #
      # @example
      #   SetMplsTtl.new( 1 )
      #
      # @param [Integer] group_id
      #   the MPLS TTL to set to.
      #
      # @raise [ArgumentError] if mpls_ttl is not specified.
      # @raise [ArgumentError] if mpls_ttl is not an unsigned 8-bit integer.
      #
    end
  end

  SetMplsTtl = Actions::SetMplsTtl
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
