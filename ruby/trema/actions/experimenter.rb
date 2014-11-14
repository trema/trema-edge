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
    # An action to set an experimenter action.
    #
    class Experimenter < BasicAction
      ofp_type OFPAT_EXPERIMENTER
      #
      # Creates an action to set an experimenter action.
      #
      # @example
      #   ExperimenterAction.new( 0x00004cff, "deadbeef".unpack( "C*" ) )
      #
      # @param [Integer] experimenter_id
      #   the experimenter identifier.
      # @param [Array] body
      #   experimenter-defined arbitrary additional data.
      #
      # @raise [TypeError] if experimenter is not an Integer.
      # @raise [ArgumentError] if experimeter is not an unsigned 32-bit Integer.
      # @raise [TypeError] if body is not an Array.
      #

      #
      # @return [Array<Fixnum>] the value of attribute {#body} that represents
      #   binary data as an array of bytes.
      #
      # @return [Integer] the value of attribute {#experimenter}
      unsigned_int32 :experimenter, presence: true
      array :body, validate_with: :check_body

      def check_body(body, name)
        if (!body.nil?)  && (!body.is_a?(Array))
          fail ArgumentError, "#{ name } must be an Array"
        end
      end
    end
  end
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
