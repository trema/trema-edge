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
    # An action that sets the queue id for the packet.
    #
    class SetQueue < BasicAction
      #
      # An action that sets the queue id for the packet.
      #
      # @example
      #   SetQueue.new( 1 )
      #
      # @param [Integer] queue_id
      #   the queue id to set to.
      #
      # @raise [ArgumentError] if queue_id is not specified.
      # @raise [ArgumentError] if queue_id is not an unsigned 32-bit integer.
      #
      # @return [Fixnum] the value of attribute {#queue_id}
      unsigned_int32 :queue_id, presence: true
    end
  end

  SetQueue = Actions::SetQueue
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
