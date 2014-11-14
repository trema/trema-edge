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
    # An action that sets the group id that uniquely identifies a group table
    # entry instance. A group table entry contains the group type, counters and
    # action buckets that modify the flow pipeline processing.
    #
    class GroupAction < BasicAction
      #
      # An action to execute the action buckets defined in the group table
      # referenced by this action group identifier. The user must ensure
      # that the specified group_id points to a valid group table entry.
      #
      # @example
      #   GroupAction.new( 1 )
      #
      # @param [Integer] group_id
      #   the group id to set to.
      #
      # @raise [ArgumentError] if group_id is not specified.
      # @raise [ArgumentError] if group_id is not an unsigned 32-bit integer.
      #
      ofp_type OFPAT_GROUP
      unsigned_int32 :group_id, presence: true
    end
  end

  GroupAction = Actions::GroupAction
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
