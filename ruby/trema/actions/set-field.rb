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
    # Action set field - an array of one or more OXM.
    # A set field action can be any OXM field except OXM_IN_PORT,
    # OXM_IN_PHY_PORT, OXM_METADATA
    #
    class SetField < BasicAction
      array :action_set, validate_with: :check_action_set
    end

    def check_action_set(_action_set, _name)
      # TODO validate argument
    end
  end

  SetField = Actions::SetField
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
