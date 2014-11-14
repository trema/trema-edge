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
    # A match field to match a Mulitprotocol Label Switching( MPLS ) label.
    # For example a value of 0 refers to IPv4 Explicit NULL label. A label
    # value is 20-bits.
    #
    class MplsLabel < FlexibleAction
      unsigned_int32 :mpls_label, presence: true
    end
  end

  MplsLabel = Actions::MplsLabel
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
