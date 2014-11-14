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
    # A match field to match an MPLS bottom of stack bit(bos)
    #
    class MplsBos < FlexibleAction
      unsigned_int8 :mpls_bos, presence: true, within: :check_mpls_bos_range

      def check_mpls_bos_range(mpls_bos, name)
        range = 0..1
        unless range.include? mpls_bos
          fail ArgumentError, "#{ name } value must be >= #{ range.first } and <= #{ range.last }."
        end
      end
    end
  end

  MplsBos = Actions::MplsBos
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
