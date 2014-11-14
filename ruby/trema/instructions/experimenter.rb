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
  module Instructions
    class Experimenter < Instruction
      unsigned_int32 :experimenter, presence: true
      array :user_data, validate_with: :check_user_data

      def check_user_data(user_data, name)
        if (!user_data.nil?)  && (!user_data.is_a?(Array))
          fail ArgumentError, "#{ name } must be an Array"
        end
      end
    end
  end
  #
  # Because there is also an experimenter action, experimenter instructions
  # need to be referenced by the full name Trema::Instructions::Experimenter
  # or we could create a different class name like ExperimenterIns
  #
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
