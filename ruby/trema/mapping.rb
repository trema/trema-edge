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

module Mapping
  def self.included(mod)
    mod.extend ClassMethods
  end

  module ClassMethods
    def map_ofp_type(klass)
      name = klass.name.demodulize.underscore
      %w( OFPAT OFPIT OFPXMT_OFB ).each do | prefix |
        store_if_valid prefix, klass, name
      end
    end

    def store(key, value)
      ClassMethods.associates[key] = value
    end

    def retrieve(key)
      ClassMethods.associates[key]
    end

    private

    def store_if_valid(prefix, klass, name)
      type = eval("#{ prefix }_#{ name.upcase }")
      store "#{ prefix }_#{ type }", klass
    rescue NameError
   end

    def self.associates
      @_associates ||= {}
     end
  end
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
