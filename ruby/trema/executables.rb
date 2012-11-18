#
# Author: Yasuhito Takamiya <yasuhito@gmail.com>
#
# Copyright (C) 2008-2012 NEC Corporation
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


require "trema/monkey-patch/module"
require "trema/monkey-patch/string"
require "trema/path"


#
# Holds the list of executalbes found in {Trema.objects} directory.
#
class Trema::Executables
  class << self
    def compiled?
      @list.each do | each |
        return false if not FileTest.executable?( __send__ each )
      end
    end


    ############################################################################
    private
    ############################################################################


    def add name
      @list ||= []
      @list << name
    end


    def path path
      name = File.basename( path ).underscore
      define_class_method( name ) do
        File.join Trema.objects, path
      end
      add name
    end
  end


  path "packetin_filter/packetin_filter"
  path "switch_manager/switch"
  path "switch_manager/switch_manager"
end


### Local variables:
### mode: Ruby
### coding: utf-8
### indent-tabs-mode: nil
### End:
