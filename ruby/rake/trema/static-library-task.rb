#
# Copyright (C) 2013 NEC Corporation
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


require "rake/trema/library-task"


module Rake
  module Trema
    #
    # Compile *.c files into a static library.
    #
    class StaticLibraryTask < LibraryTask
      ##########################################################################
      private
      ##########################################################################


      def generate_target
        ar
        ranlib
      end


      def ar
        sh "ar -cq #{ target_path } #{ objects.to_s }"
      end


      def ranlib
        sh "ranlib #{ target_path }"
      end


      def library_name
        @library_name || @name
      end


      def target_file_name
        library_name + ".a"
      end
    end
  end
end


### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
