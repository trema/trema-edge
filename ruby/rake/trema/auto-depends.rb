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


require "popen4"


module Rake
  module Trema
    #
    # Automatically detects compilation dependencies.
    #
    class AutoDepends
      attr_reader :data


      def initialize c_file, o_file, gcc_options
        @command = "gcc -H #{ gcc_options } -c #{ c_file } -o #{ o_file }"
        @data = []
      end


      def run
        puts @command
        status = POpen4.popen4( @command ) do | stdout, stderr, stdin, pid |
          stdin.close
          parse_gcc_h_stderr stderr
        end
        raise "gcc failed" if status.exitstatus != 0
      end


      ##########################################################################
      private
      ##########################################################################


      def parse_gcc_h_stderr stderr
        stderr.each do | each |
          parse_gcc_h_stderr_line( each, stderr )
        end
      end


      def parse_gcc_h_stderr_line line, stderr
        case line
        when /^\./
          @data << line.sub( /^\.+\s+/, "" ).strip
        when /Multiple include guards/
          filter_out_include_guards_warnings stderr
        else
          puts line
        end
      end


      def filter_out_include_guards_warnings stderr
        stderr.each do | each |
          if each =~ /:$/
            puts each
            return
          end
        end
      end
    end
  end
end
