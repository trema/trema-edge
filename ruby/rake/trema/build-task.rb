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


require "rake/clean"
require "rake/tasklib"
require "rake/trema/auto-depends"
require "rake/trema/dependency"


module Rake
  module Trema
    #
    # Common base class for *.c compilation tasks.
    #
    class BuildTask < TaskLib
      attr_accessor :cflags
      attr_accessor :includes
      attr_accessor :name
      attr_accessor :target_directory
      attr_writer :sources


      def initialize name, &block
        init name.to_s
        block.call self
        define
      end


      def sources
        FileList.new @sources
      end


      ##########################################################################
      private
      ##########################################################################


      def define
        define_main_task
        define_all_c_compile_tasks
        define_maybe_generate_target_task
        define_clean_targets
        define_clobber_targets
      end


      def define_main_task
        directory @target_directory
        task name => [ @target_directory, target_path ]
      end


      def define_all_c_compile_tasks
        sources.zip( objects ) do | source, object |
          define_c_compile_task source, object
        end
      end


      def define_c_compile_task source, object
        task object => source do | task |
          compile task.name, task.prerequisites[ 0 ]
        end
      end


      def define_maybe_generate_target_task
        file target_path => objects do | task |
          next if uptodate?( task.name, task.prerequisites )
          generate_target
        end
      end


      def define_clean_targets
        CLEAN.include objects
      end


      def define_clobber_targets
        CLOBBER.include target_path
        CLOBBER.include Dependency.path( @name )
      end


      def target_path
        File.join @target_directory, target_file_name
      end


      def objects
        sources.collect do | each |
          File.join @target_directory, File.basename( each ).ext( ".o" )
        end
      end


      def init name
        @name = name
        @includes = []
      end


      def gcc_l_options
        @library_dependencies.collect do | each |
          "-l#{ each }"
        end.join( " " )
      end


      def compile o_file, c_file
        if uptodate?( o_file, Dependency.read( @name, o_file ) << c_file )
          return
        end
        auto_depends = AutoDepends.new(
                         c_file,
                         o_file,
                         auto_depends_gcc_options
                       )
        auto_depends.run
        Dependency.write @name, o_file, auto_depends.data
      end


      def auto_depends_gcc_options
        "#{ @cflags.join " " } -fPIC #{ gcc_i_options }"
      end


      def gcc_i_options
        ( [ @includes ].flatten + c_includes ).collect do | each |
          "-I#{ each }"
        end.join( " " )
      end


      def c_includes
        sources.pathmap( "%d" ).uniq
      end
    end
  end
end


### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
