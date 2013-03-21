require "popen4"
require "rake/c/dependency"
require "rake/clean"
require "rake/tasklib"


module Rake
  module C
    class BuildTask < TaskLib
      attr_accessor :cflags
      attr_accessor :includes
      attr_accessor :name
      attr_accessor :target_directory
      attr_writer :sources


      def initialize name, &block
        init name
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
        CLEAN.include objects
        CLOBBER.include target_path
        CLOBBER.include Dependency.path( @name )

        task name => [ target_directory, target_path ]
        directory target_directory

        sources.zip( objects ) do | source, object |
          task object => source do | task |
            compile task.name, task.prerequisites[ 0 ]
          end
        end

        file target_path => objects do | task |
          generate_target
        end
      end


      def target_path
        File.join @target_directory, target_file_name
      end


      def objects
        sources.collect do | each |
          File.join @target_directory, File.basename( each ).ext( ".o" )
        end
      end


      def generate_target
        raise NotImplementedError, "Override this!"
      end


      def target_file_name
        raise NotImplementedError, "Override this!"
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
        return if uptodate?( o_file, [ c_file ] + Dependency.read( @name, o_file ) )
        autodepends = run_gcc_H( "gcc -H #{ gcc_cflags } -fPIC #{ gcc_I_options } -c #{ c_file } -o #{ o_file }" )
        Dependency.write( @name, o_file, autodepends )
      end


      def run_gcc_H command
        autodepends = []

        puts command
        status = POpen4.popen4( command ) do | stdout, stderr, stdin, pid |
          stdin.close
          stderr.each do | line |
            case line
            when /^\./
              autodepends << line.sub( /^\.+\s+/, "" ).strip
            when /Multiple include guards/
              # Filter out include guards warnings.
              stderr.each do | line |
                if line =~ /:$/
                  puts line
                  break
                end
              end
            else
              puts line
            end
          end
        end
        fail "gcc failed" if status.exitstatus != 0

        autodepends
      end


      def gcc_cflags
        @cflags.join " "
      end


      def gcc_I_options
        ( @includes + c_includes ).collect do | each |
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
