require "rake/trema/library-task"


module Rake
  module Trema
    class RubyLibraryTask < LibraryTask
      attr_writer :ldflags
      attr_writer :library_dependencies


      ##########################################################################
      private
      ##########################################################################


      def generate_target
        return if uptodate?( target_path, objects )
        sh "gcc -shared -o #{ target_path } #{ objects.to_s } #{ @ldflags.join " " } -L#{ RbConfig::CONFIG[ 'libdir' ] } #{ gcc_l_options }"
      end


      def target_file_name
        @library_name + ".so"
      end


      def gcc_I_options
        ( @includes + c_includes + ruby_includes ).collect do | each |
          "-I#{ each }"
        end.join( " " )
      end


      def ruby_includes
        [
           File.join( RbConfig::CONFIG[ "rubyhdrdir" ], RbConfig::CONFIG[ "arch" ] ),
           File.join( RbConfig::CONFIG[ "rubyhdrdir" ], "ruby/backward" ),
           RbConfig::CONFIG[ "rubyhdrdir" ]
        ]
      end
    end
  end
end


### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
