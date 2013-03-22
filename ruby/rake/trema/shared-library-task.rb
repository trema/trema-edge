require "rake/trema/library-task"


module Rake
  module Trema
    class SharedLibraryTask < LibraryTask
      attr_accessor :version


      ##########################################################################
      private
      ##########################################################################


      def generate_target
        return if uptodate?( target_path, objects )
        sh "gcc -shared -Wl,-soname=#{ soname } -o #{ target_path } #{ objects.to_s }"
      end


      def soname
        File.basename( target_file_name ).sub( /\.\d+\.\d+\Z/, "" )
      end


      def target_file_name
        @library_name + ".so." + @version
      end
    end
  end
end


### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
