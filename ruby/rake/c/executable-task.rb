require "rake/c/build-task"


module Rake
  module C
    class ExecutableTask < BuildTask
      attr_writer :executable_name
      attr_writer :ldflags
      attr_writer :library_dependencies


      ##########################################################################
      private
      ##########################################################################


      def target_file_name
        @executable_name
      end


      def generate_target
        return if uptodate?( target_path, objects )
        sh "gcc -o #{ target_path } #{ objects.to_s } #{ @ldflags.join " " } #{ gcc_l_options }"
      end
    end
  end
end


### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
