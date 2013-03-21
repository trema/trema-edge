require "rake/c/build-task"


module Rake
  module C
    class LibraryTask < BuildTask
      attr_accessor :library_name
    end
  end
end


require "rake/c/ruby-library-task"
require "rake/c/shared-library-task"
require "rake/c/static-library-task"


### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
