require "rake/trema/build-task"


module Rake
  module Trema
    class LibraryTask < BuildTask
      attr_accessor :library_name
    end
  end
end


require "rake/trema/ruby-library-task"
require "rake/trema/shared-library-task"
require "rake/trema/static-library-task"


### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
