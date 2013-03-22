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


$LOAD_PATH.unshift File.expand_path( File.join File.dirname( __FILE__ ), "ruby" )


require "rake/trema/executable-task"
require "rake/trema/library-task"
require "rake/clean"
require "rspec/core"
require "rspec/core/rake_task"
require "trema/dsl/parser"
require "trema/executables"
require "trema/path"
require "trema/version"


task :default => [
  :rubylib,
  :switch_manager,
  :switch_daemon,
  :trema_switch,
  :packetin_filter,
  "vendor:phost"
]


################################################################################
# Build libtrema.a
################################################################################

CFLAGS = [
  "-g",
  "-fPIC",
  "-std=gnu99",
  "-D_GNU_SOURCE",
  "-fno-strict-aliasing",
  # FIXME
  # "-Werror",
  "-Wall",
  "-Wextra",
  "-Wformat=2",
  "-Wcast-qual",
  "-Wcast-align",
  "-Wwrite-strings",
  "-Wconversion",
  "-Wfloat-equal",
  "-Wpointer-arith"
]


desc "Build Trema C library."
Rake::Trema::StaticLibraryTask.new "libtrema" do | task |
  task.library_name = "libtrema"
  task.target_directory = Trema.lib
  task.sources = "#{ Trema.include }/*.c"
  task.cflags = CFLAGS
end


################################################################################
# Build Ruby library
################################################################################

task :rubylib => :libtrema

desc "Build Ruby library."
Rake::Trema::RubyLibraryTask.new :rubylib do | task |
  task.library_name = "trema"
  task.target_directory = Trema.ruby
  task.sources = [
    "#{ Trema.ruby }/trema/*.c",
    "#{ Trema.ruby }/trema/messages/*.c"
  ]
  task.includes = [ Trema.include ]
  task.cflags = CFLAGS
  task.ldflags = [ "-Wl,-Bsymbolic", "-L#{ Trema.lib }" ]
  task.library_dependencies = [
    "trema",
    "sqlite3",
    "pthread",
    "rt",
    "dl",
    "crypt",
    "m"
  ]
end


################################################################################
# cmockery
################################################################################

task "vendor:cmockery" => Trema.libcmockery_a
file Trema.libcmockery_a do
  sh "tar xzf #{ Trema.vendor_cmockery }.tar.gz -C #{ Trema.vendor }"
  cd Trema.vendor_cmockery do
    sh "./configure --prefix=#{ Trema.cmockery }"
    sh "make install"
  end
end

CLEAN.include Trema.vendor_cmockery
CLOBBER.include Trema.cmockery
CLOBBER.include Trema.objects


################################################################################
# Build libofdp.a
################################################################################

desc "Build libofdp.a"
Rake::Trema::StaticLibraryTask.new "libofdp" do | task |
  task.library_name = "libofdp"
  task.target_directory = "#{ Trema.objects }/switch/datapath"
  task.sources = "#{ Trema.home }/src/switch/datapath/*.c"
  task.includes = [ Trema.include ]
  task.cflags = CFLAGS
end


desc "Build switch manager."
task :switch_manager => :libtrema

Rake::Trema::ExecutableTask.new "switch_manager" do | task |
  task.target_directory = File.dirname( Trema::Executables.switch_manager )
  task.sources = [
    "src/switch_manager/dpid_table.c",
    "src/switch_manager/secure_channel_listener.c",
    "src/switch_manager/switch_manager.c",
  ]
  task.includes = Trema.include
  task.cflags = CFLAGS
  task.ldflags = "-L#{ Trema.lib }"
  task.library_dependencies = [
    "trema",
    "sqlite3",
    "pthread",
    "rt",
    "dl",
  ]
end


desc "Build switch daemon."
task :switch_daemon => :libtrema

Rake::Trema::ExecutableTask.new "switch_daemon" do | task |
  task.target_directory = File.dirname( Trema::Executables.switch_daemon )
  task.sources = [
    "src/switch_manager/cookie_table.c",
    "src/switch_manager/ofpmsg_recv.c",
    "src/switch_manager/ofpmsg_send.c",
    "src/switch_manager/secure_channel_receiver.c",
    "src/switch_manager/secure_channel_sender.c",
    "src/switch_manager/service_interface.c",
    "src/switch_manager/switch.c",
    "src/switch_manager/xid_table.c",
  ]
  task.includes = Trema.include
  task.cflags = CFLAGS
  task.ldflags = "-L#{ Trema.lib }"
  task.library_dependencies = [
    "trema",
    "sqlite3",
    "pthread",
    "rt",
    "dl",
  ]
end


desc "Build Trema switch."
task :trema_switch => [ :libofdp, :libtrema ]

Rake::Trema::ExecutableTask.new "trema_switch" do | task |
  task.executable_name = "switch"
  task.target_directory = File.dirname( Trema::Executables.switch )
  task.sources = "src/switch/switch/*.c"
  task.includes = [ Trema.include, Trema.src_datapath ]
  task.cflags = CFLAGS
  task.ldflags = [ "-L#{ Trema.lib }", "-L#{ Trema.obj_datapath }" ]
  task.library_dependencies = [
    "ofdp",
    "trema",
    "sqlite3",
    "pthread",
    "rt",
    "dl",
  ]
end


desc "Build PacketIn filter."
task :packetin_filter => :libtrema

Rake::Trema::ExecutableTask.new "packetin_filter" do | task |
  task.target_directory = File.dirname( Trema::Executables.packetin_filter )
  task.sources = "src/packetin_filter/*.c"
  task.includes = Trema.include
  task.cflags = CFLAGS
  task.ldflags = [ "-L#{ Trema.lib }", "-L#{ Trema.obj_datapath }" ]
  task.library_dependencies = [
    "trema",
    "sqlite3",
    "pthread",
    "rt",
    "dl",
  ]
end


################################################################################
# Misc.
################################################################################

def phost_src
  File.join Trema.vendor_phost, "src"
end


task "vendor:phost" => [ Trema::Executables.phost, Trema::Executables.cli ]

directory File.dirname( Trema::Executables.phost )
file Trema::Executables.phost => File.dirname( Trema::Executables.phost ) do
  cd phost_src do
    sh "make"
  end
  sh "install #{ File.join( phost_src, "phost" ) } #{ Trema::Executables.phost } --mode=0755"
end

directory File.dirname( Trema::Executables.cli )
file Trema::Executables.cli => File.dirname( Trema::Executables.cli ) do
  cd phost_src do
    sh "make"
  end
  sh "install #{ File.join( phost_src, "cli" ) } #{ Trema::Executables.cli } --mode=0755"
end


################################################################################
# Tests
################################################################################

task :spec => :rubylib
RSpec::Core::RakeTask.new do | task |
  task.verbose = $trace
  task.pattern = FileList[ "spec/trema_spec.rb" ]
  task.rspec_opts = "--format documentation --color"
end


################################################################################
# YARD
################################################################################

begin
  require "yard"

  YARD::Rake::YardocTask.new do | t |
    t.files = [ "ruby/trema/**/*.c", "ruby/trema/**/*.rb" ]
    t.options = [ "--no-private" ]
    t.options << "--debug" << "--verbose" if $trace
  end
rescue LoadError
  $stderr.puts $!.to_s
end


## Local variables:
## mode: Ruby
## coding: utf-8-unix
## indent-tabs-mode: nil
## End:
