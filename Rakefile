#
# Copyright (C) 2008-2013 NEC Corporation
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


require "paper_house"
require "rake/clean"
require "rspec/core"
require "rspec/core/rake_task"
require "trema/dsl/parser"
require "trema/executables"
require "trema/path"
require "trema/version"


CLOBBER.include Trema.objects


CFLAGS = [
  "-g",
  "-fPIC",
  "-std=gnu99",
  "-D_GNU_SOURCE",
  "-fno-strict-aliasing",
  "-Werror",
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


task :default => [
  :libruby,
  :switch_manager,
  :switch_daemon,
  :trema_switch,
  :packetin_filter,
  :tremashark,
  :examples,
  "vendor:phost",
]


desc "Build Trema C library."
PaperHouse::StaticLibraryTask.new :libtrema do | task |
  task.target_directory = Trema.lib
  task.sources = "#{ Trema.include }/*.c"
  task.cflags = CFLAGS
end


desc "Build Trema Ruby library."
task :libruby => :libtrema

PaperHouse::RubyExtensionTask.new :libruby do | task |
  task.library_name = "trema"
  task.target_directory = Trema.ruby
  task.sources = [
    "#{ Trema.ruby }/trema/*.c",
    "#{ Trema.ruby }/trema/messages/*.c"
  ]
  task.includes = Trema.include
  task.cflags = CFLAGS + [ "-Wno-error=sign-conversion" ] # FIXME
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


desc "Build switch datapath library."
PaperHouse::StaticLibraryTask.new :libofdp do | task |
  task.target_directory = Trema.obj_datapath
  task.sources = "#{ Trema.src_datapath }/*.c"
  task.includes = Trema.include
  task.cflags = CFLAGS
end


desc "Build google cmockery library"
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


desc "Build switch manager."
task :switch_manager => :libtrema

PaperHouse::ExecutableTask.new :switch_manager do | task |
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

PaperHouse::ExecutableTask.new :switch_daemon do | task |
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
    "src/switch_manager/tls.c",
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
    "ssl",
    "crypto",
  ]
end


desc "Build Trema switch."
task :trema_switch => [ :libofdp, :libtrema ]

PaperHouse::ExecutableTask.new :trema_switch do | task |
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

PaperHouse::ExecutableTask.new :packetin_filter do | task |
  task.target_directory = File.dirname( Trema::Executables.packetin_filter )
  task.sources = "src/packetin_filter/*.c"
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


desc "Build Tremashark."

task :tremashark => [
  'tremashark:tremashark',
  'tremashark:syslog_relay',
  'tremashark:stdin_relay',
  'tremashark:packet_capture',
]

tremashark_sources = {
  'tremashark:tremashark' => [
    'src/tremashark/queue.c',
    'src/tremashark/pcap_queue.c',
    'src/tremashark/tremashark.c',
  ],
  'tremashark:syslog_relay' => [
    'src/tremashark/syslog_relay.c',
  ],
  'tremashark:stdin_relay' => [
    'src/tremashark/stdin_relay.c',
  ],
  'tremashark:packet_capture' => [
    'src/tremashark/queue.c',
    'src/tremashark/pcap_queue.c',
    'src/tremashark/packet_capture.c',
  ],
}

Rake::Task[ :tremashark ].prerequisites.each do | utility |
  begin
    Rake::Task[ utility ]
  rescue
    desc "Build #{ utility }."
    task utility => :libtrema

    PaperHouse::ExecutableTask.new utility do | task |
      task.target_directory = File.dirname( Trema::Executables.tremashark )
      task.executable_name = utility.split(':')[1]
      task.sources = tremashark_sources[utility]
      task.includes = Trema.include
      task.cflags = CFLAGS
      task.ldflags = "-L#{ Trema.lib }"
      task.library_dependencies = [
        "trema",
        "sqlite3",
        "pthread",
        "rt",
        "dl",
        "pcap",
      ]
    end
  end
end


################################################################################
# Examples.
################################################################################

def target_directory_of example
  File.join Trema.objects, example
end

task :examples => [
  'examples:cbench_switch',
  'examples:dumper',
  'examples:hello_trema',
  'examples:learning_switch',
  'examples:list_switches',
  'examples:multi_learning_switch',
  'examples:openflow_message',
  #'examples:packetin_filter_config',
  'examples:packet_in',
  'examples:repeater_hub',
  'examples:switch_info',
  'examples:switch_monitor',
  'examples:traffic_monitor'
]


task 'examples:openflow_message' => [
  'examples:openflow_message:echo_reply',
  'examples:openflow_message:echo_request',
  'examples:openflow_message:features_request',
  'examples:openflow_message:hello',
  'examples:openflow_message:group_mod',
  'examples:openflow_message:port_desc_multipart_request',
  'examples:openflow_message:set_config'
]


Rake::Task[ :examples ].prerequisites.each do | example |
  begin
    Rake::Task[ example ]
  rescue
    desc "Build #{ example }."
    task example => :libtrema

    PaperHouse::ExecutableTask.new example do | task |
      example_name = example.gsub(/:/,'/')
      task.executable_name = File.basename example_name
      task.target_directory = target_directory_of "#{ example_name }"
      task.sources = "src/#{ example_name }/*.c"
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
  end
end


Rake::Task[ 'examples:openflow_message' ].prerequisites.each do | example |
  begin
    Rake::Task[ example ]
  rescue
    desc "Build #{ example }."
    task example => :libtrema

    PaperHouse::ExecutableTask.new example do | task |
      example_name = example.gsub(/:/,'/')
      task.executable_name = File.basename example_name
      task.target_directory = target_directory_of "#{ File.dirname example_name }"
      task.sources = "src/#{ example_name }.c"
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
  end
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
# Unit tests
################################################################################
desc "Build Trema C unittest library."
PaperHouse::StaticLibraryTask.new :libtrema do | task |
  task.target_directory = Trema.obj_unittests
  task.sources = "#{ Trema.include }/*.c"
  task.cflags = [ '--coverage' ] + CFLAGS
end


desc "Build libofdp.a unittest library"
PaperHouse::StaticLibraryTask.new :libofdp do | task |
  task.target_directory = "#{ Trema.obj_unittests }/switch/datapath"
  task.sources = "#{ Trema.src_datapath }/*.c"
  task.includes = Trema.include
  task.cflags = [ '--coverage', '-DUNIT_TESTING' ] + CFLAGS
end


def switch_tests
  {
    parse_options_test: [
      "#{ Trema.src_unittests }/switch/switch/parse-options-test.c",
      "#{ Trema.src_unittests }/switch/switch/mocks.c",
      "#{ Trema.src_trema_switch }/parse-options.c"
    ],
    group_helper_test: [
      "#{ Trema.src_unittests }/switch/switch/group-helper-test.c",
      "#{ Trema.src_unittests }/switch/switch/mocks.c",
      "#{ Trema.src_trema_switch }/group-helper.c",
      "#{ Trema.src_trema_switch }/action*.c",
      "#{ Trema.src_trema_switch }/oxm*.c"
    ]
  }
end


desc "Build switch unittest"
switch_tests.keys.each do | each |
  task each => [ 'vendor:cmockery', :libtrema, :libofdp ]
  PaperHouse::ExecutableTask.new each do | task |
    task.target_directory = "#{ Trema.obj_unittests }/switch/switch"
    task.sources = switch_tests[ each ]
    task.includes = [
      File.dirname( Trema.cmockery_h ),
      Trema.src_datapath,
      Trema.include,
      Trema.src_unittests
    ]
    task.cflags = [ '--coverage', '-DUNIT_TESTING' ] + CFLAGS
    task.ldflags = "-Wl,--rpath -Wl,#{ Trema.cmockery }/lib --coverage -L#{ Trema.obj_unittests } -L#{ Trema.cmockery }/lib -L#{ Trema.obj_unittests }/switch/datapath"
    task.library_dependencies = [
      'cmockery',
      'ofdp',
      'trema',
      'sqlite3',
      'pthread',
      'rt',
      'dl'
    ]
  end
end


desc "Run unittests"
task :run_unittests => switch_tests.keys do
  cd Trema.obj_unittests do
    Dir.glob( "*/*/*_test" ).each do | exec |
      sh "sudo -E #{ exec }"
    end
  end
end


################################################################################
# Tests
################################################################################

task :spec => :libruby
RSpec::Core::RakeTask.new do | task |
  task.verbose = $trace
  task.pattern = FileList[ "spec/trema_spec.rb", "spec/trema/messages/hello_spec.rb" ]
  task.rspec_opts = "--format documentation --color"
end


require "cucumber/rake/task"
task :features => :default
Cucumber::Rake::Task.new( :features ) do | t |
  t.cucumber_opts = "features --tags ~@wip"
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
