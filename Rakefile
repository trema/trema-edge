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
$LOAD_PATH.unshift File.expand_path( File.join File.dirname( __FILE__ ), "vendor", "ruby-ifconfig-1.2", "lib" )


require "rake/clean"
require "rake/builder"
require "rake/loaders/makefile"


require "trema/executables"
require "trema/path"
require "trema/dsl/parser"

desc "Do not output any build messages"
task :silent do
  ENV[ 'DEBUG' ] = nil
end

CFLAGS = [
    '-g',
    '-fPIC',
    '-std=gnu99',
    '-D_GNU_SOURCE',
    '-fno-strict-aliasing',
    # FIXME
    # '-Werror',
    '-Wall',
    '-Wextra',
    '-Wformat=2',
    '-Wcast-qual',
    '-Wcast-align',
    '-Wwrite-strings',
    '-Wconversion',
    '-Wfloat-equal',
    '-Wpointer-arith'
]

Rake::Builder.new do | builder |
  builder.programming_language = 'c'
  builder.target = 'ruby/trema.so'
  builder.target_type = :shared_library
  builder.target_prerequisites = [ 'objects/lib/libtrema.a' ]
  builder.source_search_paths = [
    'ruby/trema',
    'ruby/trema/messages',
  ]
  builder.installable_headers = [ 'src/lib' ]
  ruby_includes = [
    RbConfig::CONFIG[ 'rubyhdrdir' ] + '/' + RbConfig::CONFIG[ 'arch' ],
    RbConfig::CONFIG[ 'rubyhdrdir' ] + '/ruby/backward',
    RbConfig::CONFIG[ 'rubyhdrdir' ]
  ]
  builder.include_paths = ruby_includes + [ 'ruby/trema', 'src/lib' ]
  builder.objects_path = 'ruby'
  builder.compilation_options = CFLAGS
  builder.library_paths = [
    RbConfig::CONFIG[ 'libdir' ],
    'objects/lib'
  ]
  builder.linker_options = [ '-Wl,-Bsymbolic' ]
  builder.library_dependencies = [
    'ruby',
    'trema',
    'sqlite3',
    'pthread',
    'rt',
    'dl',
    'crypt',
    'm'
  ]
end


desc "build cmockery library"
task "vendor:cmockery" => Trema.libcmockery_a
file Trema.libcmockery_a do
  sh "tar -xzf #{ Trema.vendor_cmockery }.tar.gz -C #{ Trema.vendor }"
  cd Trema::vendor_cmockery do
    sh "./configure --prefix=#{ Trema.cmockery }"
    sh "make install"
  end
end
Rake::Task[ "vendor:cmockery" ].invoke


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
Rake::Task[ "vendor:phost" ].invoke


Rake::Builder.new do | builder |
  builder.programming_language = 'c'
  builder.target = 'objects/lib/libtrema.a'
  builder.target_type = :static_library
  builder.source_search_paths = [ 'src/lib' ]
  builder.installable_headers = [ 'src/lib' ]
  builder.include_paths = [ 'src/lib' ]
  builder.objects_path = 'objects/lib'
  builder.compilation_options = CFLAGS
end


Rake::Builder.new do | builder |
  builder.programming_language = 'c'
  builder.target = 'objects/lib/libtrema.a'
  builder.target_type = :static_library
  builder.source_search_paths = [ 'src/lib' ]
  builder.installable_headers = [ 'src/lib' ]
  builder.include_paths = [ 'src/lib' ]
  builder.objects_path = 'objects/lib'
  builder.compilation_options = CFLAGS
end


Rake::Builder.new do | builder |
  builder.programming_language = 'c'
  builder.target = 'objects/switch/datapath/libofdp.a'
  builder.target_type = :static_library
  builder.source_search_paths = [ 'src/switch/datapath' ]
  builder.installable_headers = [ 'src/switch/datapath' ]
  builder.include_paths = [
    'src/lib',
    'src/switch/datapath'
  ]
  builder.objects_path = 'objects/switch/datapath'
  builder.compilation_options = CFLAGS
end


# build switch
Rake::Builder.new do | builder |
  builder.programming_language = 'c'
  builder.target = 'objects/switch/switch/switch'
  builder.target_type = :executable
  builder.source_search_paths = [ 'src/switch/switch' ]
  builder.installable_headers = [ 'src/switch/switch' ]
  builder.include_paths = [ 'src/lib', 'src/switch/datapath' ]
  builder.objects_path = 'objects/switch/switch'
  builder.compilation_options = CFLAGS
  builder.library_paths = [
    'objects/switch/datapath',
    'objects/lib'
  ]
  builder.library_dependencies = [
    'ofdp',
    'trema',
    'sqlite3',
    'dl',
    'rt',
    'pthread'
  ]
  builder.target_prerequisites = [
    "#{ File.expand_path 'objects/switch/datapath/libofdp.a' }",
    "#{ File.expand_path 'objects/lib/libtrema.a' }"
  ]
end


# build switch_manager
Rake::Builder.new do | builder |
  builder.programming_language = 'c'
  builder.target = Trema::Executables.switch_manager
  builder.target_type = :executable
  builder.source_search_paths = [
    'src/switch_manager/dpid_table.c',
    'src/switch_manager/switch_manager.c',
    'src/switch_manager/secure_channel_listener.c'
  ]
  builder.installable_headers = [ 'src/switch_manager' ]
  builder.include_paths = [ 'src/lib' ]
  builder.objects_path = File.dirname Trema::Executables.switch_manager
  builder.compilation_options = CFLAGS
  builder.library_paths = [ 'objects/lib' ]
  builder.library_dependencies = [
    'trema',
    'sqlite3',
    'dl',
    'rt',
    'pthread'
  ]
  builder.target_prerequisites = [ "#{ File.expand_path 'objects/lib/libtrema.a' }" ]
end


# build switch_daemon
Rake::Builder.new do | builder |
  builder.programming_language = 'c'
  builder.target = 'objects/switch_manager/switch_daemon'
  builder.target_type = :executable
  builder.source_search_paths = [
    'src/switch_manager/cookie_table.c',
    'src/switch_manager/ofpmsg_recv.c',
    'src/switch_manager/ofpmsg_send.c',
    'src/switch_manager/secure_channel_receiver.c',
    'src/switch_manager/secure_channel_sender.c',
    'src/switch_manager/service_interface.c',
    'src/switch_manager/switch.c',
    'src/switch_manager/xid_table.c'
  ]
  builder.installable_headers = [ 'src/switch_manager' ]
  builder.include_paths = [ 'src/lib' ]
  builder.objects_path = File.dirname Trema::Executables.switch_manager
  builder.compilation_options = CFLAGS
  builder.library_paths = [ 'objects/lib' ]
  builder.library_dependencies = [
    'trema',
    'sqlite3',
    'dl',
    'rt',
    'pthread'
  ]
  builder.target_prerequisites = [ "#{ File.expand_path 'objects/lib/libtrema.a' }" ]
end


# build packetin_filter
Rake::Builder.new do | builder |
  builder.programming_language = 'c'
  builder.target = Trema::Executables.packetin_filter
  builder.target_type = :executable
  builder.source_search_paths = [ 'src/packetin_filter' ]
  builder.installable_headers = [ 'src/packetin_filter' ]
  builder.include_paths = [ 'src/lib' ]
  builder.objects_path = 'objects/packetin_filter'
  builder.compilation_options = CFLAGS
  builder.library_paths = [ 'objects/lib' ]
  builder.library_dependencies = [
    'trema',
    'pthread',
    'sqlite3',
    'dl',
    'rt'
  ]
  builder.target_prerequisites = [ "#{ File.expand_path 'objects/lib/libtrema.a' }" ]
end


# build tremashark
Rake::Builder.new do | builder |
  builder.programming_language = 'c'
  builder.target = Trema::Executables.tremashark
  builder.target_type = :executable
  builder.source_search_paths = [
    'src/tremashark/pcap_queue.c',
    'src/tremashark/queue.c',
    'src/tremashark/tremashark.c'
  ]
  builder.installable_headers = [ 'src/tremashark' ]
  builder.include_paths = [ 'src/lib' ]
  builder.objects_path = 'objects/tremashark'
  builder.compilation_options = CFLAGS
  builder.library_paths = [ 'objects/lib' ]
  builder.library_dependencies = [
    'trema',
    'sqlite3',
    'dl',
    'rt',
    'pcap',
    'pthread'
  ]
  builder.target_prerequisites = [ "#{ File.expand_path 'objects/lib/libtrema.a' }" ]
end


# build  packet_capture
Rake::Builder.new do | builder |
  builder.programming_language = 'c'
  builder.target = Trema::Executables.packet_capture
  builder.target_type = :executable
  builder.source_search_paths = [
    'src/tremashark/packet_capture.c',
    'src/tremashark/queue.c'
  ]
  builder.installable_headers = [ 'src/tremashark' ]
  builder.include_paths = [ 'src/lib' ]
  builder.objects_path = 'objects/tremashark'
  builder.compilation_options = CFLAGS
  builder.library_paths = [ 'objects/lib' ]
  builder.library_dependencies = [
    'trema',
    'sqlite3',
    'dl',
    'rt',
    'pcap',
    'pthread'
  ]
  builder.target_prerequisites = [ "#{ File.expand_path 'objects/lib/libtrema.a' }" ]
end


# build syslog_relay
Rake::Builder.new do | builder |
  builder.programming_language = 'c'
  builder.target = Trema::Executables.syslog_relay
  builder.target_type = :executable
  builder.source_search_paths = [
    'src/tremashark/syslog_relay.c'
  ]
  builder.installable_headers = [ 'src/tremashark' ]
  builder.include_paths = [ 'src/lib' ]
  builder.objects_path = 'objects/tremashark'
  builder.compilation_options = CFLAGS
  builder.library_paths = [ 'objects/lib' ]
  builder.library_dependencies = [
    'trema',
    'sqlite3',
    'dl',
    'rt',
    'pcap',
    'pthread'
  ]
  builder.target_prerequisites = [ "#{ File.expand_path 'objects/lib/libtrema.a' }" ]
end


# build stdin_relay
Rake::Builder.new do | builder |
  builder.programming_language = 'c'
  builder.target = Trema::Executables.stdin_relay
  builder.target_type = :executable
  builder.source_search_paths = [
    'src/tremashark/stdin_relay.c'
  ]
  builder.installable_headers = [ 'src/tremashark' ]
  builder.include_paths = [ 'src/lib' ]
  builder.objects_path = 'objects/tremashark'
  builder.compilation_options = CFLAGS
  builder.library_paths = [ 'objects/lib' ]
  builder.library_dependencies = [
    'trema',
    'sqlite3',
    'dl',
    'rt',
    'pcap',
    'pthread'
  ]
  builder.target_prerequisites = [ "#{ File.expand_path 'objects/lib/libtrema.a' }" ]
end

# build management commands
#management_commands = [
#  "application",
#  "echo",
#  "set_logging_level",
#  "show_stats",
#]

#management_commands.each do | each |
#  Rake::Builder.new do | builder |
#    builder.programming_language = 'c'
#    builder.target = each
#    builder.target_type = :executable
#    builder.source_search_paths = [ "src/management/#{ each }.c" ]
#    builder.installable_headers = [ 'src/management' ]
#    builder.include_paths = [ 'src/lib' ]
#    builder.objects_path = 'objects/management'
#    builder.compilation_options = CFLAGS
#    builder.library_paths = [ 'objects/lib' ]
#    builder.library_dependencies = [ 'trema', 'sqlite3', 'dl', 'rt', 'pthread' ]
#  end
#end

# build standalone examples
standalone_examples = [
  "learning_switch",
  "dumper"
]

standalone_examples.each do | each |
  Rake::Builder.new do | builder |
    builder.programming_language = 'c'
    builder.target = "objects/examples/#{ each }/#{ each }"
    builder.target_type = :executable
    builder.source_search_paths = [ "src/examples/#{ each }/#{ each }.c" ]
    builder.installable_headers = [ "src/examples/#{ each }" ]
    builder.include_paths = [ 'src/lib' ]
    builder.objects_path = "objects/examples/#{ each }"
    builder.compilation_options = CFLAGS
    builder.library_paths = [ 'objects/lib' ]
    builder.library_dependencies = [
      'trema',
      'sqlite3',
      'dl',
      'rt',
      'pthread'
    ]
    builder.target_prerequisites = [ "#{ File.expand_path 'objects/lib/libtrema.a' }" ]
  end
end


packetin_filter_config = [
  "add_filter",
  "delete_filter",
  "delete_filter_strict",
  "dump_filter",
  "dump_filter_strict",
]

packetin_filter_config.each do | each |
  Rake::Builder.new do | builder |
    builder.programming_language = 'c'
    builder.target = "objects/examples/packetin_filter_config/#{ each }"
    builder.target_type = :executable
    builder.source_search_paths = [
      "src/examples/packetin_filter_config/#{ each }.c",
      'src/examples/packetin_filter_config/utils.c'
    ]
    builder.installable_headers = [ "src/examples/packetin_filter_config" ]
    builder.include_paths = [ 'src/lib' ]
    builder.objects_path = "objects/examples/packetin_filter_config"
    builder.compilation_options = CFLAGS
    builder.library_paths = [ 'objects/lib' ]
    builder.library_dependencies = [
      'trema',
      'sqlite3',
      'dl',
      'rt',
      'pthread'
    ]
    builder.target_prerequisites = [ "#{ File.expand_path 'objects/lib/libtrema.a' }" ]
  end
end


Rake::Builder.new do | builder |
  builder.programming_language = 'c'
  builder.target = "objects/unittests/libtrema.a"
  builder.target_type = :static_library
  builder.source_search_paths = [ 'src/lib' ]
  builder.installable_headers = [ 'src/lib' ]
  builder.include_paths = [ 'src/lib' ]
  builder.objects_path = 'objects/unittests'
  builder.compilation_options = [ '--coverage' ] + CFLAGS
end


Rake::Builder.new do | builder |
  builder.programming_language = 'c'
  builder.target = 'objects/unittests/switch/datapath/libofdp.a'
  builder.target_type = :static_library
  builder.source_search_paths = [ 'src/switch/datapath' ]
  builder.installable_headers = [ 'src/switch/datapath' ]
  builder.include_paths = [
    'src/lib',
    'src/switch/datapath',
    "#{ File.dirname Trema.cmockery_h }", 'unittests/switch'
  ]
  builder.objects_path = 'objects/unittests/switch/datapath'
  builder.compilation_options = [ '--coverage', '-DUNIT_TESTING' ] + CFLAGS
end


tests = [
  "objects/unittests/buffer_test",
  "objects/unittests/doubly_linked_list_test",
  "objects/unittests/ether_test",
  "objects/unittests/hash_table_test",
  "objects/unittests/linked_list_test",
  "objects/unittests/log_test",
  "objects/unittests/packetin_filter_interface_test",
  "objects/unittests/packet_info_test",
  "objects/unittests/packet_parser_test", # this test fails"
  "objects/unittests/persistent_storage_test",
  "objects/unittests/trema_private_test",
  "objects/unittests/utility_test",
  "objects/unittests/wrapper_test",
  "objects/unittests/match_table_test",
  "objects/unittests/message_queue_test",
#  "objects/unittests/management_interface_test",
#  "objects/unittests/management_service_interface_test",
]


tests.each do | each |
  Rake::Builder.new do | builder |
    builder.programming_language = 'c'
    builder.target = each
    builder.target_type = :executable
    builder.source_search_paths = [
      "unittests/lib/#{ File.basename each }.c",
      'unittests/cmockery_trema.c'
    ]
    builder.installable_headers = [ "unittests/lib" ]
    builder.include_paths = [
      "src/lib", "#{ File.dirname Trema.cmockery_h }",
      'unittests' ]
    builder.objects_path = 'objects/unittests'
    builder.compilation_options = [ '--coverage' ] + CFLAGS
    builder.library_paths = [
      'objects/unittests',
      "#{ File.dirname Trema.libcmockery_a }"
    ]
    builder.library_dependencies = [
      'trema',
      'rt',
      'cmockery',
      'sqlite3',
      'dl',
      'pthread'
    ]
    builder.linker_options = '--coverage --static'
    builder.target_prerequisites = [
      "#{ File.expand_path 'objects/unittests/libtrema.a' }",
      'vendor:cmockery'
    ]
  end
end


def switch_tests
  # { target => source_dependencies }
  {
    "parse-options-test" => [
      "unittests/switch/switch/parse-options-test.c",
      "unittests/switch/switch/mocks.c",
      "src/switch/switch/parse-options.c"
    ],
    "group-helper-test" => [
      "unittests/switch/switch/group-helper-test.c",
      "unittests/switch/switch/mocks.c",
      "src/switch/switch/group-helper.c",
      "src/switch/switch/action*.c"
    ],
    "stats-helper-test" => [
      "unittests/switch/switch/stats-helper-test.c",
      "unittests/switch/switch/mocks.c",
      "src/switch/switch/stats-helper.c",
      "src/switch/switch/oxm*.c",
      "src/switch/switch/action*.c"
    ],
    "protocol-handler-test" => [
       "unittests/switch/switch/protocol-handler-test.c",
       "unittests/switch/switch/mocks.c",
       "src/switch/switch/protocol-handler.c",
       "src/switch/switch/stats-helper.c",
       "src/switch/switch/switch-common.c",
       "src/switch/switch/action*.c",
       "src/switch/switch/oxm*.c"
    ]
  }
end


#switch_tests.keys.each do | each |
#  Rake::Builder.new do | builder |
#    builder.programming_language = 'c'
#    builder.target  = "objects/unittests/switch/#{ each }"
#    builder.target_type = :executable
#    builder.source_search_paths = switch_tests[ each ]
#    builder.installable_headers = [ "unittests/switch" ]
#    builder.include_paths = [
#      'src/lib',
#      'src/switch/datapath',
#      'src/switch/switch',
#      "#{ File.dirname Trema.cmockery_h }", "unittests"
#    ]
#    builder.objects_path = 'objects/unittests/switch'
#    builder.compilation_options = [ '--coverage', '-DUNIT_TESTING' ] + CFLAGS
#    builder.library_paths = [
#      'objects/unittests/switch/datapath',
#      'objects/unittests',
#      "#{ File.dirname Trema.libcmockery_a }"
#    ]
#    builder.library_dependencies = [
#      'ofdp',
#      'trema',
#      'rt',
#      'cmockery',
#      'sqlite3',
#      'dl',
#      'pthread'
#    ]
#    builder.linker_options = '--coverage --static'
#    builder.target_prerequisites = [
#      'vendor:cmockery',
#      "#{ File.expand_path 'objects/unittests/switch/datapath/libofdp.a' }",
#      "#{ File.expand_path 'objects/unittests/libtrema.a' }"
#    ]
#  end
#end


require "rspec/core"
require "rspec/core/rake_task"


task :spec => :default
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
