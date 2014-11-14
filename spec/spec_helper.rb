#
# Author: Yasuhito Takamiya <yasuhito@gmail.com>
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

$LOAD_PATH << File.join(File.dirname(__FILE__), '..', 'ruby')
$LOAD_PATH.unshift File.expand_path(File.join File.dirname(__FILE__), '..', 'vendor', 'ruby-ifconfig-1.2', 'lib')

require 'rubygems'

require 'rspec'
require 'trema'
require 'trema/dsl/configuration'
require 'trema/dsl/context'
require 'trema/util'
require 'trema/shell/send_packets'

require 'coveralls'
Coveralls.wear!

RSpec.configure do | config |
  config.expect_with :rspec do | c |
    # Ensure that 'expect' is used and disable 'should' for consistency
    c.syntax = :expect
  end
end

# Requires supporting files with custom matchers and macros, etc,
# in ./support/ and its subdirectories.
Dir["#{ File.dirname(__FILE__) }/support/**/*.rb"].each do | each |
  require File.expand_path(each)
end

include Trema

def controller(name)
  Trema::App[name]
end

def vswitch(name)
  Trema::OpenflowSwitch[name]
end

def vhost(name)
  Trema::Host[name]
end

def send_packets(source, dest, options = {})
  Trema::Shell.send_packets source, dest, options
end

include Trema::Util

class MockController < Controller
  def initialize(network_blk)
    @network_blk = network_blk
    @context = Trema::DSL::Parser.new.eval(&network_blk)
  end

  def start_receiving
    if @network_blk.respond_to? :call
      trema_run
    else
      fail ArgumentError, 'Network configuration should a proc block'
    end
  end

  def stop_receiving
    trema_kill
  end

  def time_sleep(interval)
    sleep interval
    yield
  end

  private

  def trema_run
    controller = self
    unless controller.is_a?(Trema::Controller)
      fail "#{ controller_class } is not a subclass of Trema::Controller"
    end
    Trema::DSL::Context.new(@context).dump

    app_name = controller.name
    rule = { port_status: app_name, packet_in: app_name, state_notify: app_name }
    sm = SwitchManager.new(rule, @context.port)
    sm.no_flow_cleanup = true
    sm.run!

    @context.links.each do | _name, each |
      each.add!
    end
    @context.hosts.each do | _name, each |
      each.run!
    end
    @context.trema_switches.each do | _name, each |
      each.run!
    end
    @context.links.each do | _name, each |
      each.up!
    end
    @context.hosts.each do | _name, each |
      each.add_arp_entry @context.hosts.values - [each]
    end

    @th_controller = Thread.start do
      controller.run!
    end
    sleep 2  # FIXME: wait until controller.up?
  end

  def trema_kill
    cleanup_current_session
    @th_controller.join if @th_controller
    sleep 2  # FIXME: wait until switch_manager.down?
  end
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
