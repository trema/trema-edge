#
# Author: Yasuhito Takamiya <yasuhito@gmail.com>
#
# Copyright (C) 2008-2011 NEC Corporation
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


require "fileutils"
require "trema/monkey-patch/string"
require "trema/process"


module Trema
  module Daemon
    module ClassMethods
      def command &block
        class_variable_set :@@command, block
      end


      def wait_until_up
        class_variable_set :@@wait_until_up, true
      end


      def daemon_id method_id
        class_variable_set :@@daemon_id, method_id
      end
    end


    def self.included base
      base.class_eval do
        class_variable_set :@@command, nil
        class_variable_set :@@wait_until_up, false
        class_variable_set :@@daemon_id, nil
      end
      base.extend ClassMethods
    end


    def run!
      raise "'#{ name }' is already running!" if running?
      FileUtils.rm_f log_file if self.respond_to?( :log_file )
      command_block = self.class.class_eval do
        class_variable_get( :@@command )
      end
      if command_block
        sh command_block.call( self )
      else
        sh self.__send__( :command )
      end
      wait_until_up
    end


    #
    # Kills running daemon process
    #
    # @example
    #   daemon.shutdown!
    #
    # @return [undefined]
    #
    def shutdown!
      Trema::Process.read( pid_file, name ).kill!
    end


    #
    # Restarts running daemon process
    #
    # @example
    #   daemon.restart!
    #
    # @return [undefined]
    #
    def restart!
      return if not running?
      shutdown!
      sleep 1
      run!
    end


    def pid_file
      prefix = self.class.name.demodulize.underscore
      File.join Trema.tmp, "#{ prefix }.#{ daemon_id }.pid"
    end


    def running?
      FileTest.exists? pid_file
    end


    ############################################################################
    private
    ############################################################################


    def daemon_id
      m = self.class.class_eval do
        class_variable_get( :@@daemon_id ) || :name
      end
      self.__send__ m
    end


    def wait_until_up
      wait = self.class.class_eval do
        class_variable_get( :@@wait_until_up )
      end
      return if not wait
      loop do
        sleep 0.1
        break if FileTest.exists?( pid_file )
      end
    end
  end
end


### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End: